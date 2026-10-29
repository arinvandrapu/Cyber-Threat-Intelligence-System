"""Inputs for ``cti attack-eval2`` (Phase 10b): NVD records, test labels, CAPEC paths, CVSS rule.

Rules are fixed in :mod:`cti.nlp.attack2_config`; this module only loads and joins.

- **NVD.** Every non-rejected record from the main snapshot's raw feeds and the
  2002-2022 reference archive, with no publish-date window, read straight from the raw
  JSON (the Phase 1 parse drops the CVSS v2 booleans the rule needs).
- **Test labels.** CTID ``attack_to_cve`` rows, merged per CVE, split on ";", remapped
  through revocations, rolled up to parents; unknown IDs are counted and dropped.
- **CAPEC chain.** CWE -> CAPEC from the CWE catalog, CAPEC -> ATT&CK from CAPEC 3.9.
"""

from __future__ import annotations

import csv
import io
import zipfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

import ijson
from defusedxml.ElementTree import iterparse

from cti import reference
from cti.nlp import attack2_config as cfg
from cti.nlp.attack_catalog import parent
from cti.snapshot import Snapshot
from cti.sources.base import gunzip_stream
from cti.sources.cwe import NS as CWE_NS
from cti.sources.cwe import CWESource
from cti.sources.nvd import NO_CWE, NVD_SOURCE

CAPEC_NS = "{http://capec.mitre.org/capec-3}"
_V3_KEYS = ("cvssMetricV31", "cvssMetricV30")
_V2_FLAGS = ("userInteractionRequired",)  # metric-level, optional, NVD-only


@dataclass(frozen=True)
class NvdRecord:
    cve: str
    text: str
    cwes: tuple[str, ...]
    cvss: dict | None  # {"family": "v3"|"v2", "vector": {...}, "flags": {...}, "source"}


def _vector(text: str) -> dict[str, str]:
    """``AV:N/AC:L/...`` (with or without a ``CVSS:3.1/`` prefix) -> {"AV": "N", ...}."""
    return dict(p.split(":", 1) for p in text.split("/") if ":" in p and not p.startswith("CVSS"))


def _cvss(metrics: dict, cna: str | None) -> dict | None:
    """NVD's own score first, else the CNA's; newest of v3.1 / v3.0 / v2. No v4."""
    for want in (NVD_SOURCE, cna):
        if want is None:
            continue
        for key in (*_V3_KEYS, "cvssMetricV2"):
            for metric in metrics.get(key) or []:
                if metric.get("source") != want:
                    continue
                return {
                    "family": "v2" if key == "cvssMetricV2" else "v3",
                    "vector": _vector(metric["cvssData"].get("vectorString") or ""),
                    "flags": {f: bool(metric.get(f)) for f in _V2_FLAGS},
                    "source": "nvd" if want == NVD_SOURCE else "cna",
                }
    return None


def _record(cve: dict) -> NvdRecord | None:
    if cve.get("vulnStatus") == "Rejected":
        return None
    text = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
    cwes = sorted(
        {
            d["value"]
            for w in cve.get("weaknesses", [])
            for d in w.get("description", [])
            if d["value"].startswith("CWE-") and d["value"] not in NO_CWE
        }
    )
    return NvdRecord(
        cve["id"], text, tuple(cwes), _cvss(cve.get("metrics", {}), cve.get("sourceIdentifier"))
    )


def nvd_records(snapshots: Iterable[Snapshot], wanted: set[str]) -> dict[str, NvdRecord]:
    """``wanted`` CVEs from every ``nvd`` feed in ``snapshots``, unfiltered by date."""
    out: dict[str, NvdRecord] = {}
    for snap in snapshots:
        for entry in snap.entries("nvd"):
            stream = gunzip_stream(snap.read_raw(entry))
            for item in ijson.items(stream, "vulnerabilities.item", use_float=True):
                cve = item["cve"]
                if cve["id"] in wanted and (rec := _record(cve)) is not None:
                    out[cve["id"]] = rec
    return out


# ---- test labels ------------------------------------------------------------------------


@dataclass
class TestLabels:
    gold: dict[str, dict[str, set[str]]]  # cve -> mapping type -> parents
    counts: Counter = field(default_factory=Counter)  # remapped / dropped / merged rows
    raw: dict[str, set[str]] = field(default_factory=dict)  # cve -> PRIMARY_TYPE IDs, unrolled


def load_test(
    data_dir, current: set[str], revoked: Mapping[str, str], exclude: set[str]
) -> TestLabels:
    """CTID attack_to_cve labels for CVEs not in ``exclude`` (the training CVEs).

    ``current``: technique IDs in ATT&CK v20; ``revoked``: old ID -> replacement.
    """
    text = reference.read_pinned(data_dir, reference.CTID_ATTACK_TO_CVE).decode("utf-8-sig")
    gold: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    raw: dict[str, set[str]] = defaultdict(set)
    counts: Counter = Counter()
    seen: Counter = Counter()
    had_label: set[tuple[str, str]] = set()  # (cve, type) with >= 1 label before filtering
    for row in csv.DictReader(io.StringIO(text)):
        cve = row["CVE ID"].strip()
        seen[cve] += 1
        if cve in exclude:
            counts["rows_training_overlap"] += 1
            continue
        for column, mapping_type in cfg.TEST_COLUMNS.items():
            for tid in (t.strip() for t in row[column].split(";")):
                if not tid:
                    continue
                had_label.add((cve, mapping_type))
                if tid in revoked:
                    tid = revoked[tid]
                    counts["labels_remapped"] += 1
                if tid not in current:
                    counts["labels_unknown_dropped"] += 1
                    continue
                gold[cve][mapping_type].add(parent(tid))
                if mapping_type == cfg.PRIMARY_TYPE:
                    raw[cve].add(tid)
    for mapping_type in cfg.TEST_COLUMNS.values():  # not graded for that type (config)
        counts[f"cves_all_labels_dropped_{mapping_type}"] = sum(
            t == mapping_type and not gold.get(c, {}).get(t) for c, t in had_label
        )
    counts["cves_with_two_rows"] = sum(n > 1 for n in seen.values())
    counts["training_overlap_cves"] = len(set(seen) & exclude)
    return TestLabels({c: dict(t) for c, t in gold.items()}, counts, dict(raw))


# ---- CAPEC chain ------------------------------------------------------------------------


def cwe_to_capec(source: CWESource, snapshot: Snapshot) -> dict[str, set[str]]:
    """``CWE-79`` -> {"CAPEC-209", ...} from Related_Attack_Pattern in the CWE catalog."""
    out: dict[str, set[str]] = defaultdict(set)
    with source.open_xml(snapshot) as fh:
        for _, elem in iterparse(fh, events=("end",)):
            if elem.tag == f"{CWE_NS}Weakness":
                for rap in elem.iter(f"{CWE_NS}Related_Attack_Pattern"):
                    out[f"CWE-{elem.get('ID')}"].add(f"CAPEC-{rap.get('CAPEC_ID')}")
                elem.clear()
    return dict(out)


def capec_to_attack(data_dir, revoked: Mapping[str, str], current: set[str]) -> dict:
    """``CAPEC-1`` -> {parent technique} from CAPEC 3.9 ATTACK taxonomy mappings."""
    data = reference.read_pinned(data_dir, reference.CAPEC)
    out: dict[str, set[str]] = defaultdict(set)
    with zipfile.ZipFile(io.BytesIO(data)) as zf, zf.open("capec_v3.9.xml") as fh:
        for _, elem in iterparse(fh, events=("end",)):
            if elem.tag != f"{CAPEC_NS}Attack_Pattern":
                continue
            for tm in elem.iter(f"{CAPEC_NS}Taxonomy_Mapping"):
                entry = tm.find(f"{CAPEC_NS}Entry_ID")
                if tm.get("Taxonomy_Name") != "ATTACK" or entry is None or not entry.text:
                    continue
                tid = "T" + entry.text.strip()
                tid = revoked.get(tid, tid)
                if tid in current:
                    out[f"CAPEC-{elem.get('ID')}"].add(parent(tid))
            elem.clear()
    return dict(out)


def current_only(gold: dict, current: set[str]) -> tuple[dict, int]:
    """Training labels restricted to parents of current techniques (config: unknown IDs are
    dropped and counted for training as for test). ``gold``: cve -> type -> parents."""
    parents = {parent(t) for t in current}
    dropped = 0
    out = {}
    for cve, types in gold.items():
        kept = {}
        for t, labels in types.items():
            dropped += len(labels - parents)
            if labels & parents:
                kept[t] = labels & parents
        out[cve] = kept
    return out, dropped


def capec_paths(
    cwes: Iterable[str], cwe_capec: Mapping[str, set[str]], capec_attack: Mapping[str, set[str]]
) -> Counter:
    """Parent -> number of CWE -> CAPEC -> parent paths."""
    paths: Counter = Counter()
    for cwe in cwes:
        for capec in cwe_capec.get(cwe, ()):
            for tech in capec_attack.get(capec, ()):
                paths[tech] += 1
    return paths


# ---- CVSS rule --------------------------------------------------------------------------


def cvss_parents(cvss: dict | None) -> set[str]:
    """Parents the CVSS exploitation-flow rule (``cfg.CVSS_RULES``) marks for a record."""
    if not cvss:
        return set()
    v, f = cvss["vector"], cvss["flags"]
    if cvss["family"] == "v3":
        fires = (
            v.get("AV") == "N" and v.get("UI") == "N",
            v.get("UI") == "R",
            v.get("AV") == "L",
            v.get("AV") == "N" and v.get("PR") in ("L", "H"),
        )
    else:
        fires = (
            v.get("AV") == "N" and not f["userInteractionRequired"],
            f["userInteractionRequired"],
            v.get("AV") == "L",
            v.get("AV") == "N" and v.get("Au") in ("S", "M"),
        )
    rules = cfg.CVSS_RULES[cvss["family"]]
    return {p for (_, parents), hit in zip(rules, fires, strict=True) if hit for p in parents}
