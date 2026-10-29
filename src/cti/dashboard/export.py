"""``cti export``: the dashboard's data, from pipeline outputs only (Phase 8).

Writes ``data/export/<date>/{meta,risk,iocs,graphs,eval,threats}.json`` (gitignored: the
IOC and threat files hold abuse.ch-derived aggregates). Nothing here is recomputed by hand:
every number is a pipeline output or is derived from one in code below.

- **Risk.** The pre-registered logistic model (``risk_config``, unchanged and SHA-checked
  against ``risk-eval.json``) refit on all four labelled windows, then used to rank the
  snapshot population (``eligible["snapshot"]``) from ``features_at(record, "snapshot")``.
  Only rank and tier are shown, never a probability: the model was fit at ~0.03%
  prevalence and the snapshot's EPSS is a newer model version. Tier hit rates come from
  the evaluation folds, not from this ranking, which has no labels yet.
- **Context** (CVSS, CWE, assigner, description) is display-only and never a model input.
  URL, IP and domain spans in descriptions are defanged before truncation.
- **IOCs.** Reference-page strings of indicator type (not vetted as malicious); NVD-origin
  as counts only; abuse.ch feeds as aggregates only (no values: licence). Every network
  value is checked to be defanged, failing closed.
- **Threats** (Phase 10a, optional input). ``cti threats`` reads this export's risk tiers,
  so the order is ``cti export`` -> ``cti threats`` -> ``cti export``. Without a threats
  file, ``threats.json`` says ``available: false``; with one, its dates and every linked
  CVE tier must match this export, or the export stops. Per-family aggregates only.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import date
from pathlib import Path

import numpy as np

from cti.config import ConfigError
from cti.dashboard import schema
from cti.defang import defang_host, defang_ip, defang_scheme, refang
from cti.enrich.cves import cve_sort_key, features_at, known_in_kev
from cti.nlp import risk_config as cfg
from cti.nlp import risk_eval
from cti.nlp.iocs import extract
from cti.threats.config import PRIORITY_REVIEW_TOP_N

DESCRIPTION_CHARS = 320
TOP_FAMILIES = 25
INDICATOR_CVES = 10
HOSTS_MAX = 30
HOST_CVES_MAX = 30
TABLE_TYPES_EXCLUDED = ("cve", "cvss")  # identifiers, not indicators
GRAPH_TIERS = ("critical", "high")
TIER_NAMES = [name for name, _ in cfg.TIERS]

DISCLOSURES = [
    "Ranks only CVEs published from {window_start} that were not in CISA KEV at the snapshot.",
    "Rank and tier only: the model's output is not a probability (fit at {prevalence} "
    "prevalence; snapshot EPSS is a newer model version than training saw).",
    "Snapshot EPSS is model {snapshot_epss}; the risk model was trained on {train_epss}. "
    "Percentiles are used, but the shift is untested.",
    "The snapshot ranking itself is not evaluated. Tier hit rates are historical: the "
    "same procedure on the rolling-origin test folds ({test_span}), next 180 days.",
    "Newer CVEs rank higher (standardized log-age weight {age_weight:+.2f}): {recent:,} of "
    "the {tiered:,} tiered CVEs are 30 days old or younger.",
    "Weights describe correlated signals, not causes; the refit's weights differ from the "
    "evaluated folds' (both shown).",
    "CVSS, CWE, assigner and descriptions are context only and were never model inputs.",
    "The logistic model (pre-registered headline) ranks the snapshot, not the boosting "
    "challenger: it was fixed before scoring and its contributions can be explained.",
]
RECENT_DAYS = 30
# Families shown: the priority top N, which is hand-labelled by rule (so no MISP name
# collision reaches the top of the list), plus any family with a CVE link.
TOP_THREATS = PRIORITY_REVIEW_TOP_N
THREATS_DISCLOSURE = (
    "Threat categories and CVE-link reviews were labelled by Claude on the owner's behalf; "
    "threat priority is a pre-declared heuristic, not a validated model."
)
# Registries that every CVE links to: shared by construction, not infrastructure
HOSTS_EXCLUDED = frozenset({"cve[.]org", "cve[.]mitre[.]org", "nvd[.]nist[.]gov"})

# ---- defanging --------------------------------------------------------------------------------

_BARE_DOT = re.compile(r"(?<!\[)\.(?!\])")
_LIVE_SCHEME = re.compile(r"^(?:https?|s?ftp)://", re.IGNORECASE)
_WIDE_DOTS = re.compile("[\u3002\uff0e\uff61]")
_EMAIL = re.compile(r"\b([\w.+-]+)@([\w-]+(?:\.[\w-]+)+)\b")


def _is_ip(text: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def check_defanged(kind: str, value: str) -> None:
    """Raise unless a network indicator is defanged by the rule for its type (fail closed).

    Domains and IPs must equal the canonical defanged form of their refanged value; URL
    hosts must hold no live dot (ASCII or the full-width forms browsers also accept)."""
    if kind == "url":
        host = value.partition("://")[2].partition("/")[0] if "://" in value else ""
        ok = (
            not _LIVE_SCHEME.match(value)
            and bool(host)
            and not _BARE_DOT.search(host)
            and not _WIDE_DOTS.search(host)
        )
    elif kind == "domain":
        ok = defang_host(refang(value)) == value and not _WIDE_DOTS.search(value)
    elif kind in ("ipv4", "ipv6"):
        plain = refang(value)
        ok = _is_ip(plain) and defang_ip(plain) == value
    else:
        return
    if not ok:
        raise ValueError(f"{kind} value is not defanged: {value!r}")


def defang_text(text: str) -> str:
    """``text`` with every URL, IP and domain span the IOC extractor recognises defanged.

    Names the extractor rejects (unknown suffixes, ``localhost``, placeholders) stay as
    written, so descriptions must only ever be rendered as plain text, never linkified."""
    out, last = [], 0
    for ioc in extract(text):
        if ioc.type in ("url", "ipv4", "ipv6", "domain"):
            check_defanged(ioc.type, ioc.value)
            out.append(text[last : ioc.start])
            out.append(ioc.value)
            last = ioc.end
    out.append(text[last:])
    # the extractor has no email type: defang the @ and the domain's dots as well
    return _EMAIL.sub(lambda m: f"{m.group(1)}[@]{defang_host(m.group(2))}", "".join(out))


def truncate(text: str, limit: int = DESCRIPTION_CHARS) -> str:
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0]
    return cut.rstrip(".,;:") + " …"


# ---- risk -------------------------------------------------------------------------------------


def config_guard(risk_eval_result: dict) -> str:
    """The SHA-256 of ``risk_config.py``; refuses if it differs from the evaluated one."""
    digest = hashlib.sha256(Path(cfg.__file__).read_bytes()).hexdigest()
    evaluated = risk_eval_result["provenance"]["config_sha256"]
    if digest != evaluated:
        raise ConfigError(
            f"risk_config.py ({digest[:12]}) differs from the evaluated config "
            f"({evaluated[:12]}); rerun `cti risk-eval` or restore the file"
        )
    return digest


def refit(windows: dict[str, risk_eval.Window]) -> risk_eval.Fitted:
    """The pre-registered logistic model on every labelled window (oldest first)."""
    x = np.vstack([windows[w].x for w in cfg.CUTOFFS])
    y = np.concatenate([windows[w].y for w in cfg.CUTOFFS])
    return risk_eval.fit(x, y, risk_eval.FEATURES, "logistic")


def score_snapshot(records: Iterable[dict], day: str, fitted: risk_eval.Fitted) -> dict:
    """Rank and tier every CVE eligible at the snapshot, best first."""
    kept, xs, details, in_kev = [], [], [], set()
    for record in records:
        if known_in_kev(record, day):
            in_kev.add(record["cve"])
        if not record["eligible"].get("snapshot"):
            continue
        if known_in_kev(record, day):  # eligibility already excludes these: defence in depth
            raise ValueError(f"{record['cve']} is in KEV but marked eligible")
        x, detail = risk_eval.featurize(record, "snapshot", day)
        xs.append(x)
        details.append(detail)
        # only what the export shows: full records for ~168k CVEs would not fit in memory
        kept.append(
            {
                "cve": record["cve"],
                "published": record["published"],
                "context_snapshot": record["context_snapshot"],
                "ssvc": features_at(record, "snapshot").get("vulnrichment") or {},
            }
        )
    x = np.array(xs, dtype=float).reshape(len(kept), len(risk_eval.FEATURES))
    scores = fitted.score(x)
    rank = risk_eval.ranks(scores)
    tier = risk_eval.assign_tiers(scores)
    contrib = fitted.matrix(x, None) * fitted.model.coef_[0]
    order = sorted(range(len(kept)), key=lambda i: (rank[i], cve_sort_key(kept[i]["cve"])))
    return {
        "records": [kept[i] for i in order],
        "x": x[order],
        "rank": rank[order],
        "tier": tier[order],
        "contrib": contrib[order],
        "details": [details[i] for i in order],
        "in_kev": in_kev,
    }


def _age(record: dict, day: str) -> int:
    return (date.fromisoformat(day) - date.fromisoformat(record["published"][:10])).days


def _coverage(scored: dict) -> dict[str, dict[str, float]]:
    x, tier = scored["x"], scored["tier"]
    col = {f: x[:, i] for i, f in enumerate(risk_eval.FEATURES)}
    flags = {
        "public_exploit": (col["exploitdb"] == 1) | (col["metasploit"] == 1),
        "nuclei_template": col["nuclei"] == 1,
        "ssvc_exploitation_poc_or_active": np.nan_to_num(col["ssvc_exploitation"]) >= 1,
        "ssvc_automatable": np.nan_to_num(col["ssvc_automatable"]) == 1,
        "ssvc_missing": col["ssvc_missing"] == 1,
        "epss_missing": col["epss_missing"] == 1,
    }
    out = {}
    for name, flag in flags.items():
        out[name] = {
            t: round(float(flag[tier == t].mean()), 4) if (tier == t).any() else 0.0
            for t in TIER_NAMES
        }
    return out


def build_risk(
    scored: dict,
    fitted: risk_eval.Fitted,
    training_positives: dict[str, int],
    training_rows: int,
    evaluated: dict,
    nvd_context: dict[str, dict],
    day: str,
) -> dict:
    features = risk_eval.FEATURES
    rows, months = [], defaultdict(Counter)
    for i, record in enumerate(scored["records"]):
        tier = scored["tier"][i]
        if tier == "baseline":
            continue
        cve = record["cve"]
        ctx_snap = record["context_snapshot"]
        nvd = nvd_context.get(cve, {})
        vr = record["ssvc"]
        if tier in GRAPH_TIERS:
            months[record["published"][:7]][tier] += 1
        rows.append(
            {
                "rank": round(float(scored["rank"][i]), 1),
                "cve": cve,
                "tier": tier,
                "published": record["published"][:10],
                "epss": scored["details"][i]["epss"],
                "epss_percentile": scored["details"][i]["epss_percentile"],
                "ssvc_exploitation": vr.get("exploitation"),
                "ssvc_automatable": vr.get("automatable"),
                "ssvc_technical_impact": vr.get("technical_impact"),
                "exploit_sources": scored["details"][i]["exploit_sources"],
                "age_days": _age(record, day),
                "contributions": {
                    f: round(float(scored["contrib"][i, j]), 4) for j, f in enumerate(features)
                },
                "imputed": [f for j, f in enumerate(features) if np.isnan(scored["x"][i, j])],
                "context": {
                    "cvss_nvd": (ctx_snap.get("cvss_nvd") or {}).get("base_score"),
                    "cvss_cna": (ctx_snap.get("cvss_cna") or {}).get("base_score"),
                    "cwes": [c["id"] for c in ctx_snap.get("cwes", [])],
                    "assigner": nvd.get("assigner"),
                    "name": defang_text(
                        derived_name(
                            nvd.get("affected", []),
                            ctx_snap.get("cwes", []),
                            nvd.get("cwe_assignments", []),
                        )
                        or ""
                    )
                    or None,
                    "description": nvd.get("description", ""),
                },
            }
        )
    counts = Counter(scored["tier"].tolist())
    last_fold = evaluated["logistic_coefficients_last_fold_standardized"]
    coef = fitted.model.coef_[0]
    tiers_eval = evaluated["tiers_logistic"]["tiers"]
    return {
        "snapshot_date": day,
        "ranked_cves": len(scored["records"]),
        "tiers": [
            {"name": name, "max_rank_fraction": cut, "cves": counts.get(name, 0)}
            for name, cut in cfg.TIERS
        ],
        "rows": rows,
        "coefficients": [
            {
                "feature": f,
                "refit": round(float(coef[j]), 4),
                "evaluated_last_fold": last_fold[f],
            }
            for j, f in enumerate(features)
        ],
        "intercept": round(float(fitted.model.intercept_[0]), 4),
        "training_positives": training_positives,
        "training_rows": training_rows,
        "iterations": int(fitted.model.n_iter_[0]),
        "historical_tiers": [
            {
                "name": name,
                "cves": tiers_eval[name]["cves"],
                "kev_positives": tiers_eval[name]["kev_positives"],
                "hit_rate": tiers_eval[name]["hit_rate"],
                "wilson95": tiers_eval[name]["wilson95"],
            }
            for name in TIER_NAMES
        ],
        "signal_coverage": _coverage(scored),
        "published_by_month": {m: dict(c) for m, c in sorted(months.items())},
    }


def nvd_context(nvd_rows: Iterable[dict], cves: set[str]) -> dict[str, dict]:
    """Assigner, affected vendor/product and defanged, truncated description for ``cves``."""
    out = {}
    for row in nvd_rows:
        cve = row["source_id"]
        if cve in cves:
            out[cve] = {
                "assigner": row["metadata"].get("assigner"),
                "affected": row["metadata"].get("affected", []),
                "cwe_assignments": row["metadata"].get("cwe_assignments", []),
                "description": truncate(defang_text(row.get("text") or "")),
            }
    return out


_PLACEHOLDER = frozenset({"", "n/a", "na", "unknown", "unspecified", "-"})


def derived_name(
    affected: list[dict], cwes: list[dict], assignments: list[dict] = ()
) -> str | None:
    """An approximate common name from data we hold: "<vendor> <product>: <weakness>".

    - What: the first affected entry; placeholder values ("n/a", "unknown") skipped, and
      the vendor dropped when it repeats the product ("Linux" + "Linux kernel", "PHP
      Group" + "PHP").
    - Weakness: NVD's Primary CWE, else the CVE's only CWE. With several CWEs and none
      marked primary there is no honest single choice, so the name says "vulnerability".
    """
    what = ""
    for data in affected[:1]:
        vendor, product = data.get("vendor", "").strip(), data.get("product", "").strip()
        vendor = "" if vendor.lower() in _PLACEHOLDER else vendor
        product = "" if product.lower() in _PLACEHOLDER else product
        v, p = vendor.lower(), product.lower()
        if vendor and product and (p.startswith(v) or p in v.split()):
            vendor = ""
        what = " ".join(x for x in (vendor, product) if x)
    names = {c["id"]: c["name"] for c in cwes if c.get("name")}
    primary = next(
        (
            a["id"]
            for a in assignments
            if a.get("source_kind") == "nvd" and a.get("type") == "Primary" and a["id"] in names
        ),
        None,
    )
    weakness = (
        names.get(primary) if primary else (next(iter(names.values())) if len(names) == 1 else None)
    )
    if what and weakness:
        return f"{what}: {weakness}"
    if what:
        return f"{what} vulnerability"
    return weakness


# ---- IOCs -------------------------------------------------------------------------------------


def build_iocs(extracted: Iterable[dict], threatfox: Iterable[dict], urlhaus: Iterable[dict]):
    found: dict[tuple[str, str], dict] = {}
    nvd_counts: Counter = Counter()
    pages = 0
    for doc in extracted:
        if doc["origin"] != "reference_page":
            nvd_counts.update(
                i["type"] for i in doc["iocs"] if i["type"] not in TABLE_TYPES_EXCLUDED
            )
            continue
        pages += 1
        for ioc in doc["iocs"]:
            kind, value = ioc["type"], ioc["value"]
            if kind in TABLE_TYPES_EXCLUDED:
                continue
            if kind == "url":  # extractions made before ftp schemes were defanged
                value = defang_scheme(value)
            check_defanged(kind, value)
            entry = found.setdefault(
                (kind, value), {"cves": set(), "occurrences": 0, "public": ioc.get("public")}
            )
            entry["cves"].add(doc["cve"])
            entry["occurrences"] += 1
    indicators = [
        {
            "type": kind,
            "value": value,
            "cves": sorted(e["cves"], key=cve_sort_key)[:INDICATOR_CVES],
            "cve_count": len(e["cves"]),
            "occurrences": e["occurrences"],
            "public": e["public"],
        }
        for (kind, value), e in found.items()
    ]
    indicators.sort(key=lambda i: (-i["cve_count"], -i["occurrences"], i["type"], i["value"]))
    return {
        "title": "Indicator-type strings from CVE references (not vetted as malicious)",
        "reference_pages": pages,
        "by_type": dict(sorted(Counter(i["type"] for i in indicators).items())),
        "nvd_description_counts": dict(sorted(nvd_counts.items())),
        "indicators": indicators,
        "feeds": {
            "threatfox": _feed(threatfox, "ioc_type", "threat_type", family="malware"),
            "urlhaus": _feed(urlhaus, "ioc_type", "threat"),
        },
    }


def _feed(rows: Iterable[dict], type_key: str, threat_key: str, family: str | None = None):
    n, kinds, threats, months, families = 0, Counter(), Counter(), Counter(), Counter()
    for row in rows:
        meta = row["metadata"]
        n += 1
        kinds[str(meta.get(type_key))] += 1
        threats[str(meta.get(threat_key))] += 1
        months[(row.get("published") or "unknown")[:7]] += 1
        if family:
            families[str(meta.get(family))] += 1
    out = {
        "records": n,
        "by_type": dict(sorted(kinds.items())),
        "by_threat": dict(sorted(threats.items())),
        "by_month": dict(sorted(months.items())),
    }
    if family:
        top = sorted(families.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_FAMILIES]
        out["top_families"] = [list(kv) for kv in top]
    return out


# ---- graphs -----------------------------------------------------------------------------------


def weakness_graph(rows: list[dict], records: dict[str, dict], cwe_names: dict[str, str]):
    """CWE pillar -> CWE -> CVE for the critical and high tiers (CWEs as labelled, context).

    ``records`` are the slim scored records, by CVE."""
    nodes, edges, members = {}, Counter(), defaultdict(set)
    for row in rows:
        if row["tier"] not in GRAPH_TIERS:
            continue
        cve = row["cve"]
        for cwe in records[cve]["context_snapshot"].get("cwes", []):
            pillar = cwe.get("pillar")
            if cwe.get("kind") != "weakness" or not pillar:
                continue
            nodes.setdefault(cve, {"id": cve, "label": cve, "kind": "cve", "tier": row["tier"]})
            nodes.setdefault(
                pillar, {"id": pillar, "label": cwe_names.get(pillar, pillar), "kind": "pillar"}
            )
            members[pillar].add(cve)
            if cwe["id"] == pillar:
                edges[(pillar, cve)] = 1
                continue
            nodes.setdefault(
                cwe["id"], {"id": cwe["id"], "label": cwe.get("name") or cwe["id"], "kind": "cwe"}
            )
            members[cwe["id"]].add(cve)
            edges[(pillar, cwe["id"])] = 1
            edges[(cwe["id"], cve)] = 1
    for node_id, cves in members.items():  # count = distinct CVEs under the node
        nodes[node_id]["count"] = len(cves)
    for (src, dst), _ in list(edges.items()):  # pillar -> CWE weight = CVEs of that CWE
        if nodes[src]["kind"] == "pillar" and nodes[dst]["kind"] == "cwe":
            edges[(src, dst)] = len(members[dst])
    return _graph(
        "CWE pillar -> CWE -> critical/high-tier CVE (NVD/CNA labels, display only)",
        nodes,
        edges,
        truncated=False,
    )


def attack_graphs(ctid_rows: list[dict], revoked: dict[str, str], techniques) -> dict:
    """KEV CVE -> technique -> tactic per CTID mapping type (technique level, remapped)."""
    from cti.nlp.attack_catalog import parent
    from cti.nlp.attack_eval import MAPPING_TYPES

    by_id = {t.id: t for t in techniques}
    out = {}
    for mapping_type in MAPPING_TYPES:
        nodes, edges = {}, Counter()
        for row in ctid_rows:
            if row["type"] != mapping_type:
                continue
            tid = parent(revoked.get(row["technique"], row["technique"]))
            tech = by_id.get(tid)
            nodes.setdefault(
                row["cve"], {"id": row["cve"], "label": row["cve"], "kind": "cve", "in_kev": True}
            )
            if (row["cve"], tid) in edges:
                continue
            t = nodes.setdefault(
                tid, {"id": tid, "label": tech.name if tech else tid, "kind": "technique"}
            )
            t["count"] = t.get("count", 0) + 1
            edges[(row["cve"], tid)] += 1
            for tactic in tech.tactics if tech else ():
                nodes.setdefault(
                    tactic,
                    {"id": tactic, "label": tactic.replace("-", " ").title(), "kind": "tactic"},
                )
                edges[(tid, tactic)] = 1
        for _, dst in edges:  # tactic count = techniques under it
            if nodes[dst]["kind"] == "tactic":
                nodes[dst]["count"] = nodes[dst].get("count", 0) + 1
        out[mapping_type] = _graph(
            f"CTID KEV mappings ({mapping_type}): KEV CVE -> ATT&CK technique -> tactic",
            nodes,
            edges,
            truncated=False,
        )
    return out


_PORT = re.compile(r":\d+$")


def _host(kind: str, value: str) -> str | None:
    if kind == "domain":
        return value
    if kind == "url":
        authority = value.partition("://")[2].partition("/")[0]
        return _PORT.sub("", authority.rpartition("@")[2]) or None  # no userinfo, no port
    return None


def _registry(host: str) -> bool:
    host = host.lower()
    return host in HOSTS_EXCLUDED or host.removeprefix("www[.]") in HOSTS_EXCLUDED


def _local_ip(host: str) -> bool:
    """A loopback, private or otherwise non-global IP literal (not a real shared host)."""
    import ipaddress

    try:
        return not ipaddress.ip_address(refang(host).strip("[]")).is_global
    except ValueError:
        return False


def shared_host_graph(extracted: Iterable[dict], tiers: dict[str, str], in_kev: set[str]) -> dict:
    """Hosts named on the reference pages of two or more CVEs, largest first (capped).

    Non-global IP literals (127.0.0.1, 10/8, ...) and the CVE registries every record links
    to are dropped: shared, but not infrastructure. A CVE with no tier is either in KEV
    (``in_kev``) or outside the ranked population (published before the NVD window)."""
    hosts: dict[str, set[str]] = defaultdict(set)
    for doc in extracted:
        if doc["origin"] != "reference_page":
            continue
        for ioc in doc["iocs"]:
            host = _host(ioc["type"], ioc["value"])
            if host is None or _registry(host) or _local_ip(host):
                continue
            check_defanged("domain", host)
            hosts[host].add(doc["cve"])
    shared = sorted(
        ((h, c) for h, c in hosts.items() if len(c) >= 2), key=lambda hc: (-len(hc[1]), hc[0])
    )
    truncated = len(shared) > HOSTS_MAX
    nodes, edges = {}, Counter()
    for host, cves in shared[:HOSTS_MAX]:
        nodes[host] = {"id": host, "label": host, "kind": "host", "count": len(cves)}
        ordered = sorted(cves, key=cve_sort_key)
        truncated |= len(ordered) > HOST_CVES_MAX
        for cve in ordered[:HOST_CVES_MAX]:
            nodes.setdefault(
                cve,
                {
                    "id": cve,
                    "label": cve,
                    "kind": "cve",
                    "tier": tiers.get(cve),
                    "in_kev": cve in in_kev,  # KEV CVEs are never ranked, so no tier
                },
            )
            edges[(host, cve)] += 1
    return _graph(
        "Hosts on the reference pages of 2+ CVEs (defanged; not vetted as malicious)",
        nodes,
        edges,
        truncated=truncated,
    )


def _graph(description: str, nodes: dict, edges: Counter, truncated: bool) -> dict:
    return {
        "description": description,
        "nodes": sorted(nodes.values(), key=lambda n: (n["kind"], n["id"])),
        "edges": [{"source": s, "target": t, "weight": w} for (s, t), w in sorted(edges.items())],
        "truncated": truncated,
    }


# ---- evaluation summaries ----------------------------------------------------------------------


def pick(data: dict, *path: str):
    """``data[path[0]][path[1]]...`` with the full path in the error if a key is missing."""
    for i, key in enumerate(path):
        if not isinstance(data, dict) or key not in data:
            raise KeyError(f"missing {'/'.join(path[: i + 1])}")
        data = data[key]
    return data


RISK_POOLED = (
    "positives",
    "hits@100",
    "recall@100",
    "recall@100_wilson95",
    "hits@1%",
    "recall@1%",
    "recall@1%_wilson95",
    "mean_average_precision",
)
RISK_FOLD = ("n", "positives", "hits@100", "hits@1%", "average_precision")
ATTACK_METRICS = ("cves", "hit@1", "hit@5", "mrr")
CWE_METRICS = ("n", "macro_f1", "macro_f1_ci95", "accuracy", "top5")


def build_eval(results: dict[str, dict]) -> dict:
    risk, attack, cwe = results["risk"], results["attack"], results["cwe"]
    extract_eval, ner = results["extract"], results["ner"]
    test = pick(attack, "results", "test", "nvd")
    return {
        "risk": {
            "headline": pick(risk, "headline"),
            "decision": pick(risk, "decision"),
            "secondary_paired": pick(risk, "secondary_paired"),
            "random_expected": pick(risk, "random_expected"),
            "folds": pick(risk, "folds"),
            "tiers": pick(risk, "tiers_logistic"),
            "methods": {
                m: {
                    "pooled": {k: pick(cell, "pooled", k) for k in RISK_POOLED},
                    "per_fold": {
                        f: {k: pick(cell, "per_fold", f, k) for k in RISK_FOLD}
                        for f in pick(cell, "per_fold")
                    },
                }
                for m, cell in pick(risk, "methods").items()
            },
        },
        "attack": {
            "primary": pick(attack, "primary"),
            "splits": pick(attack, "splits"),
            "test_nvd": {
                m: {t: {k: pick(test, m, t, k) for k in ATTACK_METRICS} for t in test[m]}
                for m in test
            },
        },
        "cwe": {
            "headline": pick(cwe, "headline"),
            "classes": pick(cwe, "classes", "known"),
            "test": {
                m: {s: {k: pick(cells, s, k) for k in CWE_METRICS} for s in cells}
                for m, cells in pick(cwe, "test").items()
            },
        },
        "extract": {
            # overall includes the CVE-ID and CVSS strata (precision 1.0): show per type too
            "overall_including_identifiers": pick(extract_eval, "review", "overall"),
            "per_type": pick(extract_eval, "review", "per_type"),
            "per_origin": pick(extract_eval, "review", "per_origin"),
        },
        "ner": {
            "model": pick(ner, "model"),
            "exact": pick(ner, "text_derived_spans", "exact"),
            "overlap": pick(ner, "text_derived_spans", "overlap"),
        },
    }


# ---- files ------------------------------------------------------------------------------------


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def epss_versions(records: Iterable[dict]) -> dict[str, list[str]]:
    seen: dict[str, set[str]] = defaultdict(set)
    for record in records:
        for as_of, signals in record["signals"].items():
            if version := (signals.get("epss") or {}).get("model_version"):
                seen[as_of].add(version)
    return {a: sorted(v) for a, v in sorted(seen.items())}


def validate(files: dict[str, dict]) -> dict[str, dict]:
    """Each file through its schema model (raises on any mismatch); returns them unchanged."""
    if set(files) != set(schema.FILES):
        raise ValueError(f"export files {sorted(files)} != {sorted(schema.FILES)}")
    for name, data in files.items():
        schema.FILES[name].model_validate(data)
    return files


def disclosures(
    versions: dict[str, list[str]],
    prevalence: float,
    folds: dict[str, dict],
    recent: int,
    tiered: int,
    age_weight: float,
) -> list[str]:
    train = sorted({v for a in cfg.CUTOFFS for v in versions.get(a, [])})
    values = {
        "window_start": cfg.NVD_WINDOW_START,
        "prevalence": f"{prevalence:.3%}",
        "snapshot_epss": ", ".join(versions.get("snapshot", [])) or "unknown",
        "train_epss": " and ".join(train),
        "test_span": f"{min(f['cutoff'] for f in folds.values())} to "
        f"{max(f['window_end'] for f in folds.values())}",
        "recent": recent,
        "tiered": tiered,
        "age_weight": age_weight,
    }
    return [d.format(**values) for d in DISCLOSURES]


def load_threats(path: Path, day: str) -> dict | None:
    """The ``cti threats`` document for ``day``, or ``None`` if it has not been run."""
    import json

    if not path.exists():
        return None
    doc = json.loads(path.read_text())
    if doc["snapshot_date"] != day:
        raise ConfigError(f"{path} is for {doc['snapshot_date']}, not {day}")
    return doc


def build_threats(doc: dict | None, tiers: dict[str, str], technique_names: dict[str, str]):
    """``threats.json`` from a ``cti threats`` document (or ``None``: not yet run).

    ``tiers``: this export's tier per ranked CVE (baseline excluded), checked against the
    tier ``cti threats`` recorded on every link, so a stale threats file fails the export.
    """
    if doc is None:
        return {
            "available": False,
            "snapshot_date": None,
            "families_total": 0,
            "families": [],
            "categories": [],
            "kev_ransomware_cves": 0,
            "review": None,
        }
    stale = sorted(
        c["cve"] for f in doc["families"] for c in f["cves"] if c["tier"] != tiers.get(c["cve"])
    )
    if stale:
        raise ConfigError(
            f"threats.json tiers differ from this export for {stale[:5]}; "
            "rerun `cti threats`, then `cti export`"
        )
    top = [f for f in doc["families"] if f["rank"] <= TOP_THREATS]
    if unchecked := [f["family"] for f in top if f["category_source"] != "owner"]:
        raise ConfigError(
            f"priority top {TOP_THREATS} must be hand-labelled; not yet: {unchecked}; "
            "run `cti threats-sheet --priority`, label, then `cti threats`"
        )
    # below the top, a family appears only for a link that was not reviewed as wrong
    shown = top + [
        f
        for f in doc["families"]
        if f["rank"] > TOP_THREATS and any(c["review"] != "rejected" for c in f["cves"])
    ]
    families = [
        {
            "rank": f["rank"],
            "family": f["family"],
            "categories": f["categories"],
            "category_source": f["category_source"],
            "attack_software": f["attack"]["software"],
            "attack_name": f["attack"]["name"],
            "techniques": [
                {"id": t, "name": technique_names.get(t, t)} for t in f["attack"]["techniques"]
            ],
            "tactics": f["attack"]["tactics"],
            "links": [
                {
                    "cve": c["cve"],
                    "via": c["via"],
                    "surface": sorted({e["surface"] for e in c["evidence"]}),
                    "evidence_text": next(
                        (e["text"] for e in c["evidence"] if e.get("text")), None
                    ),
                    "review": c["review"],
                    "counts_for_priority": c["counts_for_priority"],
                    "in_kev": c["in_kev"],
                    "tier": c["tier"],
                }
                for c in f["cves"]
            ],
            "linked_kev_cves": f["priority_keys"]["linked_kev_cves"],
            "linked_high_tier_cves": f["priority_keys"]["linked_high_tier_cves"],
            "ioc_rows": f["priority_keys"]["ioc_rows"],
            "ioc_growth": f["priority_keys"]["ioc_growth"],
            "why": f["why"],
        }
        for f in shown
    ]
    review = doc["review"]
    precision = (review["links"].get("precision") or {}).get("all")
    return {
        "available": True,
        "snapshot_date": doc["snapshot_date"],
        "families_total": len(doc["families"]),
        "families": families,
        "categories": [
            {"category": cat, "ioc_rows": rows}
            for cat, rows in sorted(doc["category_rows"].items(), key=lambda kv: (-kv[1], kv[0]))
        ],
        "kev_ransomware_cves": len(doc["kev_ransomware_cves"]),
        "review": {
            "labeller": review["labeller"],
            "hand_labelled_families": doc["summary"]["category_source"].get("owner", 0),
            "links_reviewed": precision["n"] if precision else 0,
            "links_correct": precision["correct"] if precision else 0,
            "link_precision_ci95": tuple(precision["ci95"]) if precision else None,
        },
    }


def tier_lookup(scored: dict) -> dict[str, str]:
    return {r["cve"]: t for r, t in zip(scored["records"], scored["tier"], strict=True)}


def inputs(data_dir: Path, day: str) -> dict[str, Path]:
    from cti.nlp.attack_eval import CTID_FILE

    processed, extracted = data_dir / "processed" / day, data_dir / "extracted" / day
    evals = data_dir / "eval" / day
    return {
        "cves": data_dir / "enriched" / day / "cves.jsonl.gz",
        "cves_summary": data_dir / "enriched" / day / "cves-summary.json",
        "nvd": processed / "nvd.jsonl.gz",
        "cwe": processed / "cwe.jsonl.gz",
        "attack": processed / "attack.jsonl.gz",
        "threatfox": processed / "threatfox.jsonl.gz",
        "urlhaus": processed / "urlhaus.jsonl.gz",
        "iocs": extracted / "iocs.jsonl.gz",
        "ctid": data_dir / CTID_FILE,
        **{f"{name}_eval": evals / f"{name}-eval.json" for name in EVALS},
        "threats": data_dir / "threats" / day / "threats.json",  # optional
    }


EVALS = ("risk", "attack", "cwe", "extract", "ner")


def run(paths: dict[str, Path], revoked: dict[str, str], git: dict, log=print) -> dict:
    """Every export file, validated. ``paths`` from ``inputs``; ``revoked`` ATT&CK remaps."""
    import json

    from cti.enrich import read_jsonl
    from cti.nlp.attack_catalog import load_techniques
    from cti.nlp.attack_eval import load_ctid

    optional = {"threats"}
    if missing := [str(p) for n, p in paths.items() if n not in optional and not p.exists()]:
        raise ConfigError(f"missing inputs {missing}; run the pipeline through `cti risk-eval`")
    results = {n: json.loads(paths[f"{n}_eval"].read_text()) for n in EVALS}
    config_sha = config_guard(results["risk"])
    summary = json.loads(paths["cves_summary"].read_text())
    dates = summary["as_of_dates"]
    day = dates["snapshot"]
    provenance = results["risk"]["provenance"]
    if provenance.get("cves_sha256") != summary.get("cves_sha256"):
        raise ConfigError("risk-eval.json was computed from other enriched data; rerun it")

    def cves():
        return read_jsonl(paths["cves"])

    windows = risk_eval.build_windows(cves(), dates)
    fitted = refit(windows)
    positives = {w: int(windows[w].y.sum()) for w in cfg.CUTOFFS}
    training_rows = sum(len(windows[w].y) for w in cfg.CUTOFFS)
    log(f"  refit on {training_rows:,} rows, {sum(positives.values())} positives")
    del windows
    scored = score_snapshot(cves(), day, fitted)
    tiered = {
        r["cve"] for r, t in zip(scored["records"], scored["tier"], strict=True) if t != "baseline"
    }
    log(f"  ranked {len(scored['records']):,} snapshot CVEs; {len(tiered):,} tiered")
    context = nvd_context(read_jsonl(paths["nvd"]), tiered)
    risk = build_risk(scored, fitted, positives, training_rows, results["risk"], context, day)
    iocs = build_iocs(
        read_jsonl(paths["iocs"]), read_jsonl(paths["threatfox"]), read_jsonl(paths["urlhaus"])
    )
    cwe_names = {r["source_id"]: r["title"] for r in read_jsonl(paths["cwe"])}
    slim = {r["cve"]: r for r in scored["records"]}
    graphs = {
        "weakness": weakness_graph(risk["rows"], slim, cwe_names),
        "attack": attack_graphs(
            load_ctid(paths["ctid"]), revoked, load_techniques(paths["nvd"].parent)
        ),
        "shared_hosts": shared_host_graph(
            read_jsonl(paths["iocs"]), tier_lookup(scored), scored["in_kev"]
        ),
    }
    threats_doc = load_threats(paths["threats"], day)
    shown_tiers = {c: t for c, t in tier_lookup(scored).items() if t != "baseline"}
    names = {t.id: t.name for t in load_techniques(paths["nvd"].parent)}
    threats = build_threats(threats_doc, shown_tiers, names)
    shown = f"{len(threats['families'])} families shown" if threats_doc else "not run"
    log(f"  threats: {shown}")
    evals = build_eval(results)
    evals["sources_sha256"] = {n: sha256(paths[f"{n}_eval"]) for n in EVALS}
    versions = epss_versions(cves())
    meta = {
        "schema_version": schema.SCHEMA,
        "snapshot_date": day,
        "as_of_dates": dates,
        "kev_catalog_version": provenance["kev_catalog_version"],
        "epss_model_versions": versions,
        "git": git,
        "config_sha256": config_sha,
        "inputs_sha256": {
            name: sha256(p)
            for name, p in sorted(paths.items())
            if not name.endswith("_eval") and p.exists()
        },
        "disclosures": disclosures(
            versions,
            sum(positives.values()) / training_rows,
            results["risk"]["folds"],
            sum(r["age_days"] <= RECENT_DAYS for r in risk["rows"]),
            len(risk["rows"]),
            next(c["refit"] for c in risk["coefficients"] if c["feature"] == "log_age_days"),
        )
        + ([THREATS_DISCLOSURE] if threats_doc else []),
    }
    return validate(
        {
            "meta.json": meta,
            "risk.json": risk,
            "iocs.json": iocs,
            "graphs.json": graphs,
            "eval.json": evals,
            "threats.json": threats,
        }
    )


def write(out_dir: Path, files: dict[str, dict]) -> dict[str, int]:
    """Compact, key-sorted JSON (the risk file is large); atomic per file. Returns sizes."""
    import json
    import os

    out_dir.mkdir(parents=True, exist_ok=True)
    sizes = {}
    for name, data in sorted(files.items()):
        path = out_dir / name
        tmp = path.with_name(f".{name}.tmp")
        text = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        tmp.write_text(text + "\n", encoding="utf-8")
        os.replace(tmp, path)
        sizes[name] = path.stat().st_size
    return sizes
