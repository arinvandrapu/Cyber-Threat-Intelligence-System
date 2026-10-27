import hashlib
import io
import json

import pytest

from cti.cli import main
from cti.enrich import read_jsonl, write_jsonl
from cti.enrich.cves import SIGNAL_SOURCES, build, cve_sort_key, features_at
from cti.enrich.cwe import describe, load_catalog
from cti.snapshot import Snapshot
from cti.storage import LocalStorage

from .conftest import gzip_bytes, jsonl, zip_bytes

CUTOFF, SNAPSHOT = "2026-04-29", "2026-10-26"
DATES = {"cutoff": CUTOFF, "snapshot": SNAPSHOT}

CWE_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7"><Weaknesses>
<Weakness ID="664" Name="Improper Control" Abstraction="Pillar" Status="Stable"/>
<Weakness ID="118" Name="Wrong Range" Abstraction="Class" Status="Draft">
 <Related_Weaknesses>
  <Related_Weakness Nature="ChildOf" CWE_ID="664" View_ID="1000" Ordinal="Primary"/>
 </Related_Weaknesses></Weakness>
<Weakness ID="119" Name="Buffer" Abstraction="Base" Status="Stable">
 <Related_Weaknesses>
  <Related_Weakness Nature="ChildOf" CWE_ID="20" View_ID="1003" Ordinal="Primary"/>
  <Related_Weakness Nature="ChildOf" CWE_ID="118" View_ID="1000" Ordinal="Primary"/>
 </Related_Weaknesses>
 <Mapping_Notes><Usage>Discouraged</Usage><Rationale>Too broad.</Rationale></Mapping_Notes>
</Weakness>
<Weakness ID="132" Name="DEPRECATED: Old" Abstraction="Base" Status="Deprecated"/>
<Weakness ID="900" Name="Loop A" Abstraction="Base" Status="Draft">
 <Related_Weaknesses>
  <Related_Weakness Nature="ChildOf" CWE_ID="901" View_ID="1000" Ordinal="Primary"/>
 </Related_Weaknesses></Weakness>
<Weakness ID="901" Name="Loop B" Abstraction="Base" Status="Draft">
 <Related_Weaknesses>
  <Related_Weakness Nature="ChildOf" CWE_ID="900" View_ID="1000" Ordinal="Primary"/>
 </Related_Weaknesses></Weakness>
</Weaknesses><Categories>
<Category ID="264" Name="Permissions" Status="Obsolete">
 <Mapping_Notes><Usage>Prohibited</Usage></Mapping_Notes></Category>
</Categories></Weakness_Catalog>"""


@pytest.fixture
def catalog():
    return load_catalog(io.BytesIO(CWE_XML))


def test_cwe_catalog_kinds_and_pillars(catalog):
    assert describe(catalog, "CWE-119") == {
        "id": "CWE-119",
        "name": "Buffer",
        "kind": "weakness",
        "pillar": "CWE-664",  # Base -> Class -> Pillar, ignoring the view-1003 parent
        "usage": "Discouraged",  # MITRE's mapping guidance
    }
    assert describe(catalog, "CWE-264")["usage"] == "Prohibited"
    assert describe(catalog, "CWE-118")["usage"] is None  # no Mapping_Notes
    assert describe(catalog, "CWE-664")["pillar"] == "CWE-664"
    assert describe(catalog, "CWE-264")["kind"] == "category"
    assert describe(catalog, "CWE-132")["kind"] == "deprecated"
    assert describe(catalog, "CWE-900")["pillar"] is None  # cycle terminates
    assert describe(catalog, "CWE-99999") == {
        "id": "CWE-99999",
        "name": None,
        "kind": "unknown",
        "pillar": None,
        "usage": None,
    }


def nvd(cve, published, cwes=(), refs=()):
    return {
        "source_id": cve,
        "published": f"{published}T10:00:00",
        "metadata": {
            "vuln_status": "Analyzed",
            "cvss_nvd": {"base_score": 9.8},
            "cvss_cna": {"base_score": 7.5},
            "cwes": list(cwes),
            "references": list(refs),
        },
    }


def signal(cve, source, as_of, **values):
    return {"cve": cve, "source": source, "as_of": as_of, "values": values}


def write_processed(path, rows_by_source):
    path.mkdir(parents=True, exist_ok=True)
    for source in ("nvd", "kev", "references", *SIGNAL_SOURCES):
        (path / f"{source}.jsonl.gz").write_bytes(gzip_bytes(jsonl(rows_by_source.get(source, []))))


@pytest.fixture
def processed(tmp_path):
    path = tmp_path / "parsed"
    write_processed(
        path,
        {
            "nvd": [
                nvd(
                    "CVE-2026-10000",
                    "2026-01-01",
                    cwes=["CWE-119"],
                    refs=[
                        "https://www.exploit-db.com/exploits/1",
                        "https://github.com/a/b/commit/c",
                    ],
                ),
                nvd("CVE-2026-9999", "2026-01-02"),  # added to KEV after the cutoff
                nvd("CVE-2026-0001", "2026-02-01"),  # added to KEV on the cutoff day
                nvd("CVE-2026-0002", "2026-06-01"),  # published after the cutoff
            ],
            "kev": [
                {"source_id": "CVE-2026-9999", "metadata": kev("2026-05-15")},
                {"source_id": "CVE-2026-0001", "metadata": kev(CUTOFF)},
                {"source_id": "CVE-2019-0001", "metadata": kev("2020-01-01")},  # not in window
            ],
            "epss": [
                signal("CVE-2026-9999", "epss", "cutoff", epss=0.1, score_date=CUTOFF),
                signal("CVE-2026-9999", "epss", "snapshot", epss=0.9),
            ],
            "exploitdb": [
                signal("CVE-2026-9999", "exploitdb", "snapshot", exploit_count=1),
                {"id": "exploitdb:1", "cves": ["CVE-2026-9999"]},  # a document, not a signal
            ],
            "references": [{"id": "references:x", "cves": ["CVE-2026-9999"]}],
        },
    )
    return path


def kev(date_added):
    return {"date_added": date_added, "ransomware_use": "Unknown"}


@pytest.fixture
def joined(processed, catalog):
    rows, summary = build(processed, catalog, DATES)
    return {r["cve"]: r for r in rows}, rows, summary


def test_rows_sorted_numerically(joined):
    _, rows, _ = joined
    assert [r["cve"] for r in rows] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
        "CVE-2026-9999",
        "CVE-2026-10000",
    ]
    assert cve_sort_key("CVE-2024-9999") < cve_sort_key("CVE-2024-10000")


def test_kev_boundary_and_eligibility(joined):
    by_cve, _, summary = joined
    assert by_cve["CVE-2026-9999"]["eligible"] == {"cutoff": True, "snapshot": False}
    # added on the cutoff day: already known at the cutoff, so not a forward positive
    assert by_cve["CVE-2026-0001"]["eligible"]["cutoff"] is False
    assert by_cve["CVE-2026-0002"]["eligible"]["cutoff"] is False  # not yet published
    assert summary["kev_positives"] == {"cutoff->snapshot": 1}
    assert summary["in_kev"] == 2  # the 2019 CVE is outside the NVD window


def test_features_are_point_in_time_only(joined):
    by_cve, _, _ = joined
    record = by_cve["CVE-2026-9999"]
    assert features_at(record, "cutoff") == {"epss": {"epss": 0.1, "score_date": CUTOFF}}
    assert "exploitdb" not in features_at(record, "cutoff")  # snapshot-only signal
    assert features_at(record, "snapshot")["exploitdb"] == {"exploit_count": 1}
    assert features_at(record, "unknown-label") == {}
    flat = json.dumps(features_at(record, "cutoff"))
    for snapshot_only in ("vuln_status", "cvss", "date_added", "page_count", "ref_types"):
        assert snapshot_only not in flat


def test_context_snapshot(joined):
    by_cve, _, _ = joined
    context = by_cve["CVE-2026-10000"]["context_snapshot"]
    assert context["ref_types"] == {"exploit": 1, "github_commit": 1}
    assert context["cwes"][0]["pillar"] == "CWE-664"
    assert context["cvss_cna"] == {"base_score": 7.5}
    assert by_cve["CVE-2026-9999"]["context_snapshot"]["page_count"] == 1


def test_join_is_generic_over_as_of_labels(processed, catalog):
    epss = processed / "epss.jsonl.gz"
    rows = [*read_jsonl(epss), signal("CVE-2026-9999", "epss", "cutoff-2026-07", epss=0.5)]
    epss.write_bytes(gzip_bytes(jsonl(rows)))
    with pytest.raises(ValueError, match="no date for as_of label"):
        build(processed, catalog, DATES)
    rows, summary = build(processed, catalog, {**DATES, "cutoff-2026-07": "2026-07-29"})
    [record] = [r for r in rows if r["cve"] == "CVE-2026-9999"]
    assert features_at(record, "cutoff-2026-07") == {"epss": {"epss": 0.5}}
    assert record["eligible"]["cutoff-2026-07"] is False  # in KEV since 2026-05-15
    assert summary["kev_positives"]["cutoff->cutoff-2026-07"] == 1


def test_write_jsonl_is_byte_deterministic(tmp_path, joined):
    _, rows, _ = joined
    write_jsonl(tmp_path / "a.jsonl.gz", rows)
    write_jsonl(tmp_path / "b.jsonl.gz", rows)
    assert (tmp_path / "a.jsonl.gz").read_bytes() == (tmp_path / "b.jsonl.gz").read_bytes()
    assert list(read_jsonl(tmp_path / "a.jsonl.gz")) == rows
    assert not list(tmp_path.glob(".*.tmp"))


@pytest.fixture
def data_dir(tmp_path, processed, monkeypatch):
    """A data dir with a snapshot holding only the CWE catalog, and the processed files."""
    snap = Snapshot.create(LocalStorage(tmp_path / "snapshots"), SNAPSHOT)
    snap.write_raw("cwe", "cwec.xml.zip", zip_bytes({"cwec.xml": CWE_XML}))
    target = tmp_path / "processed" / SNAPSHOT
    target.parent.mkdir(parents=True)
    processed.rename(target)
    monkeypatch.setenv("CTI_DATA_DIR", str(tmp_path))
    return tmp_path, target


def test_cli_enrich_writes_outputs(data_dir, capsys):
    root, _ = data_dir
    assert main(["enrich", "--date", SNAPSHOT, "--only", "cves"]) == 0
    out = root / "enriched" / SNAPSHOT
    assert len(list(read_jsonl(out / "cves.jsonl.gz"))) == 4
    summary = json.loads((out / "cves-summary.json").read_text())
    assert summary["as_of_dates"] == DATES
    assert not (root / "gold").exists()  # the gold set is never touched


def test_cli_enrich_rejects_mismatched_cutoff(data_dir, capsys, monkeypatch):
    monkeypatch.setenv("CTI_CUTOFF_DAYS", "90")
    assert main(["enrich", "--date", SNAPSHOT, "--only", "cves"]) == 2
    assert f"snapshot cutoff is {CUTOFF}, but CTI_CUTOFF_DAYS=90" in capsys.readouterr().err


def test_cli_enrich_needs_parsed_inputs(data_dir, capsys):
    _, processed = data_dir
    (processed / "kev.jsonl.gz").unlink()
    assert main(["enrich", "--date", SNAPSHOT, "--only", "cves"]) == 2
    assert "run `cti parse` first" in capsys.readouterr().err
    assert main(["enrich", "--date", SNAPSHOT, "--only", "bogus"]) == 2
    assert "unknown enrich steps" in capsys.readouterr().err


def test_cli_enrich_needs_a_dated_epss_cutoff(data_dir, capsys):
    _, processed = data_dir
    epss = [signal("CVE-2026-9999", "epss", "snapshot", epss=0.9)]
    (processed / "epss.jsonl.gz").write_bytes(gzip_bytes(jsonl(epss)))
    assert main(["enrich", "--date", SNAPSHOT, "--only", "cves"]) == 2
    assert "no dated EPSS cutoff rows" in capsys.readouterr().err


def test_cli_summary_records_data_hash(data_dir):
    root, _ = data_dir
    assert main(["enrich", "--date", SNAPSHOT, "--only", "cves"]) == 0
    out = root / "enriched" / SNAPSHOT
    summary = json.loads((out / "cves-summary.json").read_text())
    assert (
        summary["cves_sha256"] == hashlib.sha256((out / "cves.jsonl.gz").read_bytes()).hexdigest()
    )
