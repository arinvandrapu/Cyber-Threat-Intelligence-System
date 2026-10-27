import csv
import gzip
import hashlib
import json

import pytest

from cti.cli import main
from cti.gold import GoldEntity, GoldRecord
from cti.nlp import evaluate

from .conftest import gzip_bytes, jsonl

DAY = "2026-10-26"
PAGE = (
    "Threat report. The Sednit group used C2 servers 203.0.113[.]7 and evil[.]example(.)com, "
    "dropping a payload with SHA-256 "
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 via CVE-2026-1234."
)


def attack(ext_id, title, stix_type, aliases):
    return {
        "source_id": ext_id,
        "title": title,
        "metadata": {"stix_type": stix_type, "aliases": aliases},
    }


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    processed = tmp_path / "processed" / DAY
    enriched = tmp_path / "enriched" / DAY
    processed.mkdir(parents=True)
    enriched.mkdir(parents=True)
    nvd = [
        {"id": "nvd:CVE-2026-1234", "source_id": "CVE-2026-1234", "text": "Bug in example.com."},
        {"id": "nvd:CVE-2026-0001", "source_id": "CVE-2026-0001", "text": "No indicators."},
        {"id": "nvd:CVE-2026-0002", "source_id": "CVE-2026-0002", "text": ""},
    ]
    (processed / "nvd.jsonl.gz").write_bytes(gzip_bytes(jsonl(nvd)))
    groups = [attack("G0007", "APT28", "intrusion-set", ["APT28", "Sednit"])]
    (processed / "attack.jsonl.gz").write_bytes(gzip_bytes(jsonl(groups)))
    tf = [{"metadata": {"malware": "Mirai", "malware_alias": "None"}}]
    (processed / "threatfox.jsonl.gz").write_bytes(gzip_bytes(jsonl(tf)))
    refs = [
        {"id": "references:a", "cve": "CVE-2026-1234", "in_corpus": True, "text": PAGE},
        {"id": "references:b", "cve": "CVE-2026-1234", "in_corpus": False, "text": "1.2.3.4"},
    ]
    (enriched / "references.jsonl.gz").write_bytes(gzip_bytes(jsonl(refs)))
    monkeypatch.setenv("CTI_DATA_DIR", str(tmp_path))
    return tmp_path


def rows(path):
    with gzip.open(path, "rt") as fh:
        return [json.loads(line) for line in fh]


def test_cli_extract_writes_defanged_tagged_rows(data_dir, capsys):
    assert main(["extract", "--date", DAY]) == 0
    out = data_dir / "extracted" / DAY
    iocs = rows(out / "iocs.jsonl.gz")
    assert [(r["origin"], r["doc_id"]) for r in iocs] == [
        ("nvd_description", "nvd:CVE-2026-1234"),
        ("reference_page", "references:a"),  # references:b is not in the corpus
    ]
    page = {i["type"]: i for i in iocs[1]["iocs"]}
    assert page["ipv4"]["value"] == "203.0.113[.]7"
    assert page["domain"]["value"] == "evil[.]example[.]com"
    assert page["ipv4"]["defanged_in_source"] is True
    assert set(page) == {"ipv4", "domain", "sha256", "cve"}
    summary = json.loads((out / "iocs-summary.json").read_text())
    digest = hashlib.sha256((out / "iocs.jsonl.gz").read_bytes()).hexdigest()
    assert summary["iocs_sha256"] == digest
    assert summary["docs"] == {"nvd_description": 2, "reference_page": 1}
    assert summary["headline_origin"] == "reference_page"
    [alias_row] = rows(out / "aliases.jsonl.gz")
    assert alias_row["aliases"][0]["ids"] == ["G0007"]
    assert "extracted iocs" in capsys.readouterr().out


def test_cli_extract_is_byte_deterministic(data_dir):
    path = data_dir / "extracted" / DAY / "iocs.jsonl.gz"
    main(["extract", "--date", DAY, "--only", "iocs"])
    first = path.read_bytes()
    main(["extract", "--date", DAY, "--only", "iocs"])
    assert path.read_bytes() == first


def test_cli_extract_validates_inputs(data_dir, capsys):
    assert main(["extract", "--date", DAY, "--only", "nope"]) == 2
    (data_dir / "processed" / DAY / "attack.jsonl.gz").unlink()
    assert main(["extract", "--date", DAY]) == 2
    assert "run `cti parse`" in capsys.readouterr().err


def test_cli_review_sample_and_score(data_dir):
    main(["extract", "--date", DAY, "--only", "iocs"])
    assert main(["extract-eval", "--date", DAY, "--sample", "3", "--seed", "1"]) == 0
    sheet = data_dir / "eval" / DAY / "ioc-review-sample-seed1.csv"
    with sheet.open() as fh:
        sample = list(csv.DictReader(fh))
    assert len(sample) == 3
    for rec in sample:
        assert "http" not in rec["context"] and "203.0.113.7" not in rec["context"]
        assert "[[" in rec["context"]
        rec["correct"] = "y"
    labels = data_dir / "labels.csv"
    with labels.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["doc_id", "type", "start", "end", "correct"])
        w.writeheader()
        w.writerows({k: r[k] for k in w.fieldnames} for r in sample)
    assert main(["extract-eval", "--date", DAY, "--labels", str(labels)]) == 0
    result = json.loads((data_dir / "eval" / DAY / "extract-eval.json").read_text())
    assert result["review"]["labelled"] == 3
    assert result["review"]["overall"]["precision"] == 1.0
    assert result["review"]["overall"]["ci95"][0] < 1.0  # all-correct still has an interval


def test_draw_sample_is_stratified_and_seeded():
    rows_ = [
        {"doc_id": f"d{i}", "origin": "o", "iocs": [{"type": t, "start": 0, "end": 1}]}
        for i, t in enumerate(["a"] * 50 + ["b"] * 2)
    ]
    sample = evaluate.draw_sample(rows_, 6, seed=7)
    kinds = sorted(ioc["type"] for _, ioc in sample)
    assert kinds == ["a", "a", "a", "a", "b", "b"]  # b is exhausted, a gets the spare slots
    assert evaluate.draw_sample(rows_, 6, seed=7) == sample


def test_read_labels_rejects_unknown_marks(tmp_path):
    path = tmp_path / "l.csv"
    path.write_text("doc_id,type,start,end,correct\nd,a,0,1,maybe\n")
    with pytest.raises(ValueError, match="y or n"):
        evaluate.read_labels(path)


def test_wilson():
    assert evaluate.wilson(0, 0) == (0.0, 0.0)
    lo, hi = evaluate.wilson(12, 12)
    assert lo < 1.0 and hi == 1.0


def gold(source, text, entities):
    return GoldRecord(
        id=f"{source}:1",
        source=source,
        title="t",
        text=text,
        labels=["x"],
        primary_label="x",
        label_signals=[],
        entities=[GoldEntity(derivation="regex", **e) for e in entities],
    )


def test_gold_eval_scores_only_labelled_sources_and_audits_cvss():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    tf_text = "Malicious domains: bad.example.com, also see tria.ge"
    nvd_text = f"CVE-2026-1001 on vendor.example.org. Vector: {vector}"
    records = [
        gold("threatfox", tf_text, [dict(type="domain", value="bad.example.com", start=19, end=0)]),
        gold(
            "nvd_ref",
            nvd_text,
            [
                dict(type="cve_id", value="CVE-2026-1001", start=0, end=13),
                dict(type="cvss_score", value="3.1", start=nvd_text.index("3.1"), end=0),
            ],
        ),
    ]
    result = evaluate.gold_eval(records)
    assert result["scored_sources"] == {"cve_id": ["nvd_ref"], "domain": ["threatfox"]}
    # vendor.example.org (an unlabelled source) is not scored; tria.ge is an unlabelled
    # real name in a labelled record, so precision is a lower bound
    assert result["scores"]["domain"] == {
        "tp": 1,
        "fp": 1,
        "fn": 0,
        "precision": 0.5,
        "recall": 1.0,
    }
    assert result["scores"]["cve_id"]["recall"] == 1.0
    assert result["cvss_score_label_audit"]["vector_version_labelled_as_score"] == 1
