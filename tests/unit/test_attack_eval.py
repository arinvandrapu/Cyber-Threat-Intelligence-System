import hashlib
import json

import pytest

np = pytest.importorskip("numpy")  # the ml extra
pytest.importorskip("sklearn")

from cti.cli import main  # noqa: E402
from cti.nlp import attack_eval as ae  # noqa: E402
from cti.nlp.attack_catalog import (  # noqa: E402
    Technique,
    clean,
    parent,
    revocations_from_bundle,
)
from cti.snapshot import Snapshot  # noqa: E402
from cti.storage import LocalStorage  # noqa: E402

from .conftest import gzip_bytes, jsonl  # noqa: E402

DAY = "2026-10-26"


def tech(tid, name, text=""):
    return Technique(tid, name, (), f"{name}. {text}")


TECHNIQUES = [
    tech("T1190", "Exploit Public-Facing Application", "web server internet facing exploit"),
    tech("T1059", "Command and Scripting Interpreter", "execute commands shell"),
    tech("T1059.004", "Unix Shell", "bash unix shell commands"),
    tech("T1068", "Exploitation for Privilege Escalation", "kernel driver elevate privileges"),
]


def test_parent_and_clean():
    assert parent("T1059.004") == "T1059" and parent("T1190") == "T1190"
    text = "Adversaries use [PowerShell](https://attack.mitre.org/T1059/001) (Citation: X 2020)."
    assert clean(text) == "Adversaries use PowerShell."


def test_revocations_follow_chains():
    def pattern(i, ext):
        return {
            "type": "attack-pattern",
            "id": f"attack-pattern--{i}",
            "external_references": [{"source_name": "mitre-attack", "external_id": ext}],
        }

    def revoked(a, b):
        return {
            "type": "relationship",
            "relationship_type": "revoked-by",
            "source_ref": f"attack-pattern--{a}",
            "target_ref": f"attack-pattern--{b}",
        }

    objects = [pattern(1, "T1"), pattern(2, "T2"), pattern(3, "T3"), revoked(1, 2), revoked(2, 3)]
    assert revocations_from_bundle(objects) == {"T1": "T3", "T2": "T3"}


def ctid_file(tmp_path, mappings):
    path = tmp_path / "ctid.json"
    path.write_text(json.dumps({"metadata": {}, "mapping_objects": mappings}))
    return path


def mapping(cve, kind, tid):
    return {
        "capability_id": cve,
        "mapping_type": kind,
        "attack_object_id": tid,
        "comments": "the labeller's rationale",  # must never reach a ranker
        "capability_group": "rce",
    }


def test_load_ctid_checks_hash_and_drops_labeller_fields(tmp_path):
    path = ctid_file(tmp_path, [mapping("CVE-2024-0001", "exploitation_technique", "T1190")])
    with pytest.raises(ValueError, match="does not match"):
        ae.load_ctid(path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    rows = ae.load_ctid(path, digest)
    assert rows == [
        {"cve": "CVE-2024-0001", "type": "exploitation_technique", "technique": "T1190"}
    ]


def test_gold_labels_roll_up_and_remap():
    rows = [
        {"cve": "C1", "type": "primary_impact", "technique": "T1059.004"},
        {"cve": "C1", "type": "primary_impact", "technique": "T1562.001"},
        {"cve": "C1", "type": "exploitation_technique", "technique": "T1190"},
    ]
    gold, remapped = ae.gold_labels(rows, {"T1562.001": "T1685"})
    assert gold == {
        "C1": {"primary_impact": {"T1059", "T1685"}, "exploitation_technique": {"T1190"}}
    }
    assert remapped == 1


def test_rank_parents_uses_max_over_subtechniques_and_breaks_ties_by_id():
    scores = np.array([[0.1, 0.2, 0.9, 0.0], [0.0, 0.0, 0.0, 0.0]])
    ranked = ae.rank_parents(scores, TECHNIQUES)
    assert ranked[0][0] == "T1059"  # via its sub-technique T1059.004
    assert ranked[1] == ["T1059", "T1068", "T1190"]


def test_per_cve_metrics():
    m = ae._per_cve(["T1", "T2", "T3"], {"T2", "T9"})
    assert m["hit@1"] == 0.0 and m["hit@3"] == 1.0
    assert m["recall@3"] == 0.5 and m["mrr"] == 0.5


def test_majority_is_fit_on_dev_only():
    dev = {"D1": {"exploitation_technique": {"T1068"}}, "D2": {"exploitation_technique": {"T1068"}}}
    ranker = ae.MajorityRanker(dev, "exploitation_technique", TECHNIQUES)
    assert ranker.rank(["anything"])[0][0] == "T1068"


def test_evaluate_never_fits_majority_on_test_labels():
    # two test CVEs labelled T1068 would flip the prior if test labels leaked into it
    gold = {
        "CVE-2024-0001": {"exploitation_technique": {"T1068"}},
        "CVE-2024-0002": {"exploitation_technique": {"T1068"}},
        "CVE-2020-0001": {"exploitation_technique": {"T1190"}},
    }
    texts = {
        "nvd": {"CVE-2024-0001": "x", "CVE-2024-0002": "y"},
        "kev": {c: "z" for c in gold},
    }
    cell = ae.evaluate(gold, texts, TECHNIQUES, {})["results"]["test"]["nvd"]["majority"]
    assert cell["exploitation_technique"]["hit@1"]["value"] == 0.0  # prior says T1190


def test_tfidf_ranks_by_text():
    ranker = ae.TfidfRanker(TECHNIQUES)
    [ranked] = ranker.rank(["a kernel driver flaw lets a local user elevate privileges"])
    assert ranked[0] == "T1068"


def test_evaluate_splits_and_compares_with_majority():
    gold = {
        "CVE-2024-0001": {"exploitation_technique": {"T1068"}},
        "CVE-2024-0002": {"exploitation_technique": {"T1190"}},
        "CVE-2020-0001": {"exploitation_technique": {"T1190"}},
    }
    texts = {
        "nvd": {
            "CVE-2024-0001": "kernel driver lets a local user elevate privileges",
            "CVE-2024-0002": "internet facing web server exploit",
        },
        "kev": {c: "a vulnerability" for c in gold},
    }
    result = ae.evaluate(gold, texts, TECHNIQUES, {"tfidf": ae.TfidfRanker(TECHNIQUES).rank})
    assert result["splits"] == {"dev": 1, "test": 2}
    cell = result["results"]["test"]["nvd"]
    assert cell["tfidf"]["exploitation_technique"]["hit@1"]["value"] == 1.0
    assert cell["majority"]["exploitation_technique"]["hit@1"]["value"] == 0.5  # T1190 prior
    assert cell["tfidf"]["exploitation_technique"]["vs_majority"]["difference"] == 0.0  # hit@5
    assert "nvd" not in result["results"]["dev"]  # dev CVEs have no NVD text
    assert cell["tfidf"]["primary_impact"]["cves"] == 0


def test_cli_attack_eval(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTI_DATA_DIR", str(tmp_path))
    processed = tmp_path / "processed" / DAY
    processed.mkdir(parents=True)
    attack_docs = [
        {
            "source_id": t.id,
            "title": t.name,
            "text": t.text.split(". ", 1)[1],
            "metadata": {"stix_type": "attack-pattern", "tactics": [], "aliases": []},
        }
        for t in TECHNIQUES
    ]
    (processed / "attack.jsonl.gz").write_bytes(gzip_bytes(jsonl(attack_docs)))
    nvd = [{"source_id": "CVE-2024-0001", "text": "kernel driver elevate privileges"}]
    (processed / "nvd.jsonl.gz").write_bytes(gzip_bytes(jsonl(nvd)))
    kev = [
        {"source_id": c, "title": "Bug", "text": "a bug"} for c in ("CVE-2024-0001", "CVE-2020-1")
    ]
    (processed / "kev.jsonl.gz").write_bytes(gzip_bytes(jsonl(kev)))
    snap = Snapshot.create(LocalStorage(tmp_path / "snapshots"), DAY)
    bundle = {"objects": []}
    snap.write_raw("attack", "enterprise-attack.json.gz", gzip_bytes(json.dumps(bundle).encode()))
    ctid = ctid_file(
        tmp_path,
        [
            mapping("CVE-2024-0001", "exploitation_technique", "T1068"),
            mapping("CVE-2020-1", "exploitation_technique", "T1190"),
        ],
    )
    assert main(["attack-eval", "--date", DAY, "--ctid", str(ctid)]) == 2  # unpinned hash
    monkeypatch.setattr(ae, "CTID_SHA256", hashlib.sha256(ctid.read_bytes()).hexdigest())
    monkeypatch.setattr(ae.load_ctid, "__defaults__", (ae.CTID_SHA256,))
    assert main(["attack-eval", "--date", DAY, "--ctid", str(ctid)]) == 0
    result = json.loads((tmp_path / "eval" / DAY / "attack-eval.json").read_text())
    assert result["methods"] == ["majority", "tfidf"]
    assert result["ctid"]["cves"] == 2 and result["splits"] == {"dev": 1, "test": 1}
    assert "tfidf" in capsys.readouterr().out
    assert main(["attack-eval", "--date", DAY, "--methods", "nope"]) == 2
