import hashlib
import json
import shutil
import subprocess

import pytest

np = pytest.importorskip("numpy")
pytest.importorskip("sklearn")

from cti.cli import _git_state  # noqa: E402
from cti.config import ConfigError  # noqa: E402
from cti.dashboard import export, schema  # noqa: E402
from cti.nlp import risk_config, risk_eval  # noqa: E402
from tests.unit.test_risk_eval import DATES, epss, record, synthetic_records  # noqa: E402

# ---- defanging ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("url", "hxxps://evil[.]example/a.b"),
        ("url", "fxp://user:pw@files[.]example/x"),
        ("url", "hxxp://203[.]0[.]113[.]7:8080/x"),
        ("domain", "evil[.]example"),
        ("ipv4", "203.0.113[.]7"),
        ("ipv6", "2001[:]db8[:][:]1"),
        ("sha256", "a" * 64),  # hashes aren't network indicators
    ],
)
def test_check_defanged_accepts(kind, value):
    export.check_defanged(kind, value)


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("url", "https://evil[.]example/x"),  # live scheme
        ("url", "ftp://files[.]example/x"),
        ("url", "hxxps://evil.example/x"),  # bare dot in the host
        ("url", "evil[.]example/x"),  # no scheme, no host to check
        ("domain", "evil.example"),
        ("ipv4", "203.0.113.7"),
        ("ipv6", "2001:db8::1"),
        ("ipv4", "1.2.3.4 [.]"),  # contains "[.]" but isn't the defanged form
        ("domain", "evil\u3002com"),  # full-width dot: browsers read it as "."
        ("url", "hxxp://evil\uff0ecom/x"),
    ],
)
def test_check_defanged_refuses_and_names_the_value(kind, value):
    with pytest.raises(ValueError, match="not defanged") as err:
        export.check_defanged(kind, value)
    assert value in str(err.value)


def test_descriptions_are_defanged_then_truncated():
    text = "Visit https://evil.example.com/x or 203.0.113.7 via update.example.com now."
    out = export.defang_text(text)
    assert "hxxps://evil[.]example[.]com/x" in out
    assert "203.0.113[.]7" in out and "update[.]example[.]com" in out
    assert "https://" not in out
    assert export.defang_text("mail a.b@mail.example.com") == "mail a.b[@]mail[.]example[.]com"
    short = export.truncate("word " * 100, limit=22)
    assert short == "word word word word …"
    assert export.truncate("  a   b ") == "a b"


# ---- risk -------------------------------------------------------------------------------------


def test_config_guard():
    with open(risk_config.__file__, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    assert export.config_guard({"provenance": {"config_sha256": digest}}) == digest
    with pytest.raises(ConfigError, match="differs from the evaluated config"):
        export.config_guard({"provenance": {"config_sha256": "0" * 64}})


def snapshot_records(n=400):
    """Synthetic records with snapshot signals, a CWE and CVSS for context."""
    out = []
    for i, rec in enumerate(synthetic_records(n)):
        p = 0.01 + (i % 97) / 100
        rec["signals"]["snapshot"] = {"epss": epss(p, DATES["snapshot"])}
        if i % 5 == 0:
            rec["signals"]["snapshot"]["nuclei"] = {}
        rec["context_snapshot"]["cwes"] = [
            {"id": "CWE-79", "kind": "weakness", "name": "XSS", "pillar": "CWE-707"}
        ]
        out.append(rec)
    out.append(record("CVE-2024-9999", kev="2024-06-01"))  # in KEV before the snapshot
    return out


def evaluated():
    tiers = {
        name: {"cves": 10, "kev_positives": 1, "hit_rate": 0.1, "wilson95": [0.02, 0.4]}
        for name, _ in risk_config.TIERS
    }
    return {
        "logistic_coefficients_last_fold_standardized": dict.fromkeys(risk_eval.FEATURES, 0.1),
        "tiers_logistic": {"tiers": tiers, "monotonic": True},
    }


def test_refit_scores_the_snapshot_without_labels():
    records = snapshot_records()
    windows = risk_eval.build_windows(records, DATES)
    fitted = export.refit(windows)
    positives = {w: int(windows[w].y.sum()) for w in risk_config.CUTOFFS}
    assert sum(positives.values()) > 0
    scored = export.score_snapshot(records, DATES["snapshot"], fitted)
    cves = [r["cve"] for r in scored["records"]]
    assert "CVE-2024-9999" not in cves  # KEV CVEs are never ranked
    assert len(cves) == sum(r["eligible"]["snapshot"] for r in records)
    assert list(scored["rank"]) == sorted(scored["rank"])  # best first
    assert not any("kev" in r for r in scored["records"])  # no labels carried

    risk = export.build_risk(scored, fitted, positives, 1, evaluated(), {}, DATES["snapshot"])
    schema.Risk.model_validate(risk)
    tiers = {t["name"]: t["cves"] for t in risk["tiers"]}
    assert sum(tiers.values()) == len(cves)
    assert len(risk["rows"]) == len(cves) - tiers["baseline"]
    assert {r["tier"] for r in risk["rows"]} <= {"critical", "high", "elevated"}
    row = risk["rows"][0]
    assert set(row["contributions"]) == set(risk_eval.FEATURES)
    # SSVC is missing in every snapshot record here: imputed and flagged
    assert {"ssvc_exploitation", "ssvc_automatable", "ssvc_total_impact"} <= set(row["imputed"])
    assert "epss_logit" not in row["imputed"]
    # contributions are coefficient x standardized value, exactly
    i = 0
    m = fitted.matrix(scored["x"][i : i + 1], None)[0]
    expected = round(float(fitted.model.coef_[0][0] * m[0]), 4)
    assert row["contributions"][risk_eval.FEATURES[0]] == expected


def test_snapshot_scores_ignore_everything_but_snapshot_features():
    """Changing labels, context or other dates' signals must not move the snapshot ranking."""
    records = snapshot_records()
    fitted = export.refit(risk_eval.build_windows(records, DATES))
    base = export.score_snapshot(records, DATES["snapshot"], fitted)
    for rec in records:
        rec["context_snapshot"] = {"cvss_cna": {"base_score": 10.0}, "cwes": [], "leak": 1}
        if rec["kev"] is None:
            rec["kev"] = {"date_added": "2026-12-01"}  # added after the snapshot
        for label in risk_config.CUTOFFS:
            rec["signals"].pop(label, None)
    again = export.score_snapshot(records, DATES["snapshot"], fitted)
    assert [r["cve"] for r in again["records"]] == [r["cve"] for r in base["records"]]
    assert np.array_equal(again["rank"], base["rank"])
    assert np.array_equal(again["contrib"], base["contrib"])


def test_contributions_and_intercept_reproduce_every_logit():
    records = snapshot_records()
    fitted = export.refit(risk_eval.build_windows(records, DATES))
    scored = export.score_snapshot(records, DATES["snapshot"], fitted)
    p = fitted.score(scored["x"])
    logit = np.log(p / (1 - p))
    total = scored["contrib"].sum(axis=1) + fitted.model.intercept_[0]
    assert np.allclose(total, logit, atol=1e-9)


def test_kev_marked_eligible_is_refused():
    rec = record("CVE-2024-0001", kev="2024-06-01")
    rec["eligible"]["snapshot"] = True
    fitted = export.refit(risk_eval.build_windows(snapshot_records(), DATES))
    with pytest.raises(ValueError, match="in KEV but marked eligible"):
        export.score_snapshot([rec], DATES["snapshot"], fitted)


def test_assign_tiers_matches_rank_fractions():
    scores = np.arange(2000, 0, -1, dtype=float)
    names = export.risk_eval.assign_tiers(scores)
    counts = {n: int((names == n).sum()) for n, _ in risk_config.TIERS}
    assert counts == {"critical": 2, "high": 18, "elevated": 80, "baseline": 1900}
    tied = risk_eval.assign_tiers(np.ones(10))  # all tied: average rank 5.5 -> baseline
    assert set(tied) == {"baseline"}


# ---- IOCs and graphs ------------------------------------------------------------------------


def doc(cve, iocs, origin="reference_page"):
    return {"cve": cve, "doc_id": f"x:{cve}", "origin": origin, "iocs": iocs, "schema": 1}


def ioc(kind, value, public=None):
    return {"type": kind, "value": value, "start": 0, "end": 1, "public": public}


def feeds():
    tf = [
        {
            "published": "2026-10-01T00:00:00",
            "metadata": {"ioc_type": "domain", "threat_type": "botnet_cc", "malware": "Fam"},
        }
    ]
    uh = [{"published": "2026-09-30T00:00:00", "metadata": {"ioc_type": "url", "threat": "x"}}]
    return tf, uh


def _threats_doc(tier="critical"):
    link = {
        "cve": "CVE-2026-0001",
        "via": "mention:reference_page",
        "evidence": [{"doc_id": "references:abc", "surface": "Akira"}],
        "tier": tier,
        "in_kev": False,
        "review": "correct",
        "counts_for_priority": True,
    }

    def fam(rank, name, cves=()):
        return {
            "rank": rank,
            "family": name,
            "categories": ["ransomware"],
            "category_source": "owner",
            "misp_categories": ["ransomware"],
            "attack": {
                "software": "S1129",
                "name": "Akira",
                "techniques": ["T1486"],
                "tactics": ["impact"],
            },
            "cves": list(cves),
            "priority_keys": {
                "linked_kev_cves": 0,
                "linked_high_tier_cves": len(cves),
                "ransomware": 1,
                "ioc_growth": 2,
                "ioc_rows": 5,
            },
            "why": ["ransomware"],
        }

    fams = [fam(i, f"Family {i}") for i in range(1, export.TOP_THREATS + 4)]
    fams[-2] = fam(export.TOP_THREATS + 2, "Linked", [link])  # below the top, but linked
    rejected = dict(link, cve="CVE-2026-0002", tier=None, review="rejected")
    fams[-1] = fam(export.TOP_THREATS + 3, "Rejected only", [rejected])  # never shown
    return {
        "snapshot_date": "2026-10-26",
        "families": fams,
        "category_rows": {"ransomware": 10, "unknown": 3},
        "kev_ransomware_cves": ["CVE-1", "CVE-2"],
        "summary": {"category_source": {"owner": 51}},
        "review": {
            "labeller": "x",
            "links": {"precision": {"all": {"n": 36, "correct": 22, "ci95": [0.45, 0.75]}}},
        },
    }


def test_build_threats_shows_top_and_linked_families_without_evidence_ids():
    out = export.build_threats(
        _threats_doc(), {"CVE-2026-0001": "critical"}, {"T1486": "Data Encrypted"}
    )
    schema.Threats.model_validate(out)
    names = [f["family"] for f in out["families"]]
    assert len(names) == export.TOP_THREATS + 1 and names[-1] == "Linked"
    [link] = out["families"][-1]["links"]
    assert link["surface"] == ["Akira"] and "evidence" not in link
    assert "references:abc" not in json.dumps(out)  # no evidence document IDs shipped
    assert out["families"][0]["techniques"] == [{"id": "T1486", "name": "Data Encrypted"}]
    assert out["kev_ransomware_cves"] == 2 and out["review"]["links_correct"] == 22
    assert out["categories"][0] == {"category": "ransomware", "ioc_rows": 10}
    assert "Rejected only" not in names
    assert out["kev"] == []  # no KEV rows passed


def test_build_threats_kev_entries_for_linked_kev_cves_only():
    doc = _threats_doc()
    kev_link = {
        "cve": "CVE-2024-0001",
        "via": "threatfox_tag",
        "evidence": [],
        "tier": None,
        "in_kev": True,
        "review": "unreviewed",
        "counts_for_priority": True,
    }
    doc["families"][0]["cves"] = [kev_link, dict(kev_link, cve="CVE-2024-0002", review="rejected")]

    def kev(cve):
        return {
            "source_id": cve,
            "title": f"{cve} Example RCE Vulnerability",
            "text": "Example product lets attackers run code via http://evil.example.com/x.",
            "metadata": {
                "vendor": "Example",
                "product": "Widget",
                "date_added": "2024-05-01",
                "due_date": "2024-05-22",
                "ransomware_use": "Known",
                "cwes": ["CWE-78"],
            },
        }

    rows = [kev("CVE-2024-0002"), kev("CVE-2024-0001"), kev("CVE-2024-9999")]
    out = export.build_threats(doc, {"CVE-2026-0001": "critical"}, {}, rows)
    schema.Threats.model_validate(out)
    [entry] = out["kev"]  # the rejected link and the unlinked KEV CVE are left out
    assert entry["cve"] == "CVE-2024-0001" and entry["families"] == ["Family 1"]
    assert entry["name"] == "CVE-2024-0001 Example RCE Vulnerability"
    assert "http://" not in entry["description"] and "evil[.]example[.]com" in entry["description"]


def test_build_threats_requires_a_hand_labelled_top():
    doc = _threats_doc()
    doc["families"][0]["category_source"] = "misp"
    with pytest.raises(ConfigError, match="must be hand-labelled"):
        export.build_threats(doc, {"CVE-2026-0001": "critical"}, {})


def test_load_threats_is_optional_and_date_checked(tmp_path):
    path = tmp_path / "threats.json"
    assert export.load_threats(path, "2026-10-26") is None
    path.write_text(json.dumps({"snapshot_date": "2026-10-25"}))
    with pytest.raises(ConfigError, match="not 2026-10-26"):
        export.load_threats(path, "2026-10-26")


def test_build_threats_refuses_stale_tiers_and_handles_not_run():
    with pytest.raises(ConfigError, match="rerun `cti threats`"):
        export.build_threats(_threats_doc(), {"CVE-2026-0001": "high"}, {})
    empty = export.build_threats(None, {}, {})
    assert empty["available"] is False and empty["families"] == []
    schema.Threats.model_validate(empty)


def test_build_iocs():
    docs = [
        doc("CVE-2026-0002", [ioc("url", "ftp://files[.]example/a"), ioc("cve", "CVE-1")]),
        doc("CVE-2026-0001", [ioc("domain", "a[.]example"), ioc("ipv4", "10.0.0[.]1", False)]),
        doc("CVE-2026-0003", [ioc("domain", "a[.]example")]),
        doc("CVE-2026-0004", [ioc("domain", "live.example")], origin="nvd_description"),
    ]
    out = export.build_iocs(docs, *feeds())
    schema.Iocs.model_validate(out)
    values = {(i["type"], i["value"]): i for i in out["indicators"]}
    assert ("url", "fxp://files[.]example/a") in values  # ftp scheme defanged on export
    assert not any(t == "cve" for t, _ in values)
    assert values[("domain", "a[.]example")]["cves"] == ["CVE-2026-0001", "CVE-2026-0003"]
    assert values[("ipv4", "10.0.0[.]1")]["public"] is False
    assert out["nvd_description_counts"] == {"domain": 1}  # counted, value not exported
    assert out["reference_pages"] == 3
    assert out["feeds"]["threatfox"]["top_families"] == [["Fam", 1]]
    assert out["feeds"]["urlhaus"]["by_month"] == {"2026-09": 1}
    with pytest.raises(ValueError, match="not defanged"):
        export.build_iocs([doc("CVE-2026-0005", [ioc("domain", "live.example")])], *feeds())


def test_shared_host_graph():
    docs = [
        doc("CVE-2026-0001", [ioc("url", "hxxps://u:p@shared[.]example:8443/a")]),
        doc("CVE-2026-0002", [ioc("domain", "shared[.]example")]),
        doc("CVE-2026-0001", [ioc("url", "hxxp://127[.]0[.]0[.]1/x")]),
        doc("CVE-2026-0002", [ioc("url", "hxxp://127[.]0[.]0[.]1/y")]),
        doc("CVE-2026-0003", [ioc("domain", "lonely[.]example")]),
        doc("CVE-2026-0003", [ioc("domain", "cve[.]org")]),  # registry: excluded
        doc("CVE-2026-0004", [ioc("domain", "www[.]cve[.]org")]),
        doc("CVE-2026-0005", [ioc("domain", "www[.]cve[.]org")]),
    ]
    g = export.shared_host_graph(docs, {"CVE-2026-0001": "critical"}, {"CVE-2026-0002"})
    schema.Graph.model_validate(g)
    hosts = {n["id"]: n for n in g["nodes"] if n["kind"] == "host"}
    assert set(hosts) == {"shared[.]example"}  # userinfo/port stripped, local IP dropped
    assert hosts["shared[.]example"]["count"] == 2
    cves = {n["id"]: (n.get("tier"), n["in_kev"]) for n in g["nodes"] if n["kind"] == "cve"}
    assert cves == {"CVE-2026-0001": ("critical", False), "CVE-2026-0002": (None, True)}


def test_weakness_and_attack_graphs():
    from cti.nlp.attack_catalog import Technique

    rows = [
        {"cve": "CVE-2026-0001", "tier": "critical"},
        {"cve": "CVE-2026-0002", "tier": "elevated"},
        {"cve": "CVE-2026-0003", "tier": "high"},
    ]
    xss = {"id": "CWE-79", "kind": "weakness", "name": "XSS", "pillar": "CWE-707"}
    sqli = {"id": "CWE-89", "kind": "weakness", "name": "SQLi", "pillar": "CWE-707"}
    pillar = {"id": "CWE-707", "kind": "weakness", "name": "Neutralization", "pillar": "CWE-707"}
    slim = {
        "CVE-2026-0001": {"context_snapshot": {"cwes": [xss, sqli]}},  # two CWEs, one pillar
        "CVE-2026-0002": {"context_snapshot": {"cwes": [xss]}},
        "CVE-2026-0003": {"context_snapshot": {"cwes": [pillar]}},  # labelled with the pillar
    }
    g = export.weakness_graph(rows, slim, {"CWE-707": "Improper Neutralization"})
    count = {n["id"]: n["count"] for n in g["nodes"] if n["kind"] != "cve"}
    assert count == {"CWE-707": 2, "CWE-79": 1, "CWE-89": 1}  # distinct CVEs, not pairs
    assert "CVE-2026-0002" not in {n["id"] for n in g["nodes"]}  # elevated tier left out
    assert {(e["source"], e["target"], e["weight"]) for e in g["edges"]} == {
        ("CWE-707", "CWE-79", 1),
        ("CWE-707", "CWE-89", 1),
        ("CWE-79", "CVE-2026-0001", 1),
        ("CWE-89", "CVE-2026-0001", 1),
        ("CWE-707", "CVE-2026-0003", 1),
    }
    ctid = [
        {"cve": "CVE-2024-0001", "type": "exploitation_technique", "technique": "T1190"},
        {"cve": "CVE-2024-0001", "type": "exploitation_technique", "technique": "T9999.001"},
    ]
    techniques = [Technique("T1190", "Exploit Public-Facing Application", ("initial-access",), "")]
    graphs = export.attack_graphs(ctid, {"T9999.001": "T1190.002"}, techniques)
    g = graphs["exploitation_technique"]
    tech = [n for n in g["nodes"] if n["kind"] == "technique"]
    assert [(t["id"], t["count"]) for t in tech] == [("T1190", 1)]  # remapped, rolled up, once
    assert {"id": "initial-access", "label": "Initial Access", "kind": "tactic", "count": 1} in [
        {k: n.get(k) for k in ("id", "label", "kind", "count")} for n in g["nodes"]
    ]


# ---- eval, validation, writing ------------------------------------------------------------------


def test_build_eval_copies_by_key_path():
    fold = {k: 1 for k in export.RISK_FOLD}
    method = {"pooled": {k: 1 for k in export.RISK_POOLED}, "per_fold": {"cutoff": fold}}
    metric = {k: 0.5 for k in export.ATTACK_METRICS}
    results = {
        "risk": {
            "headline": "h",
            "decision": {"verdict": "v"},
            "secondary_paired": {},
            "random_expected": {},
            "folds": {"cutoff": {"cutoff": "2026-04-29", "window_end": "2026-10-23"}},
            "tiers_logistic": {"tiers": {}},
            "methods": {"logistic": {**method, "ignored": 9}},
        },
        "attack": {
            "primary": {},
            "splits": {},
            "results": {"test": {"nvd": {"tfidf": {"exploitation_technique": metric}}}},
        },
        "cwe": {
            "headline": "h",
            "classes": {"known": 118},
            "test": {"tfidf": {"all": {k: 0.1 for k in export.CWE_METRICS}}},
        },
        "extract": {"review": {"overall": {}, "per_type": {}, "per_origin": {}}},
        "ner": {"model": {}, "text_derived_spans": {"exact": {}, "overlap": {}}},
    }
    out = export.build_eval(results)
    assert out["risk"]["methods"]["logistic"]["pooled"] == method["pooled"]
    assert "ignored" not in out["risk"]["methods"]["logistic"]
    assert out["attack"]["test_nvd"]["tfidf"]["exploitation_technique"] == metric
    assert out["cwe"]["classes"] == 118 and set(out["ner"]) == {"model", "exact", "overlap"}
    del results["ner"]["text_derived_spans"]["exact"]
    with pytest.raises(KeyError, match="text_derived_spans/exact"):
        export.build_eval(results)


def test_disclosures_are_derived():
    folds = {
        "a": {"cutoff": "2025-05-04", "window_end": "2025-10-31"},
        "b": {"cutoff": "2026-04-29", "window_end": "2026-10-23"},
    }
    versions = {"cutoff4": ["v1"], "cutoff": ["v2"], "snapshot": ["v3"]}
    text = " ".join(export.disclosures(versions, 88 / 262612, folds, 5, 10, -0.5725))
    assert "0.034% prevalence" in text and "2025-05-04 to 2026-10-23" in text
    assert "v3" in text and "v1 and v2" in text and "5 of the 10 tiered" in text and "-0.57" in text
    assert risk_config.NVD_WINDOW_START in text


def test_pick_names_the_missing_path():
    assert export.pick({"a": {"b": 1}}, "a", "b") == 1
    with pytest.raises(KeyError, match="a/c"):
        export.pick({"a": {"b": 1}}, "a", "c")


def test_validate_rejects_unknown_fields_and_missing_files():
    with pytest.raises(ValueError, match="export files"):
        export.validate({"meta.json": {}})
    good = schema.GraphNode(id="x", label="x", kind="cve").model_dump()
    with pytest.raises(ValueError, match="extra"):
        schema.GraphNode.model_validate({**good, "surprise": 1})


def test_write_is_deterministic(tmp_path):
    files = {"b.json": {"z": 1, "a": [2, 1]}, "a.json": {"k": "é"}}
    export.write(tmp_path / "one", files)
    export.write(tmp_path / "two", dict(reversed(files.items())))
    for name in files:
        assert (tmp_path / "one" / name).read_bytes() == (tmp_path / "two" / name).read_bytes()
    assert json.loads((tmp_path / "one" / "b.json").read_text()) == files["b.json"]


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_git_state_sees_changes_under_src(tmp_path):
    def git(*args):
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

    pkg = tmp_path / "src" / "cti"
    pkg.mkdir(parents=True)
    (pkg / "mod.py").write_text("x = 1\n")
    git("init", "-q")
    git("-c", "user.email=t@example.com", "-c", "user.name=t", "add", ".")
    git("-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-qm", "init")
    assert _git_state(pkg)["dirty"] is False
    (pkg / "mod.py").write_text("x = 2\n")
    assert _git_state(pkg)["dirty"] is True  # the pathspec is anchored at the repo root
