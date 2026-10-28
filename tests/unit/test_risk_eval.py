import math

import pytest

np = pytest.importorskip("numpy")
pytest.importorskip("sklearn")

from cti.cli import main  # noqa: E402
from cti.nlp import risk_config, risk_eval  # noqa: E402

DATES = {
    "cutoff4": "2024-11-05",
    "cutoff3": "2025-05-04",
    "cutoff2": "2025-10-31",
    "cutoff": "2026-04-29",
    "snapshot": "2026-10-26",
}


def record(cve, *, kev=None, published="2024-02-01", signals=None, cna=None):
    eligible = {
        label: published <= day and not (kev is not None and kev <= day)
        for label, day in DATES.items()
    }
    return {
        "cve": cve,
        "published": f"{published}T10:00:00",
        "signals": signals or {},
        "eligible": eligible,
        "kev": {"date_added": kev, "ransomware_use": "Unknown"} if kev else None,
        "context_snapshot": {"cvss_cna": {"base_score": cna} if cna is not None else None},
    }


def epss(p, day="2024-11-05"):
    return {"epss": p, "percentile": p, "model_version": "v", "score_date": f"{day}T00:00:00Z"}


def test_hits_at_k_gives_ties_fractional_credit():
    scores = np.array([0.9, 0.5, 0.5, 0.5, 0.5, 0.1])
    y = np.array([0, 1, 0, 0, 0, 1], dtype=bool)
    # one CVE above; 2 of the 4 tied slots fit in k = 3; 1 of the 4 tied is a positive
    assert risk_eval.hits_at_k(scores, y, 3) == pytest.approx(0.5)
    assert risk_eval.hits_at_k(scores, y, 1) == 0.0
    assert risk_eval.hits_at_k(scores, y, 10) == 2.0
    # the result doesn't depend on the order of the tied CVEs
    assert risk_eval.hits_at_k(scores[::-1], y[::-1], 3) == pytest.approx(0.5)


def test_wilson_interval():
    lo, hi = risk_eval.wilson(20, 68)
    assert (lo, hi) == (0.1992, 0.4111)  # p = 0.294, n = 68, checked by hand
    assert risk_eval.wilson(0, 0) == (0.0, 0.0)


def test_label_windows_and_kev_last_date():
    records = [
        record("CVE-2024-0001", kev="2025-05-04"),  # last day of the cutoff4 window: in
        record("CVE-2024-0002", kev="2025-05-05"),  # first day after: next window
        record("CVE-2024-0003", kev="2026-10-24"),  # after the KEV catalog's last date
        record("CVE-2024-0004"),
    ]
    w = risk_eval.build_windows(records, DATES)
    label = {f: dict(zip(w[f].cves, w[f].y, strict=True)) for f in w}
    assert label["cutoff4"]["CVE-2024-0001"]
    assert not label["cutoff4"]["CVE-2024-0002"] and label["cutoff3"]["CVE-2024-0002"]
    assert "CVE-2024-0001" not in label["cutoff3"]  # in KEV by then: not eligible
    assert not label["cutoff"]["CVE-2024-0003"]  # past 2026-10-23: not a positive
    assert risk_eval.window_end("2026-04-29") == risk_config.KEV_LAST_DATE


def test_cutoff_spacing_is_checked():
    with pytest.raises(ValueError, match="expected"):
        risk_eval.build_windows([], {**DATES, "cutoff3": "2025-05-03"})


def test_features_missing_values_and_point_in_time_only():
    rec = record(
        "CVE-2024-0001",
        published="2024-01-01",
        signals={
            "cutoff": {"metasploit": {"module_count": 1}},
            "snapshot": {"epss": epss(0.9, "2026-10-26"), "nuclei": {}},  # never read
        },
        cna=9.8,
    )
    x, detail = risk_eval.featurize(rec, "cutoff", DATES["cutoff"])
    f = dict(zip(risk_eval.FEATURES, x, strict=True))
    assert math.isnan(f["epss_logit"]) and f["epss_missing"] == 1.0  # missing, not 0
    assert math.isnan(f["ssvc_exploitation"]) and f["ssvc_missing"] == 1.0
    assert (f["metasploit"], f["nuclei"], f["exploitdb"]) == (1.0, 0.0, 0.0)  # absence = 0
    assert f["log_age_days"] == pytest.approx(math.log1p(risk_config.AGE_CAP_DAYS))  # capped
    assert detail["exploit_sources"] == ["metasploit"]


def test_epss_logit_and_ssvc_coding():
    rec = record(
        "CVE-2024-0001",
        signals={
            "cutoff4": {
                "epss": epss(1.0),
                "vulnrichment": {
                    "exploitation": "poc",
                    "automatable": "yes",
                    "technical_impact": "partial",
                    "decided_at": "2024-10-01T00:00:00Z",
                },
            }
        },
    )
    x, _ = risk_eval.featurize(rec, "cutoff4", DATES["cutoff4"])
    f = dict(zip(risk_eval.FEATURES, x, strict=True))
    hi = risk_config.EPSS_CLIP[1]
    assert f["epss_logit"] == pytest.approx(math.log(hi / (1 - hi)))  # clipped, finite
    assert (f["ssvc_exploitation"], f["ssvc_automatable"], f["ssvc_total_impact"]) == (1, 1, 0)


def test_signals_dated_after_the_cutoff_are_refused():
    rec = record("CVE-2024-0001", signals={"cutoff4": {"epss": epss(0.5, "2024-11-06")}})
    with pytest.raises(ValueError, match="after cutoff4"):
        risk_eval.featurize(rec, "cutoff4", DATES["cutoff4"])


def synthetic_records(n=600, seed=0):
    """Higher EPSS -> more likely added to KEV in the next window."""
    rng = np.random.default_rng(seed)
    kev_days = {
        "cutoff4": "2025-02-01",
        "cutoff3": "2025-08-01",
        "cutoff2": "2026-02-01",
        "cutoff": "2026-08-01",
    }
    out = []
    for i in range(n):
        p = float(rng.uniform(0.0001, 0.9))
        window = list(kev_days)[i % 4]
        kev = kev_days[window] if rng.uniform() < p**2 * 0.3 else None
        signals = {
            label: {
                "epss": epss(p, day),
                "vulnrichment": {"exploitation": "poc" if p > 0.5 else "none"},
            }
            for label, day in DATES.items()
            if label != "snapshot"
        }
        out.append(record(f"CVE-2024-{i + 1000}", kev=kev, signals=signals, cna=5.0))
    return out


def test_run_end_to_end(monkeypatch):
    monkeypatch.setattr(risk_config, "N_BOOT", 20)
    windows = risk_eval.build_windows(synthetic_records(), DATES)
    assert all(windows[f].y.sum() > 0 for f in risk_config.FOLDS)
    rng = np.random.default_rng(1)
    vec = {c: rng.normal(size=16).astype(np.float32) for w in windows.values() for c in w.cves}

    def vectors(cves):
        return np.stack([vec[c] for c in cves])

    kev_language = {windows["cutoff"].cves[0]}
    result = risk_eval.run(windows, vectors, kev_language, log=lambda _: None)

    assert set(result["methods"]) == {"logistic", "boosting", "epss", "ssvc_rule", "cvss_cna"}
    lr = result["methods"]["logistic"]["pooled"]
    assert lr["positives"] == sum(int(windows[f].y.sum()) for f in risk_config.FOLDS)
    assert result["decision"]["verdict"] in (
        "logistic better",
        "EPSS better",
        "no detectable difference",
    )
    assert set(result["ablations"]) == set(risk_config.ABLATIONS)
    assert result["ablations"]["text_no_kev_language"]["dropped_cves"]["cutoff"] == 1
    assert sum(t["cves"] for t in result["tiers_logistic"]["tiers"].values()) == sum(
        len(windows[f].y) for f in risk_config.FOLDS
    )
    assert len(result["positives"]) == lr["positives"]
    assert result["folds"]["cutoff"]["train_windows"] == ["cutoff4", "cutoff3", "cutoff2"]


def test_cli_risk_eval_needs_inputs(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTI_DATA_DIR", str(tmp_path))
    assert main(["risk-eval", "--date", "2026-10-26"]) == 2
    assert "run `cti enrich` and `cti embed` first" in capsys.readouterr().err


def test_ssvc_rule_and_cvss_baselines_order_and_missing_last():
    sig = {
        "a": {"epss": epss(0.1), "vulnrichment": {"exploitation": "active"}},
        "b": {"epss": epss(0.9), "vulnrichment": {"exploitation": "poc"}},
        "c": {"epss": epss(0.2), "vulnrichment": {"exploitation": "poc"}},
        "d": {"epss": epss(0.99)},  # no SSVC
        "e": {"vulnrichment": {"exploitation": "none"}},  # no EPSS
    }
    records = [
        record(f"CVE-2024-000{i}", signals={"cutoff4": s}, cna=(None if i == 1 else 5.0 + i))
        for i, s in enumerate(sig.values(), start=1)
    ]
    w = risk_eval.build_windows(records, DATES)["cutoff4"]
    order = [w.cves[i] for i in np.argsort(-w.ssvc_rule, kind="stable")]
    assert order == [f"CVE-2024-000{i}" for i in (1, 2, 3, 5, 4)]
    assert np.isneginf(w.epss[4]) and np.isneginf(w.cvss_cna[0])


def test_tiers_use_rank_fractions():
    scores = {"cutoff": np.arange(2000, 0, -1, dtype=float)}
    y = {"cutoff": np.zeros(2000, dtype=bool)}
    y["cutoff"][[0, 5, 30, 500]] = True
    t = risk_eval.tiers(scores, y)["tiers"]
    assert [t[n]["cves"] for n in ("critical", "high", "elevated", "baseline")] == [2, 18, 80, 1900]
    assert [t[n]["kev_positives"] for n in ("critical", "high", "elevated", "baseline")] == [
        1,
        1,
        1,
        1,
    ]


def test_bootstrap_is_deterministic_and_stratified(monkeypatch):
    monkeypatch.setattr(risk_config, "N_BOOT", 50)
    rng = np.random.default_rng(3)
    y = {"cutoff": rng.uniform(size=500) < 0.05}
    a = {"cutoff": rng.uniform(size=500) + y["cutoff"]}
    b = {"cutoff": rng.uniform(size=500)}
    one = risk_eval.paired_bootstrap(a, b, y, lambda _: 20)
    assert one == risk_eval.paired_bootstrap(a, b, y, lambda _: 20)
    assert one["difference_hits"] > 0 and one["excludes_zero"]
