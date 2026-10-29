import numpy as np
import pytest

pytest.importorskip("sklearn")

from cti.nlp import attack2_config as cfg
from cti.nlp import attack_eval2 as ae2
from cti.nlp.attack_data import NvdRecord
from cti.nlp.attack_eval import log_prior

PARENTS = ["T1068", "T1078", "T1189", "T1190", "T1204"]
PT = cfg.PRIMARY_TYPE


def _gold(labels):
    return {c: {PT: set(ts)} for c, ts in labels.items()}


def _sig(cves, informative=None):
    """Bi-encoder signal that points at ``informative[c]`` (else zeros)."""
    n, p = len(cves), len(PARENTS)
    bi = np.zeros((n, p))
    for i, c in enumerate(cves):
        if informative and c in informative:
            bi[i, PARENTS.index(informative[c])] = 1.0
    z = np.zeros((n, p))
    return ae2.Signals(list(cves), bi, z.copy(), z.copy(), z.copy(), z.copy())


def test_prior_rows_leave_one_out_for_training_cves():
    gold = _gold({"a": ["T1190"], "b": ["T1190"], "t": ["T1068"]})
    rows = ae2.prior_rows(gold, ["a", "b"], ["a", "t"], PARENTS, PT)
    from collections import Counter

    full = log_prior(Counter({"T1190": 2}), PARENTS)
    assert np.allclose(rows[1], full)  # test CVE: full training prior
    assert np.allclose(rows[0], log_prior(Counter({"T1190": 2}), PARENTS, {"T1190"}))


def test_folds_partition_and_are_seeded():
    cves = [f"c{i}" for i in range(23)]
    parts = ae2.folds(cves)
    assert len(parts) == cfg.CV_FOLDS and sorted(c for part in parts for c in part) == sorted(cves)
    assert parts == ae2.folds(cves)


def test_build_signals_capec_cvss_and_replay():
    records = {
        "c": NvdRecord(
            "c",
            "x",
            ("CWE-79",),
            {"family": "v3", "vector": {"AV": "N", "UI": "N", "PR": "N"}, "flags": {}},
        )
    }
    z = np.zeros((1, len(PARENTS)))
    sig = ae2.build_signals(
        ["c"], records, PARENTS, z, z, {"CWE-79": {"CAPEC-1"}}, {"CAPEC-1": {"T1189"}}
    )
    col = PARENTS.index
    assert sig.capec[0, col("T1189")] == pytest.approx(np.log1p(1))
    assert sig.cvss[0, col("T1190")] == 1 and sig.cvss[0].sum() == 1
    # replay: 2 x CWE table (CWE-79 -> T1189, T1204) + CVSS rule (T1190)
    assert sig.replay[0, col("T1189")] == 2 and sig.replay[0, col("T1190")] == 1


def _world(n_train=40, n_test=20):
    rng = np.random.default_rng(0)
    labels, informative = {}, {}
    for i in range(n_train + n_test):
        c = f"{'tr' if i < n_train else 'te'}{i}"
        p = PARENTS[rng.integers(0, len(PARENTS))]
        labels[c] = [p]
        informative[c] = p  # the bi-encoder signal is perfect
    gold = _gold(labels)
    train = [c for c in labels if c.startswith("tr")]
    test = [c for c in labels if c.startswith("te")]
    return gold, _sig(train, informative), _sig(test, informative)


def test_combiner_and_baseline_learn_a_perfect_signal():
    gold, train_sig, test_sig = _world()
    sel = ae2.select(train_sig, gold, train_sig.cves, PARENTS, PT, "C")
    assert sel["value"] in cfg.COMBINER_C and set(sel["cv_hit@5"]) == {
        str(c) for c in cfg.COMBINER_C
    }
    chosen = {"beta": 0.0, "combiner": sel["value"], **dict.fromkeys(cfg.ABLATIONS, 1.0)}
    ranked = ae2.rank_all(train_sig, test_sig, gold, PARENTS, PT, chosen)
    assert set(ranked) == {
        "majority",
        "prior+biencoder",
        "capec-chain",
        "methodology-replay",
        "combiner",
        *cfg.ABLATIONS,
    }
    assert ae2.score(ranked["combiner"], gold, PT)["hit@1"]["value"] == 1.0
    assert ae2.score(ranked["prior+biencoder"], gold, PT)["hit@1"]["value"] == 1.0


def test_replay_only_for_the_primary_type():
    gold, train_sig, test_sig = _world()
    for c in gold:
        gold[c]["primary_impact"] = set(gold[c][PT])
    chosen = {"beta": 0.0, "combiner": 1.0, **dict.fromkeys(cfg.ABLATIONS, 1.0)}
    ranked = ae2.rank_all(train_sig, test_sig, gold, PARENTS, "primary_impact", chosen)
    assert "methodology-replay" not in ranked


def test_evaluate_end_to_end_reports_every_preregistered_section():
    gold, train_sig, test_sig = _world()
    for c in gold:
        gold[c]["primary_impact"] = {"T1068"}
        gold[c]["secondary_impact"] = {"T1078"}
    families = {c: ("v2" if i % 2 else "v3") for i, c in enumerate(gold)}
    max_cos = {c: (0.95 if i % 5 == 0 else 0.5) for i, c in enumerate(test_sig.cves)}
    raw = {c: {"T1204.001"} for c in test_sig.cves if PT in gold[c] and "T1204" in gold[c][PT]}
    out = ae2.evaluate(train_sig, test_sig, gold, PARENTS, raw, families, max_cos)
    assert set(out) >= {
        "decision",
        "headline_vs_baseline",
        "results",
        "selection",
        "per_technique",
        "by_cvss_family",
        "below_near_duplicate",
        "subtechnique",
        "post_hoc_sensitivity",
        "train_feasibility",
    }
    assert out["decision"]["metric"] == "hit@5" and "combiner_better" in out["decision"]
    assert set(out["results"]) == {PT, *cfg.SECONDARY_TYPES}
    assert out["below_near_duplicate"]["excluded"] == 4
    assert out["train_feasibility"]["graded_cves_per_type"][PT] == len(train_sig.cves)


def test_rankings_by_is_exact_lexicographic():
    primary = np.array([[0.0, 0.69, 0.69, 0.0, 0.0]])
    tiebreak = np.array([[-1.0, -9.0, -2.0, -0.5, -0.5]])  # prior-like, any magnitude
    [order] = ae2._rankings_by(["c"], PARENTS, primary, tiebreak).values()
    # primary first; within ties the higher tiebreak; then parent ID
    assert order == ["T1189", "T1078", "T1190", "T1204", "T1068"]


def test_subtechnique_report_handles_an_empty_group():
    gold = _gold({"c": ["T1204"]})
    ranked = {m: {"c": PARENTS} for m in (cfg.HEADLINE, cfg.BASELINE)}
    out = ae2._subtechnique(ranked, gold, {"c": {"T1204.001"}, "gone": {"T1204.002"}})
    assert out["T1204.002"] == {"cves": 0}
    assert out["T1204.001"]["cves"] == 1 and out["T1204.001"][cfg.HEADLINE] == 1.0
