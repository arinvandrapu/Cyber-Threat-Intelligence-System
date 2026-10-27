import pytest

np = pytest.importorskip("numpy")  # the ml extra
pytest.importorskip("sklearn")

from cti.cli import main  # noqa: E402
from cti.enrich.cwe import CweEntry  # noqa: E402
from cti.gold import GoldEntity, GoldRecord  # noqa: E402
from cti.nlp import cwe_config, cwe_eval  # noqa: E402

CATALOG = {
    "CWE-79": CweEntry(
        "Improper Neutralization of Input During Web Page Generation", "weakness", usage="Allowed"
    ),
    "CWE-89": CweEntry("SQL Injection", "weakness", usage="Allowed"),
    "CWE-862": CweEntry("Missing Authorization", "weakness", usage="Allowed"),
    "CWE-20": CweEntry("Improper Input Validation", "weakness", usage="Discouraged"),
    "CWE-264": CweEntry("Permissions", "category", usage="Prohibited"),
    "CWE-120": CweEntry(
        "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
        "weakness",
        usage="Allowed",
    ),
}


def assign(*pairs):
    return [{"source_kind": k, "type": "Secondary", "id": i} for k, i in pairs]


def test_split_mask_and_name_rules():
    assert cwe_eval.split_of("2025-12-31T23:00:00") == "train"
    assert cwe_eval.split_of("2026-04-29T10:00:00") == "dev"
    assert cwe_eval.split_of("2026-04-30T00:00:00") == "test"
    assert cwe_eval.mask_ids("see cwe-79 and CWE-1321.") == "see CWE-[id] and CWE-[id]."
    assert cwe_eval.name_in_text("A missing authorization flaw", ["CWE-862"], CATALOG)
    # the part before " (" counts, so the parenthesised alias isn't required
    assert cwe_eval.name_in_text(
        "buffer copy without checking size of input in x", ["CWE-120"], CATALOG
    )
    assert not cwe_eval.name_in_text("an XSS bug", ["CWE-79"], CATALOG)


def test_choose_label_follows_the_chain_and_skips_prohibited_and_noinfo():
    a = assign(
        ("nvd", "NVD-CWE-noinfo"), ("nvd", "CWE-264"), ("cna", "CWE-89"), ("cisa_adp", "CWE-79")
    )
    assert cwe_eval.choose_label(a, CATALOG) == ("cna", {"CWE-89"})
    a = assign(("nvd", "CWE-79"), ("cna", "CWE-89"))
    assert cwe_eval.choose_label(a, CATALOG) == ("nvd", {"CWE-79"})
    assert cwe_eval.choose_label(assign(("other_adp", "CWE-79")), CATALOG) == ("", set())


def example(cve, split, label, text="t", name=False):
    return cwe_eval.Example(cve, split, (label,), "cna", "a@x", text, text, False, name)


def test_known_classes_and_other(monkeypatch):
    monkeypatch.setattr(cwe_config, "MIN_TRAIN_EXAMPLES", 2)
    rows = [example(f"C{i}", "train", "CWE-79") for i in range(2)]
    rows += [example("C9", "train", "CWE-89"), example("D1", "dev", "CWE-89")]
    known = cwe_eval.known_classes(rows)
    assert known == ["CWE-79"]  # CWE-89 has 1 train example; dev doesn't count
    assert cwe_eval.target(rows[2], set(known)) == cwe_config.OTHER


def test_macro_f1_matches_sklearn_and_excludes_other():
    from sklearn.metrics import f1_score

    rng = np.random.default_rng(0)
    y, p = rng.integers(0, 6, 500), rng.integers(0, 6, 500)
    n_known = 5  # code 5 = OTHER
    present = sorted(set(y[y < n_known]))
    expected = f1_score(y, p, labels=present, average="macro", zero_division=0)
    assert cwe_eval._macro_f1(y, p, n_known) == pytest.approx(expected)


def test_evaluate_scores_top_k():
    scores = np.array([[0.9, 0.1, 0.0], [0.2, 0.3, 0.5], [0.1, 0.7, 0.2]])
    out = cwe_eval.evaluate_scores(scores, np.array([0, 0, 1]), n_known=2)
    assert out["accuracy"] == round(2 / 3, 4) and out["top3"] == 1.0 and out["n"] == 3


def test_centroid_scores_are_cosine_to_class_means():
    x = np.array([[1.0, 0.0], [1.0, 0.0], [0.0, 1.0]])
    s = cwe_eval.centroid_scores(x, np.array([0, 0, 1]), np.array([[0.0, 1.0]]), n_classes=3)
    assert s[0].argmax() == 1 and s[0, 2] == -np.inf  # class 2 never seen


def test_run_end_to_end(monkeypatch):
    monkeypatch.setattr(cwe_config, "MIN_TRAIN_EXAMPLES", 2)
    monkeypatch.setattr(cwe_config, "N_BOOT", 20)
    words = {"CWE-79": "script injection in page", "CWE-89": "sql query injection"}
    rows = []
    for split, n in (("train", 6), ("dev", 3), ("test", 3)):
        for label, text in words.items():
            rows += [example(f"{split}-{label}-{i}", split, label, f"{text} {i}") for i in range(n)]
    rows.append(
        cwe_eval.Example(
            "test-multi",
            "test",
            ("CWE-79", "CWE-89"),
            "nvd",
            "b@x",
            "sql page",
            "sql page",
            False,
            False,
        )
    )
    vec = {r.cve: np.array([1.0, 0.0]) if "79" in r.cve else np.array([0.0, 1.0]) for r in rows}

    def vectors(cves, masked):
        return np.array([vec[c] for c in cves])

    result = cwe_eval.run(rows, vectors, CATALOG, log=lambda m: None)
    assert result["classes"]["known"] == 2
    assert result["test"]["tfidf"]["name_absent"]["macro_f1"] == 1.0
    assert result["test"]["embedding"]["all"]["accuracy"] == 1.0
    assert result["chosen_c"]["tfidf"] in cwe_config.TFIDF.c_grid
    assert result["secondary"]["multi_label_pool_any_in_top5"]["n"] == 1
    assert set(result["label_facts"]) == {"train", "dev", "test"}


def test_gold_check_reports_the_circular_baseline(monkeypatch):
    monkeypatch.setattr(cwe_config, "GOLD_FOLDS", 2)
    recs = [
        GoldRecord(
            id=f"{src}:{i}",
            source=src,
            title="t",
            text=f"{word} report {i}",
            labels=[lab],
            primary_label=lab,
            label_signals=[],
            entities=[GoldEntity(type="x", value="y", start=0, end=1, derivation="regex")],
        )
        for src, lab, word in (("threatfox", "ioc", "botnet"), ("phishtank", "phishing", "login"))
        for i in range(4)
    ]
    out = cwe_eval.gold_check(recs)
    assert out["accuracy"]["source_only"] == 1.0
    assert out["primary_label_equals_source_share"] == 1.0
    assert "circular" in out["note"]


def test_cli_cwe_eval_needs_inputs(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTI_DATA_DIR", str(tmp_path))
    assert main(["cwe-eval", "--date", "2026-10-26"]) == 2
    assert "cti embed --cwe-id-masked" in capsys.readouterr().err
