"""SecureBERT stages without torch: span grouping, linking, gold scoring, and the CLI
wiring are tested with fake taggers and encoders; the models themselves are not loaded."""

import hashlib

import pytest

np = pytest.importorskip("numpy")

from cti.cli import main  # noqa: E402
from cti.gold import GoldEntity, GoldRecord  # noqa: E402
from cti.nlp import models, semantic  # noqa: E402
from cti.nlp.aliases import build_index  # noqa: E402
from cti.nlp.ner import Entity, group, inert  # noqa: E402

from .conftest import gzip_bytes, jsonl  # noqa: E402


def tokens(text, tagged):
    """[(substring, tag)] -> (start, end, tag, prob) using the substrings' positions,
    with byte-level-BPE-style leading spaces included in the offsets."""
    out, pos = [], 0
    for piece, tag in tagged:
        start = text.index(piece, pos)
        out.append((start, start + len(piece), tag, 0.9))
        pos = start + len(piece)
    return out


def test_group_merges_bpe_fragments_and_snaps_to_words():
    text = "used X-Agent against Microsoft Exchange servers, via CVE-2024-21413 -"
    toks = tokens(
        text,
        [
            (" X", "B-Malware"),
            ("-", "B-Malware"),
            ("Agent", "B-Malware"),
            (" against", "O"),
            (" Microsoft", "B-System"),
            (" Exchange", "I-System"),
            (" servers,", "I-System"),
            (" via", "O"),
            (" C", "B-Indicator"),
            ("VE", "B-Indicator"),
            ("-2024", "B-Indicator"),
            ("-214", "B-Vulnerability"),
            ("13", "B-Indicator"),
            (" -", "B-Indicator"),  # a separate word: starts with a space
        ],
    )
    got = [(e.label, text[e.start : e.end]) for e in group(text, toks)]
    assert got == [
        ("Malware", "X-Agent"),
        ("System", "Microsoft Exchange servers"),
        ("Indicator", "CVE-2024-21413"),  # mixed labels in one word: the majority wins
    ]


def test_group_starts_a_new_entity_on_b_tag_after_a_space():
    text = "CISA FBI"
    toks = tokens(text, [("CISA", "B-Organization"), (" FBI", "B-Organization")])
    assert [text[e.start : e.end] for e in group(text, toks)] == ["CISA", "FBI"]


def test_keep_best_prefers_the_window_where_a_token_is_central():
    from cti.nlp.ner import keep_best

    best: dict = {}
    # window 1 covers tokens a..d; window 2 overlaps on c, d and continues to f
    w1 = [(0, 0), (0, 1), (2, 3), (4, 5), (6, 7), (0, 0)]  # [CLS] a b c d [SEP]
    w2 = [(0, 0), (4, 5), (6, 7), (8, 9), (10, 11), (0, 0)]  # [CLS] c d e f [SEP]
    keep_best(best, w1, ["O", "O", "O", "B-X", "B-X", "O"], [1, 1, 1, 0.1, 0.2, 1])
    keep_best(best, w2, ["O", "B-Y", "I-Y", "O", "O", "O"], [1, 0.3, 0.4, 1, 1, 1])
    # c: margin 1 in w1, 0 in w2 -> w1; d: margin 0 in w1 (its last), 1 in w2 -> w2
    assert best[(4, 5)] == (1, "B-X", 0.1)
    assert best[(6, 7)] == (1, "I-Y", 0.4)
    assert sorted(best) == [(0, 1), (2, 3), (4, 5), (6, 7), (8, 9), (10, 11)]


def test_entity_text_is_defanged():
    assert inert("contacting evil.example.com via https://x.io") == (
        "contacting evil[.]example[.]com via hxxps[:]//x[.]io"
    )


@pytest.fixture
def index():
    groups = [
        {
            "source_id": "G0007",
            "title": "APT28",
            "metadata": {"stix_type": "intrusion-set", "aliases": ["APT28"]},
        },
        {
            "source_id": "S0023",
            "title": "CHOPSTICK",
            "metadata": {"stix_type": "malware", "aliases": ["CHOPSTICK", "X-Agent"]},
        },
    ]
    return build_index(groups, [])


def test_link_resolves_whole_span_or_names_inside(index):
    assert semantic.link("APT28", index) == ["G0007"]
    assert semantic.link("X-Agent malware", index) == ["S0023"]
    assert semantic.link("Contoso", index) == []


def test_link_never_resolves_stoplisted_words():
    from cti.nlp.aliases import build_index

    tf = [{"metadata": {"malware": "Payload", "malware_alias": "None"}}]
    index = build_index([], tf)
    assert [e.id for e in index.lookup("payload")] == ["threatfox:Payload"]  # lookup still does
    assert semantic.link("payload", index) == []


def test_kev_language_flag():
    assert semantic.KEV_LANGUAGE.search("This vulnerability has been exploited in the wild.")
    assert semantic.KEV_LANGUAGE.search(
        "Apple is aware of a report that this issue may have been exploited"
    )
    assert not semantic.KEV_LANGUAGE.search("An attacker could exploit this to run code.")


class FakeTagger:
    spec = models.NER

    def __init__(self, entities):
        self.entities = entities

    def tag(self, texts, progress=None):
        return [self.entities.get(t, []) for t in texts]


def test_ner_gold_eval_scores_labelled_sources_only():
    text = "APT28 used X-Agent against Contoso."
    rec = GoldRecord(
        id="r",
        source="mitre_attack",
        title="t",
        text=text,
        labels=["x"],
        primary_label="x",
        label_signals=[],
        entities=[
            GoldEntity(type="malware", value="X-Agent", start=11, end=18, derivation="regex")
        ],
    )
    tagger = FakeTagger(
        {
            text: [
                Entity("Malware", 11, 26, "X-Agent against", 0.9),  # overlaps, not exact
                Entity("Organization", 27, 34, "Contoso", 0.9),  # no Organization gold here
            ]
        }
    )
    result = semantic.ner_gold_eval([rec], tagger)
    assert result["scored_sources"] == {"Malware": ["mitre_attack"]}
    assert result["overlap"]["Malware"]["recall"] == 1.0
    assert result["exact"]["Malware"]["recall"] == 0.0
    assert "Organization" not in result["overlap"]


def test_build_entities_links_and_defangs(tmp_path, index):
    page = "APT28 contacted evil.example.com"
    refs = [
        {"id": "references:a", "cve": "CVE-2024-1", "in_corpus": True, "text": page},
        {"id": "references:b", "cve": "CVE-2024-1", "in_corpus": False, "text": "skip"},
    ]
    (tmp_path / "references.jsonl.gz").write_bytes(gzip_bytes(jsonl(refs)))
    tagger = FakeTagger(
        {
            page: [
                Entity("Organization", 0, 5, "APT28", 0.9),
                Entity("Indicator", 16, 32, inert(page[16:32]), 0.9),
            ]
        }
    )
    rows, summary = semantic.build_entities(tmp_path, tagger, index)
    [row] = rows
    assert row["entities"][0]["ids"] == ["G0007"]
    assert row["entities"][1]["text"] == "evil[.]example[.]com" and "ids" not in row["entities"][1]
    assert summary["pages"] == 1 and summary["linked_to_alias_index"] == {"Organization": 1}
    assert summary["score_ge_0.9"] == {"Indicator": 1, "Organization": 1}


class FakeEncoder:
    spec = models.BIENCODER
    max_tokens = 1024

    def encode(self, texts, progress=None):
        return np.array([[len(t), 1.0] for t in texts], dtype=np.float32)


def test_build_embeddings_flags_kev_language(tmp_path):
    nvd = [
        {"source_id": "CVE-2024-2", "text": "Actively exploited in the wild."},
        {"source_id": "CVE-2024-1", "text": "A bug."},
        {"source_id": "CVE-2024-3", "text": ""},
    ]
    (tmp_path / "nvd.jsonl.gz").write_bytes(gzip_bytes(jsonl(nvd)))
    vectors, index, summary = semantic.build_embeddings(tmp_path, FakeEncoder())
    assert vectors.dtype == np.float16 and vectors.shape == (2, 2)
    assert [r["cve"] for r in index] == ["CVE-2024-1", "CVE-2024-2"]  # sorted, empty dropped
    assert [r["kev_language"] for r in index] == [False, True]
    assert summary["kev_language_rows"] == 1


def test_models_verify_rejects_unpinned_weights(tmp_path):
    (tmp_path / "model.safetensors").write_bytes(b"weights")
    (tmp_path / "config.json").write_bytes(b"{}")
    files = {
        "model.safetensors": hashlib.sha256(b"weights").hexdigest(),
        "config.json": hashlib.sha256(b"{}").hexdigest(),
    }
    models.verify(models.ModelSpec("x/y", "rev", files), tmp_path)
    tampered = {**files, "config.json": "0" * 64}  # a swapped config is caught too
    with pytest.raises(ValueError, match=r"config\.json does not match"):
        models.verify(models.ModelSpec("x/y", "rev", tampered), tmp_path)


def test_cli_explains_missing_nlp_extra(monkeypatch, capsys, tmp_path):
    import importlib.util

    real = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util, "find_spec", lambda n, *a: None if n == "torch" else real(n, *a)
    )
    monkeypatch.setenv("CTI_DATA_DIR", str(tmp_path))
    assert main(["ner", "--date", "2026-10-26"]) == 2
    assert main(["attack-eval", "--date", "2026-10-26", "--methods", "biencoder"]) == 2
    assert "nlp extra" in capsys.readouterr().err
