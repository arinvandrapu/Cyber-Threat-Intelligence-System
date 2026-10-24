import json

import pytest

from cti.gold import import_legacy, load_gold, write_fixture


def write_jsonl(path, rows):
    path.write_text("\n".join(json.dumps(r) for r in rows))
    return path


@pytest.fixture
def legacy(tmp_path):
    text = "QakBot uses 203.0.113.7 against Acme."
    gold = write_jsonl(
        tmp_path / "gold.jsonl",
        [
            {
                "id": "d1",
                "source": "threatfox",
                "title": "t",
                "labels": ["ioc"],
                "primary_label": "ioc",
                "label_details": {"ioc": {"signals": ["source_threatfox"]}},
            },
            {
                "id": "d1",
                "source": "threatfox",
                "title": "dup",
                "labels": ["ioc"],
                "primary_label": "ioc",
            },
            {
                "id": "d2",
                "source": "nvd",
                "title": "t2",
                "labels": ["vulnerability"],
                "primary_label": "vulnerability",
            },
        ],
    )
    ents = write_jsonl(
        tmp_path / "ents.jsonl",
        [
            {
                "id": "d1",
                "gold_entities": [
                    {
                        "type": "malware",
                        "value": "QakBot",
                        "start": 0,
                        "end": 6,
                        "derivation": "known_malware",
                    },
                    {
                        "type": "indicator",
                        "value": "203.0.113.7",
                        "start": 12,
                        "end": 23,
                        "derivation": "regex",
                    },
                    {
                        "type": "organization",
                        "value": "Wrong",
                        "start": 0,
                        "end": 5,
                        "derivation": "known_organization",
                    },
                ],
            },
        ],
    )
    corpus = write_jsonl(
        tmp_path / "corpus.jsonl", [{"id": "d1", "content": text}, {"id": "other", "content": "x"}]
    )
    return gold, ents, corpus


def test_import_dedupes_validates_offsets_and_reports(legacy):
    records, report = import_legacy(*legacy)
    assert [r.id for r in records] == ["d1"]
    assert report.duplicate_ids == ["d1"]
    assert report.missing_text == ["d2"]
    assert (report.entities_kept, report.entities_dropped) == (2, 1)
    assert records[0].label_signals == ["source_threatfox"]  # provenance kept: circular labels


def test_fixture_is_deterministic_and_checksum_verified(legacy, tmp_path):
    records, _ = import_legacy(*legacy)
    sha1 = write_fixture(records, tmp_path / "a.jsonl.gz")
    sha2 = write_fixture(records, tmp_path / "b.jsonl.gz")
    assert sha1 == sha2
    assert load_gold(tmp_path / "a.jsonl.gz", sha1)[0].text.startswith("QakBot")
    with pytest.raises(ValueError, match="mismatch"):
        load_gold(tmp_path / "a.jsonl.gz", "0" * 64)
