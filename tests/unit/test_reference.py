import csv
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path

import pytest

from cti import reference
from cti.nlp import attack_eval

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
REF = DATA_DIR / reference.REFERENCE_DIR
NOT_DATA = {"NOTICE.md", "LICENSE.txt", "LICENSE.md"}


def test_every_pinned_file_is_committed_and_matches():
    for name in reference.PINNED:
        assert reference.read_pinned(DATA_DIR, name)


def test_every_committed_reference_file_is_pinned():
    pinned = set(reference.PINNED) | {attack_eval.CTID_FILE.relative_to("reference").as_posix()}
    for folder in ("ctid", "capec", "misp-galaxy"):
        for path in (REF / folder).iterdir():
            if path.name not in NOT_DATA:
                assert path.relative_to(REF).as_posix() in pinned, path
        assert (REF / folder / "NOTICE.md").is_file()


def test_read_pinned_refuses_changed_bytes(tmp_path):
    name = reference.CTID_ATTACK_TO_CVE
    copy = tmp_path / reference.REFERENCE_DIR / name
    copy.parent.mkdir(parents=True)
    copy.write_bytes((REF / name).read_bytes() + b"\n")
    with pytest.raises(ValueError, match="does not match the pinned"):
        reference.read_pinned(tmp_path, name)


def test_ctid_attack_to_cve_shape():
    text = reference.read_pinned(DATA_DIR, reference.CTID_ATTACK_TO_CVE).decode("utf-8-sig")
    rows = list(csv.DictReader(io.StringIO(text)))
    assert list(rows[0]) == [
        "CVE ID",
        "Primary Impact",
        "Secondary Impact",
        "Exploitation Technique",
        "Uncategorized",
        "Phase",
    ]
    # 839 rows, 836 CVEs: three CVEs have a Phase 1 and a Phase 2 row, none with an
    # exploitation technique, so 10b merges rows per CVE
    cves = [r["CVE ID"] for r in rows]
    repeated = {c for c in cves if cves.count(c) > 1}
    assert len(rows) == 839 and len(set(cves)) == 836
    assert not any(r["Exploitation Technique"] for r in rows if r["CVE ID"] in repeated)
    # the graded columns hold well-formed Enterprise IDs; malformed ones ("T11190", "T828",
    # "T1036.") occur only in Uncategorized, which 10b drops
    graded = ("Primary Impact", "Secondary Impact", "Exploitation Technique")
    ids = [t.strip() for r in rows for col in graded for t in r[col].split(";") if t.strip()]
    assert all(re.fullmatch(r"T\d{4}(\.\d{3})?", t) for t in ids)
    assert sum(bool(r["Exploitation Technique"].strip()) for r in rows) == 204


def test_capec_archive_holds_the_3_9_catalog():
    data = reference.read_pinned(DATA_DIR, reference.CAPEC)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        head = archive.read("capec_v3.9.xml")[:1000].decode()
    assert 'Name="CAPEC"' in head and 'Version="3.9"' in head


def test_misp_category_is_the_cluster_file():
    for category in reference.MISP_CATEGORIES:
        name = f"misp-galaxy/{category}.json"
        cluster = json.loads(reference.read_pinned(DATA_DIR, name))
        assert cluster["type"] == category and cluster["values"]


def test_misp_files_are_exactly_the_trimmed_form():
    # trimming is idempotent, so a committed file equal to its own trim holds nothing the
    # trim drops (ransom notes, leak-site links, victims) and nothing hand-edited in
    for category in reference.MISP_CATEGORIES:
        data = reference.read_pinned(DATA_DIR, f"misp-galaxy/{category}.json")
        assert reference.trim_misp_cluster(data) == data


def test_trim_misp_cluster_drops_victim_data_and_onion_links():
    raw = json.dumps(
        {
            "type": "ransomware",
            "name": "Ransomware",
            "version": 1,
            "values": [
                {
                    "value": "Hive",
                    "uuid": "b",
                    "description": "RaaS",
                    "meta": {
                        "synonyms": ["HiveLeaks"],
                        "refs": [
                            "https://vendor.example/hive",
                            "http://abcdefghijklmnop.onion/",
                            "https://abcdefghijklmnop.onion.foundation/",
                        ],
                        "ransomnotes": ["Login: x Password: y"],
                        "links": ["http://leak.onion/"],
                        "payment-method": "Bitcoin",
                        "price": "1",
                        "cfr-suspected-victims": ["Victim Inc"],
                    },
                },
                {"value": "Akira", "uuid": "a", "meta": {"ransomnotes": ["note"]}},
            ],
        }
    ).encode()
    trimmed = json.loads(reference.trim_misp_cluster(raw))
    assert trimmed == {
        "type": "ransomware",
        "name": "Ransomware",
        "values": [
            {"value": "Akira", "uuid": "a"},
            {
                "value": "Hive",
                "uuid": "b",
                "description": "RaaS",
                "meta": {"synonyms": ["HiveLeaks"], "refs": ["https://vendor.example/hive"]},
            },
        ],
    }


def test_pins_are_sha256_hex():
    for digest in reference.PINNED.values():
        assert len(digest) == 64 and int(digest, 16) >= 0
    assert hashlib.sha256(b"").hexdigest() not in reference.PINNED.values()
