"""The classification gold set: imported once from the prototype's files, then frozen.

The labels are **rule-generated, not hand-labeled** (see vault/gold-set-provenance.md), so
results on this set are reported as a sanity check next to the source-only baseline.

The fixture is private (documents contain live URLs and come from feeds whose terms forbid
redistribution): it lives in ``data/gold/`` (gitignored) and the S3 bucket. Only its
SHA-256 is committed, and every load verifies it. Entity offsets index into ``text``,
so text is stored unmodified; defang at display time.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel

# SHA-256 of the frozen fixture produced by `cti gold-import`; set when it was frozen.
GOLD_SHA256: str | None = "4a612d2fb579351d8788b1f6605bce9d286bf6829d0963b96fd091bf5687ceb5"


class GoldEntity(BaseModel):
    type: str
    value: str
    start: int
    end: int
    derivation: str


class GoldRecord(BaseModel):
    id: str
    source: str
    title: str
    text: str
    labels: list[str]
    primary_label: str
    label_signals: list[str]
    entities: list[GoldEntity]


@dataclass
class ImportReport:
    records: int = 0
    duplicate_ids: list[str] = field(default_factory=list)
    missing_text: list[str] = field(default_factory=list)
    entities_kept: int = 0
    entities_dropped: int = 0
    labels: Counter = field(default_factory=Counter)
    sources: Counter = field(default_factory=Counter)
    derivations: Counter = field(default_factory=Counter)


def _jsonl(path: Path):
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def import_legacy(
    gold_path: Path, entities_path: Path, corpus_path: Path
) -> tuple[list[GoldRecord], ImportReport]:
    report = ImportReport()
    labels: dict[str, dict] = {}
    for row in _jsonl(gold_path):
        if row["id"] in labels:
            report.duplicate_ids.append(row["id"])
            continue
        labels[row["id"]] = row
    entities = {}
    for row in _jsonl(entities_path):
        entities.setdefault(row["id"], row)
    texts: dict[str, str] = {}
    for row in _jsonl(corpus_path):
        if row["id"] in labels:
            texts.setdefault(row["id"], row["content"])  # first occurrence wins everywhere

    records = []
    for doc_id, row in labels.items():
        text = texts.get(doc_id)
        if text is None:
            report.missing_text.append(doc_id)
            continue
        kept = []
        for ent in entities.get(doc_id, {}).get("gold_entities", []):
            if text[ent["start"] : ent["end"]] == ent["value"]:
                kept.append(GoldEntity(**ent))
                report.derivations[ent["derivation"]] += 1
            else:
                report.entities_dropped += 1
        primary = row["primary_label"]
        records.append(
            GoldRecord(
                id=doc_id,
                source=row["source"],
                title=row["title"],
                text=text,
                labels=row["labels"],
                primary_label=primary,
                label_signals=row.get("label_details", {}).get(primary, {}).get("signals", []),
                entities=kept,
            )
        )
        report.entities_kept += len(kept)
        report.labels[primary] += 1
        report.sources[row["source"]] += 1
    report.records = len(records)
    return sorted(records, key=lambda r: r.id), report


def serialize(records: list[GoldRecord]) -> bytes:
    body = "\n".join(r.model_dump_json() for r in sorted(records, key=lambda r: r.id))
    return gzip.compress(body.encode(), compresslevel=9, mtime=0)


def write_fixture(records: list[GoldRecord], path: Path) -> str:
    data = serialize(records)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def read_verified(path: Path, expected_sha256: str | None = GOLD_SHA256) -> bytes:
    """Return the fixture's bytes after checking them against the frozen checksum."""
    data = path.read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if expected_sha256 is None:
        raise ValueError("no frozen gold checksum is recorded (cti.gold.GOLD_SHA256)")
    if actual != expected_sha256:
        raise ValueError(f"gold fixture checksum mismatch: {actual} != {expected_sha256}")
    return data


def load_gold(path: Path, expected_sha256: str | None = GOLD_SHA256) -> list[GoldRecord]:
    data = read_verified(path, expected_sha256)
    return [GoldRecord.model_validate_json(line) for line in gzip.decompress(data).splitlines()]
