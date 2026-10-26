"""Offline enrichment: joins and cleaning over the parsed snapshot (``cti enrich``).

Outputs are derived and regenerable, so they are overwritten on every run (atomically) and
stay on local disk under ``data/enriched/<date>/``. They are written deterministically:
sorted rows and keys, and a gzip header without a filename or timestamp.
"""

from __future__ import annotations

import gzip
import json
import os
from collections.abc import Iterable, Iterator
from pathlib import Path


def read_jsonl(path: Path) -> Iterator[dict]:
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            yield json.loads(line)


def write_jsonl(path: Path, rows: Iterable[dict]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    count = 0
    try:
        with (
            tmp.open("wb") as raw,
            gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as fh,
        ):
            for row in rows:
                fh.write(json.dumps(row, sort_keys=True, ensure_ascii=False).encode() + b"\n")
                count += 1
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    return count


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
