"""FIRST EPSS scores at each evaluation cutoff and at the snapshot date.

Bulk daily CSVs (``epss_scores-YYYY-MM-DD.csv.gz``). The first line records the EPSS
model version and score date, which are kept with every signal: the model changed
between versions, and the cutoff file must be scored by the model of its day.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterator
from datetime import date, timedelta

import httpx

from cti.models import CveSignal
from cti.snapshot import Snapshot
from cti.sources.base import FetchContext, Source, as_of_from_name, gunzip_stream

BASE = "https://epss.empiricalsecurity.com"


def url_for(day: date) -> str:
    return f"{BASE}/epss_scores-{day.isoformat()}.csv.gz"


def _header(first_line: str) -> dict[str, str]:
    return dict(p.split(":", 1) for p in first_line.lstrip("#").strip().split(",") if ":" in p)


class EPSSSource(Source):
    name = "epss"

    def probe_url(self) -> str:
        return f"{BASE}/epss_scores-current.csv.gz"

    def fetch(self, ctx: FetchContext) -> None:
        for as_of, day in ctx.as_of_days:
            # Today's file may not be published yet; fall back up to 3 days.
            for back in range(4):
                url = url_for(day - timedelta(days=back))
                try:
                    data = ctx.download(url)
                    break
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code != 404 or back == 3:
                        raise
            header = _header(gunzip_stream(data).readline().decode())
            ctx.write(self.name, f"epss-{as_of}.csv.gz", data, url, header.get("model_version"))

    def parse(self, snapshot: Snapshot) -> Iterator[CveSignal]:
        for entry in snapshot.entries(self.name):
            as_of = as_of_from_name(entry.name)
            text = io.TextIOWrapper(
                gunzip_stream(snapshot.read_raw(entry)), encoding="utf-8", newline=""
            )
            header = _header(text.readline())
            for row in csv.DictReader(text):
                yield CveSignal(
                    cve=row["cve"],
                    source=self.name,
                    as_of=as_of,
                    values={
                        "epss": float(row["epss"]),
                        "percentile": float(row["percentile"]),
                        "model_version": header.get("model_version"),
                        "score_date": header.get("score_date"),
                    },
                )
