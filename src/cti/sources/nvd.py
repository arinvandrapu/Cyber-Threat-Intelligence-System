"""NVD CVE records from the yearly CVE 2.0 JSON feeds (no API key, no paging).

Feeds are grouped by CVE-ID year, not publish date, so the year before the window start
is fetched too and records are filtered by ``published`` at parse time. Each download is
verified against the SHA-256 in NVD's ``.meta`` file.

Fields that leak later knowledge are dropped at parse time: NVD's copy of CISA KEV
data (``cisaExploitAdd`` etc.) and reference tags. The CVSS v4 threat metric (``E:``)
is excluded from features in the risk phase.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from datetime import date, datetime

import ijson

from cti.models import Document
from cti.snapshot import Snapshot
from cti.sources.base import FetchContext, Source, gunzip_stream

BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
CVSS_PREFERENCE = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def _meta(text: str) -> dict[str, str]:
    return dict(line.split(":", 1) for line in text.strip().splitlines() if ":" in line)


def _sha256_of_gunzipped(data: bytes) -> str:
    digest = hashlib.sha256()
    stream = gunzip_stream(data)
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest().upper()


def _best_cvss(metrics: dict) -> dict | None:
    for key in CVSS_PREFERENCE:
        entries = metrics.get(key) or []
        entries = sorted(entries, key=lambda m: m.get("type") != "Primary")
        if entries:
            data = entries[0]["cvssData"]
            return {
                "version": data.get("version"),
                "base_score": data.get("baseScore"),
                "severity": data.get("baseSeverity") or entries[0].get("baseSeverity"),
                "vector": data.get("vectorString"),
                "source": entries[0].get("source"),
                "type": entries[0].get("type"),
            }
    return None


def _ts(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class NVDSource(Source):
    name = "nvd"

    def years(self, snapshot_year: int) -> range:
        return range(self.settings.nvd_window_start.year - 1, snapshot_year + 1)

    def probe_url(self) -> str:
        return f"{BASE}/nvdcve-2.0-{self.settings.nvd_window_start.year}.meta"

    def fetch(self, ctx: FetchContext) -> None:
        for year in self.years(ctx.snapshot_date.year):
            stem = f"nvdcve-2.0-{year}"
            for attempt in range(2):  # the feed can be regenerated between meta and data
                meta = _meta(ctx.download(f"{BASE}/{stem}.meta").decode())
                data = ctx.download(f"{BASE}/{stem}.json.gz")
                if _sha256_of_gunzipped(data) == meta["sha256"].upper():
                    break
                if attempt == 1:
                    raise ValueError(f"{stem}: checksum does not match .meta")
            ctx.write(
                self.name,
                f"{stem}.json.gz",
                data,
                f"{BASE}/{stem}.json.gz",
                meta.get("lastModifiedDate"),
            )

    def parse(self, snapshot: Snapshot) -> Iterator[Document]:
        start = self.settings.nvd_window_start
        for entry in snapshot.entries(self.name):
            stream = gunzip_stream(snapshot.read_raw(entry))
            for item in ijson.items(stream, "vulnerabilities.item", use_float=True):
                yield from self._document(item["cve"], start)

    @staticmethod
    def _document(cve: dict, start: date) -> Iterator[Document]:
        published = _ts(cve.get("published"))
        if published is None or published.date() < start:
            return
        if cve.get("vulnStatus") == "Rejected":
            return
        text = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
        cwes = sorted(
            {
                d["value"]
                for w in cve.get("weaknesses", [])
                for d in w.get("description", [])
                if d["value"].startswith("CWE-")
            }
        )
        yield Document(
            id=Document.make_id("nvd", cve["id"]),
            source="nvd",
            source_id=cve["id"],
            title=cve["id"],
            text=text,
            url=f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
            published=published,
            modified=_ts(cve.get("lastModified")),
            cves=(cve["id"],),
            metadata={
                "vuln_status": cve.get("vulnStatus"),
                "cvss": _best_cvss(cve.get("metrics", {})),
                "cwes": cwes,
                # URLs only: reference tags ("Exploit", ...) are added after publication
                # and would leak later knowledge into risk features.
                "references": [r["url"] for r in cve.get("references", [])],
            },
        )
