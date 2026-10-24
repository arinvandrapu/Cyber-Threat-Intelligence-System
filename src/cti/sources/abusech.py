"""abuse.ch ThreatFox (IOCs) and URLhaus (malicious URLs).

Requires a free Auth-Key. abuse.ch's v2 export endpoints take the key **in the URL path**
(the old keyless URLs now return 410), so every recorded URL is redacted. Data is stored
privately and never redistributed (abuse.ch terms). Indicators are defanged at parse time.
"""

from __future__ import annotations

import csv
import io
import zipfile
from collections.abc import Iterator
from datetime import datetime
from typing import ClassVar

from cti.defang import defang_host, defang_ip, defang_url
from cti.models import Document
from cti.snapshot import Snapshot
from cti.sources.base import FetchContext, Source, copy_capped, gunzip_stream, gz

MAX_CSV_BYTES = 500 * 1024 * 1024


def read_commented_csv(text: str) -> Iterator[dict[str, str]]:
    """abuse.ch CSVs put the header in the last ``#`` comment line before the data.

    Comment lines after the data starts (footers) are ignored. Lines are split on ``\n``
    only: ``str.splitlines`` would also split on characters like ``\x85`` that can
    appear inside malicious URLs.
    """
    header: list[str] | None = None
    data_lines: list[str] = []
    for line in text.replace("\r\n", "\n").split("\n"):
        if line.startswith("#"):
            body = line.lstrip("#").strip()
            if not data_lines and "," in body:
                header = next(csv.reader([body], skipinitialspace=True))
        elif line.strip():
            data_lines.append(line)
    if header is None:
        raise ValueError("no header comment found")
    data = io.StringIO("\n".join(data_lines), newline="")
    for row in csv.reader(data, skipinitialspace=True):
        yield dict(zip(header, (v.strip() for v in row), strict=False))


def _ts(value: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(value) if value else None
    except ValueError:
        return None


def defang_ioc(value: str, ioc_type: str) -> str:
    if ioc_type == "url":
        return defang_url(value)
    if ioc_type == "ip:port":
        ip, _, port = value.rpartition(":")
        return f"{defang_ip(ip)}:{port}"
    if ioc_type == "domain":
        return defang_host(value)
    return value  # hashes are inert


class _AbuseCHSource(Source):
    requires: ClassVar[tuple[str, ...]] = ("abusech_auth_key",)
    host: ClassVar[str]
    filename: ClassVar[str]

    def key(self) -> str:
        self.settings.require("abusech_auth_key")
        return self.settings.abusech_auth_key.get_secret_value()

    def url(self) -> str:
        return f"https://{self.host}/v2/files/exports/{self.key()}/{self.filename}"

    def probe_url(self) -> str:
        return self.url()

    def fetch(self, ctx: FetchContext) -> None:
        ctx.secrets.append(self.key())
        data = ctx.download(self.url())
        if not self.filename.endswith((".zip", ".gz")):
            data = gz(data)
            name = f"{self.filename}.gz"
        else:
            name = self.filename
        ctx.write(self.name, name, data, self.url())

    def _csv_text(self, raw: bytes, name: str) -> str:
        out = io.BytesIO()
        if name.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                [info] = [i for i in zf.infolist() if i.filename.endswith(".csv")]
                with zf.open(info) as fh:
                    copy_capped(fh, out, MAX_CSV_BYTES)
        else:
            copy_capped(gunzip_stream(raw), out, MAX_CSV_BYTES)
        return out.getvalue().decode("utf-8", errors="replace")


class ThreatFoxSource(_AbuseCHSource):
    name = "threatfox"
    host = "threatfox-api.abuse.ch"
    filename = "full.csv.zip"  # IOCs from the last 6 months

    def parse(self, snapshot: Snapshot) -> Iterator[Document]:
        for entry in snapshot.entries(self.name):
            for row in read_commented_csv(self._csv_text(snapshot.read_raw(entry), entry.name)):
                ioc_type = row.get("ioc_type", "")
                value = defang_ioc(row.get("ioc_value", ""), ioc_type)
                malware = row.get("malware_printable") or row.get("fk_malware") or "unknown"
                yield Document(
                    id=Document.make_id(self.name, row["ioc_id"]),
                    source=self.name,
                    source_id=row["ioc_id"],
                    title=f"{malware} {ioc_type} {value}",
                    text=f"{row.get('threat_type', '')} indicator for {malware}: {value}",
                    url=f"https://threatfox.abuse.ch/ioc/{row['ioc_id']}/",
                    published=_ts(row.get("first_seen_utc")),
                    metadata={
                        "ioc": value,
                        "ioc_type": ioc_type,
                        "threat_type": row.get("threat_type"),
                        "malware": malware,
                        "malware_alias": row.get("malware_alias") or None,
                        "confidence": int(row["confidence_level"])
                        if row.get("confidence_level", "").isdigit()
                        else None,
                        "tags": [t for t in (row.get("tags") or "").split(",") if t],
                        "last_seen": row.get("last_seen_utc") or None,
                    },
                )


class URLhausSource(_AbuseCHSource):
    name = "urlhaus"
    host = "urlhaus-api.abuse.ch"
    filename = "recent.csv"  # URLs added in the last 30 days

    def parse(self, snapshot: Snapshot) -> Iterator[Document]:
        for entry in snapshot.entries(self.name):
            for row in read_commented_csv(self._csv_text(snapshot.read_raw(entry), entry.name)):
                value = defang_url(row.get("url", ""))
                yield Document(
                    id=Document.make_id(self.name, row["id"]),
                    source=self.name,
                    source_id=row["id"],
                    title=f"{row.get('threat', 'malicious url')} {value}",
                    text=f"{row.get('threat', '')} URL ({row.get('url_status', '')}): {value}",
                    url=row.get("urlhaus_link") or None,
                    published=_ts(row.get("dateadded")),
                    metadata={
                        "ioc": value,
                        "ioc_type": "url",
                        "threat": row.get("threat"),
                        "status": row.get("url_status"),
                        "tags": [t for t in (row.get("tags") or "").split(",") if t],
                    },
                )
