"""Scraped CVE reference pages, captured once as part of the ingest.

Depends on the NVD, KEV, and EPSS data already in the snapshot (to choose targets), so it
runs last. Pages are stored as gzip'd JSONL shards with base64 bodies; the target list is
stored too, so the selection is auditable.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections import defaultdict
from collections.abc import Iterator

from cti.http.safe_fetch import SafeFetcher
from cti.models import Document
from cti.references.scraper import scrape
from cti.references.selection import select_targets
from cti.references.text import html_to_text
from cti.snapshot import Snapshot
from cti.sources.base import FetchContext, Source, gunzip_stream, gz
from cti.sources.epss import EPSSSource
from cti.sources.kev import KEVSource
from cti.sources.nvd import NVDSource

DEPENDS_ON = ("nvd", "kev", "epss")
SHARD_RECORDS = 250
SHARD_BYTES = 64 * 1024 * 1024  # also flush by size: pages can be up to ~2.7 MB as base64


class ReferencesSource(Source):
    name = "references"
    requires = ("contact",)

    def probe_url(self) -> str:
        return "https://nvd.nist.gov/robots.txt"

    def targets(self, snapshot: Snapshot):
        missing = [s for s in DEPENDS_ON if not snapshot.is_complete(s)]
        if missing:
            raise RuntimeError(f"references needs completed sources first: {', '.join(missing)}")
        references: dict[str, list[str]] = {}
        for doc in NVDSource(self.settings).parse(snapshot):
            references[doc.source_id] = list(doc.metadata.get("references", []))
        kev_added = {
            d.source_id: d.metadata["date_added"] for d in KEVSource(self.settings).parse(snapshot)
        }
        epss = {
            s.cve: s.values["epss"]
            for s in EPSSSource(self.settings).parse(snapshot)
            if s.as_of == "snapshot"
        }
        return select_targets(
            references,
            kev_added,
            epss,
            per_cve=self.settings.scrape_per_cve,
            max_pages=self.settings.scrape_max_pages,
        )

    def fetch(self, ctx: FetchContext) -> None:
        targets = self.targets(ctx.snapshot)
        listing = [{"cve": t.cve, "url": t.url, "ref_type": str(t.ref_type)} for t in targets]
        ctx.write(self.name, "targets.json.gz", gz(json.dumps(listing).encode()), None)
        with SafeFetcher(self.settings.user_agent) as fetcher:
            shard: list[str] = []
            size = number = 0
            for record in scrape(
                targets,
                fetcher,
                workers=self.settings.scrape_workers,
                host_interval=self.settings.scrape_host_interval,
            ):
                line = json.dumps(record, sort_keys=True)
                shard.append(line)
                size += len(line)
                if len(shard) >= SHARD_RECORDS or size >= SHARD_BYTES:
                    number += 1
                    self._write_shard(ctx, number, shard)
                    shard, size = [], 0
            if shard:
                self._write_shard(ctx, number + 1, shard)

    def _write_shard(self, ctx: FetchContext, number: int, lines: list[str]) -> None:
        body = "\n".join(lines).encode()
        ctx.write(self.name, f"pages-{number:04d}.jsonl.gz", gz(body), None)

    def parse(self, snapshot: Snapshot) -> Iterator[Document]:
        counts: dict[str, int] = defaultdict(int)
        for entry in snapshot.entries(self.name):
            if not entry.name.startswith("pages-"):
                continue
            for line in gunzip_stream(snapshot.read_raw(entry)):
                record = json.loads(line)
                if "body_b64" not in record:
                    counts["no_body"] += 1
                    continue
                body = base64.b64decode(record["body_b64"])
                ctype = record.get("content_type", "")
                if ctype == "application/pdf":
                    text = ""  # PDF text extraction happens in the enrichment phase
                elif ctype == "text/plain":
                    text = body.decode("utf-8", errors="replace")
                else:
                    text = html_to_text(body.decode("utf-8", errors="replace"))
                url_id = hashlib.sha256(record["url"].encode()).hexdigest()[:16]
                yield Document(
                    id=Document.make_id(self.name, url_id),
                    source=self.name,
                    source_id=url_id,
                    title=record["url"],
                    text=text,
                    url=record["url"],
                    cves=(record["cve"],),
                    metadata={
                        "ref_type": record.get("ref_type"),
                        "final_url": record.get("final_url"),
                        "content_type": ctype,
                        "truncated": record.get("truncated", False),
                        "fetched_at": record.get("fetched_at"),
                    },
                )
