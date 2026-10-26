"""MITRE CWE catalog, pinned version. Parsed with defusedxml (no XXE / entity bombs)."""

from __future__ import annotations

import io
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from typing import IO

from defusedxml.ElementTree import iterparse

from cti.models import Document
from cti.snapshot import Snapshot
from cti.sources.base import FetchContext, Source

BASE = "https://cwe.mitre.org/data/xml"
NS = "{http://cwe.mitre.org/cwe-7}"
MAX_XML_BYTES = 200 * 1024 * 1024


class CWESource(Source):
    name = "cwe"

    def url(self) -> str:
        return f"{BASE}/cwec_v{self.settings.cwe_version}.xml.zip"

    def probe_url(self) -> str:
        return self.url()

    def fetch(self, ctx: FetchContext) -> None:
        url = self.url()
        ctx.write(self.name, "cwec.xml.zip", ctx.download(url), url, self.settings.cwe_version)

    @contextmanager
    def open_xml(self, snapshot: Snapshot) -> Iterator[IO[bytes]]:
        """The catalog XML from the snapshot, size-checked. Parse it with defusedxml."""
        [entry] = snapshot.entries(self.name)
        with zipfile.ZipFile(io.BytesIO(snapshot.read_raw(entry))) as zf:
            [info] = [i for i in zf.infolist() if i.filename.endswith(".xml")]
            if info.file_size > MAX_XML_BYTES:
                raise ValueError(f"{info.filename} is larger than expected")
            with zf.open(info) as fh:
                yield fh

    def parse(self, snapshot: Snapshot) -> Iterator[Document]:
        with self.open_xml(snapshot) as fh:
            yield from self._weaknesses(fh)

    @staticmethod
    def _weaknesses(fh) -> Iterator[Document]:
        for _, elem in iterparse(fh, events=("end",)):
            if elem.tag != f"{NS}Weakness":
                continue
            if elem.get("Status") != "Deprecated":
                cwe_id = f"CWE-{elem.get('ID')}"
                desc = elem.find(f"{NS}Description")
                yield Document(
                    id=Document.make_id("cwe", cwe_id),
                    source="cwe",
                    source_id=cwe_id,
                    title=elem.get("Name", cwe_id),
                    text=(desc.text or "").strip() if desc is not None else "",
                    url=f"https://cwe.mitre.org/data/definitions/{elem.get('ID')}.html",
                    metadata={
                        "abstraction": elem.get("Abstraction"),
                        "status": elem.get("Status"),
                    },
                )
            elem.clear()
