"""CISA Known Exploited Vulnerabilities catalog (CC0)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime

from cti.models import Document
from cti.snapshot import Snapshot
from cti.sources.base import FetchContext, Source, gunzip_stream, gz

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KEVSource(Source):
    name = "kev"

    def probe_url(self) -> str:
        return URL

    def fetch(self, ctx: FetchContext) -> None:
        data = ctx.download(URL)
        version = json.loads(data).get("catalogVersion")
        ctx.write(self.name, "kev.json.gz", gz(data), URL, version)

    def parse(self, snapshot: Snapshot) -> Iterator[Document]:
        for entry in snapshot.entries(self.name):
            catalog = json.load(gunzip_stream(snapshot.read_raw(entry)))
            for v in catalog["vulnerabilities"]:
                added = datetime.fromisoformat(v["dateAdded"])
                yield Document(
                    id=Document.make_id(self.name, v["cveID"]),
                    source=self.name,
                    source_id=v["cveID"],
                    title=v.get("vulnerabilityName") or v["cveID"],
                    text=v.get("shortDescription", ""),
                    url=f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
                    published=added,
                    cves=(v["cveID"],),
                    metadata={
                        "vendor": v.get("vendorProject"),
                        "product": v.get("product"),
                        "date_added": v["dateAdded"],
                        "due_date": v.get("dueDate"),
                        "ransomware_use": v.get("knownRansomwareCampaignUse"),
                        "cwes": v.get("cwes", []),
                    },
                )
