"""ProjectDiscovery Nuclei CVE templates at each cutoff and the snapshot date (MIT).

``cves.json`` is JSON Lines with one row per CVE template. Template files also carry
``kev`` tags and EPSS scores; those are not read (they would leak later knowledge).
"""

from __future__ import annotations

import json
from collections.abc import Iterator

from cti.models import CveSignal
from cti.snapshot import Snapshot
from cti.sources import github
from cti.sources.base import FetchContext, Source, as_of_from_name, gunzip_stream, gz

REPO = "projectdiscovery/nuclei-templates"
BRANCH = "main"
PATH = "cves.json"


class NucleiSource(Source):
    name = "nuclei"

    def probe_url(self) -> str:
        return f"{github.API}/repos/{REPO}/commits?sha={BRANCH}&path={PATH}&per_page=1"

    def fetch(self, ctx: FetchContext) -> None:
        for as_of, day in ctx.as_of_days:
            sha, _ = github.head_at(github.repo_url(REPO), BRANCH, day)
            url = github.raw_url(REPO, sha, PATH)
            ctx.write(self.name, f"cves-{as_of}.jsonl.gz", gz(ctx.download(url)), url, sha)

    def parse(self, snapshot: Snapshot) -> Iterator[CveSignal]:
        for entry in snapshot.entries(self.name):
            as_of = as_of_from_name(entry.name)
            for line in gunzip_stream(snapshot.read_raw(entry)):
                if not line.strip():
                    continue
                row = json.loads(line)
                info = row.get("Info", {})
                yield CveSignal(
                    cve=row["ID"],
                    source=self.name,
                    as_of=as_of,
                    values={
                        "severity": info.get("Severity"),
                        "template": row.get("file_path"),
                        "commit": entry.source_version,
                    },
                )
