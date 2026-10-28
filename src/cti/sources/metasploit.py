"""Metasploit module metadata at each cutoff and the snapshot date (BSD-3-Clause).

``mod_time`` is bulk-reset by the project and is never used as a creation date; presence
in the file at the cutoff commit is what counts.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterator

from cti.models import CveSignal
from cti.snapshot import Snapshot
from cti.sources import github
from cti.sources.base import FetchContext, Source, as_of_from_name, gunzip_stream, gz

REPO = "rapid7/metasploit-framework"
BRANCH = "master"
PATH = "db/modules_metadata_base.json"


class MetasploitSource(Source):
    name = "metasploit"

    def probe_url(self) -> str:
        return f"{github.API}/repos/{REPO}/commits?sha={BRANCH}&path={PATH}&per_page=1"

    def fetch(self, ctx: FetchContext) -> None:
        for as_of, day in ctx.as_of_days:
            sha, _ = github.head_at(github.repo_url(REPO), BRANCH, day)
            url = github.raw_url(REPO, sha, PATH)
            ctx.write(self.name, f"modules-{as_of}.json.gz", gz(ctx.download(url)), url, sha)

    def parse(self, snapshot: Snapshot) -> Iterator[CveSignal]:
        for entry in snapshot.entries(self.name):
            as_of = as_of_from_name(entry.name)
            modules = json.load(gunzip_stream(snapshot.read_raw(entry)))
            by_cve: dict[str, list[dict]] = defaultdict(list)
            for module in modules.values():
                for ref in module.get("references", []):
                    if isinstance(ref, str) and ref.startswith("CVE-"):
                        by_cve[ref].append(module)
            for cve, mods in sorted(by_cve.items()):
                yield CveSignal(
                    cve=cve,
                    source=self.name,
                    as_of=as_of,
                    values={
                        "module_count": len(mods),
                        "exploit_modules": sum(m.get("type") == "exploit" for m in mods),
                        "best_rank": max((m.get("rank") or 0) for m in mods),
                        "modules": sorted(m["fullname"] for m in mods),
                        "commit": entry.source_version,
                    },
                )
