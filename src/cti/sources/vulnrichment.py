"""CISA Vulnrichment SSVC decisions at the cutoff and snapshot dates (CC0).

The repo's per-record timestamps are overwritten when CISA rescores, so the only honest
point-in-time view is the repo as of a commit. For each date we stream the commit's
archive, keep only the CISA-ADP SSVC options, and store that compact extract; the commit
SHA in the manifest makes it reproducible. The ADP ``kev`` block is deliberately dropped.
The archive is read in memory, never extracted to disk.
"""

from __future__ import annotations

import json
import tarfile
from collections.abc import Iterator

from cti.models import AsOf, CveSignal
from cti.snapshot import Snapshot
from cti.sources import github
from cti.sources.base import FetchContext, Source, gunzip_stream, gz

REPO = "cisagov/vulnrichment"
BRANCH = "develop"
MAX_MEMBER_BYTES = 5 * 1024 * 1024
SSVC_KEYS = {
    "Exploitation": "exploitation",
    "Automatable": "automatable",
    "Technical Impact": "technical_impact",
}


def extract_ssvc(record: dict) -> dict | None:
    for adp in record.get("containers", {}).get("adp", []):
        if adp.get("providerMetadata", {}).get("shortName") != "CISA-ADP":
            continue
        for metric in adp.get("metrics", []):
            other = metric.get("other", {})
            if other.get("type") != "ssvc":
                continue
            content = other.get("content", {})
            values = {
                SSVC_KEYS[k]: v.lower() if isinstance(v, str) else v
                for option in content.get("options", [])
                for k, v in option.items()
                if k in SSVC_KEYS
            }
            if values:
                return {
                    "cve": content.get("id") or record["cveMetadata"]["cveId"],
                    **values,
                    "decided_at": content.get("timestamp"),
                }
    return None


class VulnrichmentSource(Source):
    name = "vulnrichment"

    def probe_url(self) -> str:
        return f"{github.API}/repos/{REPO}/commits?sha={BRANCH}&per_page=1"

    def fetch(self, ctx: FetchContext) -> None:
        for as_of, day in (("cutoff", ctx.cutoff_date), ("snapshot", ctx.snapshot_date)):
            sha, _ = github.head_at(github.repo_url(REPO), BRANCH, day)
            url = github.archive_url(REPO, sha)
            with ctx.download_to_file(url) as path:
                rows = list(self._scan_archive(path))
            body = "\n".join(json.dumps(r, sort_keys=True) for r in rows).encode()
            ctx.write(self.name, f"ssvc-{as_of}.jsonl.gz", gz(body), url, sha)

    @staticmethod
    def _scan_archive(path) -> Iterator[dict]:
        with tarfile.open(path, mode="r:gz") as tar:
            for member in tar:
                if not (member.isfile() and member.name.endswith(".json")):
                    continue
                if "/CVE-" not in member.name or member.size > MAX_MEMBER_BYTES:
                    continue
                fh = tar.extractfile(member)
                if fh is None:
                    continue
                try:
                    record = json.load(fh)
                except json.JSONDecodeError:
                    continue
                if row := extract_ssvc(record):
                    yield row

    def parse(self, snapshot: Snapshot) -> Iterator[CveSignal]:
        for entry in snapshot.entries(self.name):
            as_of: AsOf = "cutoff" if "cutoff" in entry.name else "snapshot"
            for line in gunzip_stream(snapshot.read_raw(entry)):
                row = json.loads(line)
                cve = row.pop("cve")
                yield CveSignal(
                    cve=cve,
                    source=self.name,
                    as_of=as_of,
                    values={**row, "commit": entry.source_version},
                )
