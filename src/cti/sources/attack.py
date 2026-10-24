"""MITRE ATT&CK Enterprise (STIX 2.1), pinned to a release version."""

from __future__ import annotations

import json
from collections.abc import Iterator

from cti.models import Document
from cti.snapshot import Snapshot
from cti.sources.base import FetchContext, Source, gunzip_stream, gz

BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack"
KEPT_TYPES = {"attack-pattern", "malware", "tool", "intrusion-set"}


def _external_id(obj: dict) -> tuple[str | None, str | None]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id"), ref.get("url")
    return None, None


class AttackSource(Source):
    name = "attack"

    def url(self) -> str:
        return f"{BASE}/enterprise-attack-{self.settings.attack_version}.json"

    def probe_url(self) -> str:
        return self.url()

    def fetch(self, ctx: FetchContext) -> None:
        url = self.url()
        ctx.write(
            self.name,
            "enterprise-attack.json.gz",
            gz(ctx.download(url)),
            url,
            self.settings.attack_version,
        )

    def parse(self, snapshot: Snapshot) -> Iterator[Document]:
        for entry in snapshot.entries(self.name):
            bundle = json.load(gunzip_stream(snapshot.read_raw(entry)))
            for obj in bundle["objects"]:
                if obj.get("type") not in KEPT_TYPES:
                    continue
                if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                    continue
                ext_id, url = _external_id(obj)
                if not ext_id:
                    continue
                yield Document(
                    id=Document.make_id(self.name, ext_id),
                    source=self.name,
                    source_id=ext_id,
                    title=obj["name"],
                    text=obj.get("description", ""),
                    url=url,
                    metadata={
                        "stix_type": obj["type"],
                        "stix_id": obj["id"],
                        "aliases": obj.get("aliases") or obj.get("x_mitre_aliases") or [],
                        "tactics": [
                            p["phase_name"]
                            for p in obj.get("kill_chain_phases", [])
                            if p.get("kill_chain_name") == "mitre-attack"
                        ],
                        "platforms": obj.get("x_mitre_platforms", []),
                        "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
                    },
                )
