"""ATT&CK Enterprise techniques as ranking candidates, plus revoked-ID remapping.

Candidates are the active (not revoked, not deprecated) techniques and sub-techniques that
``cti parse`` keeps from the pinned v20 bundle. Their text is the name plus the description
with ``(Citation: ...)`` markers and Markdown link syntax removed.

Grading is at technique level: a sub-technique rolls up to its parent (``T1059.001`` ->
``T1059``), and a parent's score is the max over itself and its sub-techniques. Labels made
against an older ATT&CK release are remapped through the bundle's ``revoked-by``
relationships (e.g. v16.1 ``T1562`` -> v20 ``T1685``).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from cti.enrich import read_jsonl
from cti.snapshot import Snapshot
from cti.sources.attack import AttackSource
from cti.sources.base import gunzip_stream

_CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")


def parent(technique_id: str) -> str:
    return technique_id.split(".", 1)[0]


def clean(text: str) -> str:
    text = _MD_LINK.sub(r"\1", _CITATION.sub("", text))
    return " ".join(text.split())


@dataclass(frozen=True, slots=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    text: str  # name + cleaned description


def load_techniques(processed: Path) -> list[Technique]:
    out = []
    for doc in read_jsonl(processed / "attack.jsonl.gz"):
        if doc["metadata"]["stix_type"] != "attack-pattern":
            continue
        name = doc["title"]
        out.append(
            Technique(
                doc["source_id"],
                name,
                tuple(doc["metadata"]["tactics"]),
                f"{name}. {clean(doc['text'])}",
            )
        )
    return sorted(out, key=lambda t: t.id)


def _external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def revocations_from_bundle(objects: list[dict]) -> dict[str, str]:
    """Revoked technique ID -> its current replacement, following chains."""
    ids = {o["id"]: _external_id(o) for o in objects if o.get("type") == "attack-pattern"}
    direct = {
        ids[o["source_ref"]]: ids[o["target_ref"]]
        for o in objects
        if o.get("type") == "relationship"
        and o.get("relationship_type") == "revoked-by"
        and ids.get(o.get("source_ref"))
        and ids.get(o.get("target_ref"))
    }
    resolved = {}
    for old in direct:
        new, seen = direct[old], {old}
        while new in direct and new not in seen:
            seen.add(new)
            new = direct[new]
        resolved[old] = new
    return resolved


def revocations(snapshot: Snapshot) -> dict[str, str]:
    for entry in snapshot.entries(AttackSource.name):
        bundle = json.load(gunzip_stream(snapshot.read_raw(entry)))
        return revocations_from_bundle(bundle["objects"])
    raise FileNotFoundError(f"snapshot {snapshot.id} has no ATT&CK bundle")
