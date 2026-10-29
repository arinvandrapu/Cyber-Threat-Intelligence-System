"""Pinned third-party reference files committed under ``data/reference/``.

Each file is an upstream copy with its licence and source commit in the ``NOTICE.md``
beside it. All are unmodified except the MISP clusters, which are trimmed by
:func:`trim_misp_cluster` (see there). Reads go through :func:`read_pinned`, which refuses
bytes that do not match the SHA-256 recorded here, so a silently updated or edited copy
cannot change a result. ``tests/unit/test_reference.py`` checks every committed file
against this table.

The CTID KEV mappings (Phase 5b) predate this module and stay pinned in
``cti.nlp.attack_eval.CTID_SHA256``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

REFERENCE_DIR = Path("reference")  # under data_dir

CTID_ATTACK_TO_CVE = "ctid/attack_to_cve.csv"
CAPEC = "capec/capec_v3.9.zip"
_MISP_PINS = {  # category = the cluster file (Phase 10a)
    "ransomware": "d344ae09492beefd7de2ac2ea8bbcdb063b252a7dabfcf5c74e0cf9015ea3ca3",
    "stealer": "e050833bb500919430b43a2880b163ff1b85a52ed65181722946e1fda434086d",
    "rat": "1fd2b1b9768e8148f63c83c5bce968a83d944f57dbc7472d007834ad1f8cb092",
    "botnet": "09baf7607a97a2a2c85d9de32f1ccd40ed7693ed62f03cbfd4e9279ff0014790",
    "banker": "d6c776798742a0c4e0eef6d3468c9bfeb5ca95028da0b933baf5e87f5982ceb8",
    "backdoor": "e4775353c939454794cfbc38630694ebaaf95a765ec70829b1377c02c0ebdfc3",
    "tool": "d4f9def351b79d01ede61e2f69951f727af1d098d4defcfc09be588809f91612",
    "exploit-kit": "59385fe383ee1bbe2922a7d0ced8a6819587b7123281276ec284fe6b94d86390",
    "cryptominers": "a3332629715ac00f022cff95ce29d9fe74a44267d71d0fc222d5ac5cc67b9332",
}
MISP_CATEGORIES = tuple(_MISP_PINS)

PINNED: dict[str, str] = {
    CTID_ATTACK_TO_CVE: "b1daf3ed8918838e55f0f424f67fdb343882622c06d7c1c67e8a92624b19eea9",
    CAPEC: "c56527f3d64b7164fcdae73c1a7545ee6e83b1150546c07a93339b1543a3041d",
    **{f"misp-galaxy/{category}.json": sha for category, sha in _MISP_PINS.items()},
}


# What a family -> category lookup needs. Everything else is dropped, notably ransomware
# notes (one holds a victim's portal login), leak-site links, prices, payment methods and
# suspected victims: this project publishes no victim data and no live (fanged) .onion URLs.
_MISP_CLUSTER_KEYS = ("authors", "category", "description", "name", "source", "type", "uuid")
_MISP_VALUE_KEYS = ("description", "related", "uuid", "value")
_MISP_META_KEYS = ("refs", "synonyms")


def trim_misp_cluster(raw: bytes) -> bytes:
    """A MISP galaxy cluster file reduced to names, synonyms, descriptions and links.

    Deterministic (sorted keys, fixed indent), and idempotent, so committed files can be
    checked to be exactly this function's output.
    """
    cluster = json.loads(raw)
    values = []
    for value in cluster["values"]:
        kept = {k: value[k] for k in _MISP_VALUE_KEYS if k in value}
        meta = {k: value["meta"][k] for k in _MISP_META_KEYS if k in value.get("meta", {})}
        if "refs" in meta:
            meta["refs"] = [r for r in meta["refs"] if not _onion(r)]
        if meta:
            kept["meta"] = meta
        values.append(kept)
    trimmed = {k: cluster[k] for k in _MISP_CLUSTER_KEYS if k in cluster}
    trimmed["values"] = sorted(values, key=lambda v: v["uuid"])
    return (json.dumps(trimmed, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def _onion(url: str) -> bool:
    """A Tor hidden service, directly or through a Tor2web gateway (``x.onion.foundation``)."""
    host = urlsplit(url).hostname or ""
    return host.endswith(".onion") or ".onion." in host


def read_pinned(data_dir: Path, name: str) -> bytes:
    """The bytes of a pinned reference file, after checking them against ``PINNED``."""
    path = data_dir / REFERENCE_DIR / name
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != PINNED[name]:
        raise ValueError(f"{path}: SHA-256 {digest} does not match the pinned {PINNED[name]}")
    return data
