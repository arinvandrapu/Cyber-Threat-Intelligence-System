"""Core data model shared by every source."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Document(BaseModel):
    """One normalized record from any source (a CVE, an IOC, an exploit, ...)."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(description="Stable ID: '<source>:<source_id>'")
    source: str
    source_id: str
    title: str
    text: str = ""
    url: str | None = None
    published: datetime | None = None
    modified: datetime | None = None
    cves: tuple[str, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def make_id(cls, source: str, source_id: str) -> str:
        return f"{source}:{source_id}"


AsOf = Literal["cutoff", "snapshot"]


class CveSignal(BaseModel):
    """A per-CVE signal (EPSS score, SSVC decision, exploit module, ...) at a point in time.

    ``as_of="cutoff"`` values are what was known at the evaluation cutoff date and are the
    only ones allowed as features in the forward-looking risk evaluation.
    """

    model_config = ConfigDict(frozen=True)

    cve: str
    source: str
    as_of: AsOf
    values: dict[str, Any] = Field(default_factory=dict)
