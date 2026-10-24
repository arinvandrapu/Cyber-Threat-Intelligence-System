"""Core data model shared by every source."""

from __future__ import annotations

from datetime import datetime
from typing import Any

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
