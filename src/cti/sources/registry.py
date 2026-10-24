"""All sources in ingest order."""

from __future__ import annotations

from cti.config import Settings
from cti.sources.abusech import ThreatFoxSource, URLhausSource
from cti.sources.attack import AttackSource
from cti.sources.base import Source
from cti.sources.cwe import CWESource
from cti.sources.epss import EPSSSource
from cti.sources.exploitdb import ExploitDBSource
from cti.sources.kev import KEVSource
from cti.sources.metasploit import MetasploitSource
from cti.sources.nuclei import NucleiSource
from cti.sources.nvd import NVDSource
from cti.sources.vulnrichment import VulnrichmentSource

SOURCE_CLASSES: tuple[type[Source], ...] = (
    KEVSource,
    EPSSSource,
    NVDSource,
    ExploitDBSource,
    MetasploitSource,
    NucleiSource,
    VulnrichmentSource,
    AttackSource,
    CWESource,
    ThreatFoxSource,
    URLhausSource,
)


def all_sources(settings: Settings) -> list[Source]:
    return [cls(settings) for cls in SOURCE_CLASSES]


def select(settings: Settings, names: list[str] | None) -> list[Source]:
    sources = all_sources(settings)
    if not names:
        return sources
    known = {s.name: s for s in sources}
    unknown = sorted(set(names) - known.keys())
    if unknown:
        raise ValueError(f"unknown sources: {', '.join(unknown)}; known: {', '.join(known)}")
    return [known[n] for n in names]
