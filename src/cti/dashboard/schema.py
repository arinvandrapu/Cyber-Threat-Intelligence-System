"""The JSON contract between ``cti export`` and the dashboard (``web/src/types.ts`` mirrors it).

Every file is validated against these models before it is written, so a bad export fails in
Python instead of rendering wrong numbers. ``extra="forbid"`` everywhere: a field the
dashboard doesn't know about is an error, not silently shipped.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA = 1
Tier = Literal["critical", "high", "elevated", "baseline"]
Interval = tuple[float, float]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# ---- meta.json -------------------------------------------------------------------------------


class Meta(_Model):
    schema_version: Literal[1] = SCHEMA
    snapshot_date: str
    as_of_dates: dict[str, str]
    kev_catalog_version: str
    epss_model_versions: dict[str, list[str]]  # as_of -> EPSS model versions seen
    git: dict[str, str | bool | None]
    config_sha256: str
    inputs_sha256: dict[str, str]
    disclosures: list[str]


# ---- risk.json -------------------------------------------------------------------------------


class Context(_Model):
    """Shown for orientation only. None of it is a model input (label-biased, snapshot-time)."""

    cvss_nvd: float | None
    cvss_cna: float | None
    cwes: list[str]
    assigner: str | None
    description: str  # spans the IOC extractor recognises defanged, then truncated; plain text


class RiskRow(_Model):
    rank: float  # 1-based, best first; ties share their average rank
    cve: str
    tier: Tier
    published: str
    epss: float | None
    epss_percentile: float | None
    ssvc_exploitation: str | None
    ssvc_automatable: str | None
    ssvc_technical_impact: str | None
    exploit_sources: list[str]
    age_days: int
    # feature -> coefficient x standardized value: log-odds vs the training mean, no intercept
    contributions: dict[str, float]
    imputed: list[str]  # features whose value was missing (training median used)
    context: Context


class TierCount(_Model):
    name: Tier
    max_rank_fraction: float
    cves: int


class HistoricalTier(_Model):
    """Hit rate of this procedure's tier over the next 180 days, pooled over the test folds."""

    name: Tier
    cves: int
    kev_positives: int
    hit_rate: float
    wilson95: Interval


class Coefficient(_Model):
    feature: str
    refit: float  # all four labelled windows (the model ranking the snapshot)
    evaluated_last_fold: float  # from risk-eval.json, for comparison


class Risk(_Model):
    snapshot_date: str
    ranked_cves: int
    tiers: list[TierCount]
    rows: list[RiskRow]  # critical, high and elevated only
    coefficients: list[Coefficient]
    intercept: float
    training_positives: dict[str, int]  # window -> KEV additions used as positives
    training_rows: int
    iterations: int
    historical_tiers: list[HistoricalTier]
    signal_coverage: dict[str, dict[str, float]]  # signal -> tier -> share of CVEs
    published_by_month: dict[str, dict[str, int]]  # YYYY-MM -> tier -> count (critical/high)


# ---- iocs.json -------------------------------------------------------------------------------


class Indicator(_Model):
    type: str
    value: str  # defanged for network types
    cves: list[str]  # first 10, sorted
    cve_count: int
    occurrences: int
    public: bool | None  # IPs only


class FeedAggregate(_Model):
    records: int
    by_type: dict[str, int]
    by_threat: dict[str, int]
    by_month: dict[str, int]
    top_families: list[tuple[str, int]] = Field(default_factory=list)  # ThreatFox only


class Iocs(_Model):
    title: str
    reference_pages: int
    by_type: dict[str, int]  # unique values per type, reference-page origin
    nvd_description_counts: dict[str, int]  # occurrences per type (no identifiers); no values
    indicators: list[Indicator]
    feeds: dict[str, FeedAggregate]


# ---- graphs.json -----------------------------------------------------------------------------


class GraphNode(_Model):
    id: str
    label: str
    kind: str  # pillar | cwe | cve | technique | tactic | host
    tier: Tier | None = None
    in_kev: bool | None = None  # CVE nodes: already in KEV at the snapshot (never ranked)
    count: int = 0  # distinct CVEs under the node (techniques, for a tactic)


class GraphEdge(_Model):
    source: str
    target: str
    weight: int = 1


class Graph(_Model):
    description: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    truncated: bool


class Graphs(_Model):
    weakness: Graph
    attack: dict[str, Graph]  # mapping type -> graph
    shared_hosts: Graph


# ---- eval.json -------------------------------------------------------------------------------


class Eval(_Model):
    """Copied by explicit key path from the evaluation files (``export.build_eval``), with
    no recomputation. The inner dicts are opaque here: their shape is the eval files'."""

    risk: dict
    attack: dict
    cwe: dict
    extract: dict
    ner: dict
    sources_sha256: dict[str, str]


FILES: dict[str, type[_Model]] = {
    "meta.json": Meta,
    "risk.json": Risk,
    "iocs.json": Iocs,
    "graphs.json": Graphs,
    "eval.json": Eval,
}
