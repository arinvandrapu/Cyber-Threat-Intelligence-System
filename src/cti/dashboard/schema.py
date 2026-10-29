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


# ---- threats.json ----------------------------------------------------------------------------
# From `cti threats` (Phase 10a), copied by explicit key. Aggregates only (abuse.ch terms):
# family names and counts, never an IOC value, URL or evidence document.


class TechniqueRef(_Model):
    id: str
    name: str


class ThreatLink(_Model):
    cve: str
    via: Literal["threatfox_tag", "mention:reference_page"]
    surface: list[str]  # the names matched on the evidence page (empty for a tag)
    review: Literal["correct", "rejected", "unreviewed"]
    counts_for_priority: bool
    in_kev: bool
    tier: Tier | None  # the CVE's tier in this export's risk queue; None if not queued


class ThreatFamily(_Model):
    rank: int
    family: str
    categories: list[str]
    category_source: Literal["owner", "misp", "none"]
    attack_software: str | None  # ATT&CK software ID (S####)
    attack_name: str | None
    techniques: list[TechniqueRef]
    tactics: list[str]
    links: list[ThreatLink]
    linked_kev_cves: int
    linked_high_tier_cves: int
    ioc_rows: int
    ioc_growth: int  # last 30 days minus the 30 before
    why: list[str]


class KevEntry(_Model):
    """A KEV CVE linked to a shown family. KEV CVEs are never in the risk queue (already
    confirmed exploited), so this is their only detail in the dashboard."""

    cve: str
    name: str  # CISA's vulnerabilityName
    vendor: str
    product: str
    description: str  # CISA's short description, defanged and truncated
    date_added: str
    due_date: str | None
    ransomware_use: str  # "Known" | "Unknown" (CISA's field)
    cwes: list[str]
    families: list[str]  # shown families linking to it (links not reviewed as wrong)


class CategoryCount(_Model):
    category: str
    ioc_rows: int  # overlapping: a multi-category family counts in each


class ThreatReview(_Model):
    labeller: str
    hand_labelled_families: int
    links_reviewed: int
    links_correct: int
    link_precision_ci95: Interval | None


class Threats(_Model):
    available: bool  # False when `cti threats` has not run for this snapshot
    snapshot_date: str | None
    families_total: int
    families: list[ThreatFamily]  # hand-checked priority top N, plus families with a link
    # that was not reviewed as wrong
    categories: list[CategoryCount]
    kev_ransomware_cves: int  # KEV entries with known ransomware use (category-level link)
    kev: list[KevEntry]
    review: ThreatReview | None


FILES: dict[str, type[_Model]] = {
    "meta.json": Meta,
    "risk.json": Risk,
    "iocs.json": Iocs,
    "graphs.json": Graphs,
    "eval.json": Eval,
    "threats.json": Threats,
}
