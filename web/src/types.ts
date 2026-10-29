// The JSON contract written by `cti export`. Mirrors src/cti/dashboard/schema.py; a pytest
// (tests/unit/test_web_contract.py) fails if a field exists there but not here.

export type Tier = "critical" | "high" | "elevated" | "baseline";
export type Interval = [number, number];

// ---- meta.json ----

export interface Meta {
  schema_version: 1;
  snapshot_date: string;
  as_of_dates: Record<string, string>;
  kev_catalog_version: string;
  epss_model_versions: Record<string, string[]>;
  git: Record<string, string | boolean | null>;
  config_sha256: string;
  inputs_sha256: Record<string, string>;
  disclosures: string[];
}

// ---- risk.json ----

export interface Context {
  cvss_nvd: number | null;
  cvss_cna: number | null;
  cwes: string[];
  assigner: string | null;
  description: string; // plain text only: never rendered as HTML or linkified
}

export interface RiskRow {
  rank: number;
  cve: string;
  tier: Tier;
  published: string;
  epss: number | null;
  epss_percentile: number | null;
  ssvc_exploitation: string | null;
  ssvc_automatable: string | null;
  ssvc_technical_impact: string | null;
  exploit_sources: string[];
  age_days: number;
  contributions: Record<string, number>;
  imputed: string[];
  context: Context;
}

export interface TierCount {
  name: Tier;
  max_rank_fraction: number;
  cves: number;
}

export interface HistoricalTier {
  name: Tier;
  cves: number;
  kev_positives: number;
  hit_rate: number;
  wilson95: Interval;
}

export interface Coefficient {
  feature: string;
  refit: number;
  evaluated_last_fold: number;
}

export interface Risk {
  snapshot_date: string;
  ranked_cves: number;
  tiers: TierCount[];
  rows: RiskRow[];
  coefficients: Coefficient[];
  intercept: number;
  training_positives: Record<string, number>;
  training_rows: number;
  iterations: number;
  historical_tiers: HistoricalTier[];
  signal_coverage: Record<string, Record<Tier, number>>;
  published_by_month: Record<string, Partial<Record<Tier, number>>>;
}

// ---- iocs.json ----

export interface Indicator {
  type: string;
  value: string;
  cves: string[];
  cve_count: number;
  occurrences: number;
  public: boolean | null;
}

export interface FeedAggregate {
  records: number;
  by_type: Record<string, number>;
  by_threat: Record<string, number>;
  by_month: Record<string, number>;
  top_families: [string, number][];
}

export interface Iocs {
  title: string;
  reference_pages: number;
  by_type: Record<string, number>;
  nvd_description_counts: Record<string, number>;
  indicators: Indicator[];
  feeds: Record<string, FeedAggregate>;
}

// ---- graphs.json ----

export interface GraphNode {
  id: string;
  label: string;
  kind: "pillar" | "cwe" | "cve" | "technique" | "tactic" | "host";
  tier?: Tier | null;
  in_kev?: boolean | null;
  count?: number;
}

export interface GraphEdge {
  source: string;
  target: string;
  weight: number;
}

export interface Graph {
  description: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  truncated: boolean;
}

export interface Graphs {
  weakness: Graph;
  attack: Record<string, Graph>;
  shared_hosts: Graph;
}

// ---- eval.json (shapes set by export.build_eval) ----

export interface Metric {
  value: number;
  ci95: Interval;
}

export interface RiskPooled {
  positives: number;
  "hits@100": number;
  "recall@100": number;
  "recall@100_wilson95": Interval;
  "hits@1%": number;
  "recall@1%": number;
  "recall@1%_wilson95": Interval;
  mean_average_precision: number;
}

export interface RiskFold {
  n: number;
  positives: number;
  "hits@100": number;
  "hits@1%": number;
  average_precision: number;
}

export interface Paired {
  difference_hits: number;
  ci95: Interval;
  excludes_zero: boolean;
}

export interface FoldInfo {
  cutoff: string;
  window_end: string;
  eligible: number;
  positives: number;
}

export interface Eval {
  risk: {
    headline: string;
    decision: { rule: string; verdict: string } & Record<string, Paired | string>;
    secondary_paired: Record<string, Paired>;
    random_expected: Record<string, number>;
    folds: Record<string, FoldInfo>;
    tiers: { monotonic: boolean; tiers: Record<Tier, Omit<HistoricalTier, "name">> };
    methods: Record<string, { pooled: RiskPooled; per_fold: Record<string, RiskFold> }>;
  };
  attack: {
    primary: { mapping_type: string; split: string; variant: string };
    splits: Record<string, number>;
    test_nvd: Record<
      string,
      Record<string, { cves: number; "hit@1": Metric; "hit@5": Metric; mrr: Metric }>
    >;
  };
  cwe: {
    headline: string;
    classes: number;
    test: Record<
      string,
      Record<
        string,
        { n: number; macro_f1: number; macro_f1_ci95: Interval; accuracy: number; top5: number }
      >
    >;
  };
  extract: {
    overall_including_identifiers: PrecisionCell;
    per_type: Record<string, PrecisionCell>;
    per_origin: Record<string, PrecisionCell>;
  };
  ner: {
    model: Record<string, string>;
    exact: Record<string, NerCell>;
    overlap: Record<string, NerCell>;
  };
  sources_sha256: Record<string, string>;
}

export interface PrecisionCell {
  precision: number;
  ci95: Interval;
  labelled: number;
  population: number;
}

export interface NerCell {
  f1: number;
  precision: number;
  recall: number;
  gold: number;
  predicted: number;
}

export interface TechniqueRef {
  id: string;
  name: string;
}

export interface ThreatLink {
  cve: string;
  via: "threatfox_tag" | "mention:reference_page";
  surface: string[];
  review: "correct" | "rejected" | "unreviewed";
  counts_for_priority: boolean;
  in_kev: boolean;
  tier: Tier | null;
}

export interface ThreatFamily {
  rank: number;
  family: string;
  categories: string[];
  category_source: "owner" | "misp" | "none";
  attack_software: string | null;
  attack_name: string | null;
  techniques: TechniqueRef[];
  tactics: string[];
  links: ThreatLink[];
  linked_kev_cves: number;
  linked_high_tier_cves: number;
  ioc_rows: number;
  ioc_growth: number;
  why: string[];
}

export interface KevEntry {
  cve: string;
  name: string;
  vendor: string;
  product: string;
  description: string;
  date_added: string;
  due_date: string | null;
  ransomware_use: string;
  cwes: string[];
  families: string[];
}

export interface CategoryCount {
  category: string;
  ioc_rows: number;
}

export interface ThreatReview {
  labeller: string;
  hand_labelled_families: number;
  links_reviewed: number;
  links_correct: number;
  link_precision_ci95: Interval | null;
}

export interface Threats {
  available: boolean;
  snapshot_date: string | null;
  families_total: number;
  families: ThreatFamily[];
  categories: CategoryCount[];
  kev_ransomware_cves: number;
  kev: KevEntry[];
  review: ThreatReview | null;
}

export interface Data {
  meta: Meta;
  risk: Risk;
  iocs: Iocs;
  graphs: Graphs;
  evals: Eval;
  threats: Threats;
}
