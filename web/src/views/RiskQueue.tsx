import { useEffect, useMemo, useState } from "react";
import type { Data, RiskRow, ThreatLink, Tier } from "../types";
import { DivergingBar, PageHead, Pager, TierDot, TierName } from "../components/ui";
import { FEATURE_LABEL, TIER_LABEL, epss, int, signed } from "../format";
import { CveCard, LinkRow } from "./Threats";

const PAGE = 100;
const EVIDENCE: Record<string, string> = { exploitdb: "EDB", metasploit: "MSF", nuclei: "Nuclei" };
type SortKey = "rank" | "epss" | "age" | "cvss";
const SORTS: Record<SortKey, (a: RiskRow, b: RiskRow) => number> = {
  rank: (a, b) => a.rank - b.rank,
  epss: (a, b) => (b.epss_percentile ?? -1) - (a.epss_percentile ?? -1) || a.rank - b.rank,
  age: (a, b) => a.age_days - b.age_days || a.rank - b.rank,
  cvss: (a, b) => cvss(b) - cvss(a) || a.rank - b.rank,
};

function cvss(r: RiskRow): number {
  return r.context.cvss_nvd ?? r.context.cvss_cna ?? -1;
}

function ssvc(r: RiskRow): string {
  if (!r.ssvc_exploitation && !r.ssvc_automatable && !r.ssvc_technical_impact) return "not scored";
  return [r.ssvc_exploitation, r.ssvc_automatable, r.ssvc_technical_impact].map((v) => v ?? "?").join("/");
}

export function RiskQueue({ data, focus }: { data: Data; focus: string | null }) {
  const { risk, meta } = data;
  const [tier, setTier] = useState<Tier | "all">("all");
  const [query, setQuery] = useState("");
  const [evidenceOnly, setEvidenceOnly] = useState(false);
  const [sort, setSort] = useState<SortKey>("rank");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<string | null>(focus ?? risk.rows[0]?.cve ?? null);

  // CVE -> the threat families linked to it, with how each link was found and reviewed
  const threatsByCve = useMemo(() => {
    const m = new Map<string, { family: string; link: ThreatLink }[]>();
    for (const f of data.threats.families)
      for (const l of f.links)
        // a link reviewed as wrong is not evidence about this CVE
        if (l.review !== "rejected") m.set(l.cve, [...(m.get(l.cve) ?? []), { family: f.family, link: l }]);
    return m;
  }, [data.threats.families]);

  const counts = useMemo(() => {
    const c: Record<string, number> = { all: risk.rows.length };
    for (const r of risk.rows) c[r.tier] = (c[r.tier] ?? 0) + 1;
    return c;
  }, [risk.rows]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return risk.rows
      .filter((r) => tier === "all" || r.tier === tier)
      .filter((r) => !evidenceOnly || r.exploit_sources.length > 0)
      .filter(
        (r) =>
          !q ||
          r.cve.toLowerCase().includes(q) ||
          r.context.cwes.some((c) => c.toLowerCase().includes(q)) ||
          (r.context.assigner ?? "").toLowerCase().includes(q),
      )
      .sort(SORTS[sort]);
  }, [risk.rows, tier, query, evidenceOnly, sort]);

  // a CVE opened from another view: jump to its page
  useEffect(() => {
    if (!focus) return;
    setSelected(focus);
    setTier("all");
    setQuery("");
    setEvidenceOnly(false);
    setSort("rank");
    const i = risk.rows.findIndex((r) => r.cve === focus);
    setPage(i >= 0 ? Math.floor(i / PAGE) : 0);
  }, [focus, risk.rows]);

  const pages = Math.max(1, Math.ceil(rows.length / PAGE));
  const shown = rows.slice(page * PAGE, (page + 1) * PAGE);
  const detail = risk.rows.find((r) => r.cve === selected) ?? null;
  const notRanked = focus && !risk.rows.some((r) => r.cve === focus);
  const focusCard = focus ? data.threats.linked_cves.find((k) => k.cve === focus) : undefined;
  const reset = () => setPage(0);

  const header = (key: SortKey, text: string, className?: string) => (
    <th className={className} aria-sort={sort === key ? (key === "rank" || key === "age" ? "ascending" : "descending") : "none"}>
      <button type="button" className="sort" onClick={() => { setSort(key); reset(); }}>
        {text}{sort === key ? " ↓" : ""}
      </button>
    </th>
  );

  return (
    <>
      <PageHead
        title="Risk queue"
        lede={`${int(risk.rows.length)} CVEs in the critical, high and elevated tiers, best first. Grey columns are context only and were never model inputs.`}
      />
      {notRanked && focusCard && (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <p className="note">
            {focusCard.source === "kev"
              ? `${focus} is in CISA KEV: it is already confirmed exploited, so it is not ranked here. Patch KEV CVEs first.`
              : `${focus} is not ranked: it is outside the queue's window or below its tiers. A threat links to it; its NVD record is below.`}
          </p>
          <CveCard entry={focusCard} />
        </div>
      )}
      {notRanked && !focusCard && (
        <p className="note">
          {focus} is not in the ranked tiers: it is already in KEV, below the elevated tier, or published before the
          ranked window.
        </p>
      )}

      <section className="toolbar">
        {(["all", "critical", "high", "elevated"] as const).map((t) => (
          <button key={t} type="button" className="pill" aria-pressed={tier === t} onClick={() => { setTier(t); reset(); }}>
            {t === "all" ? <span className="dot" style={{ background: "var(--accent)" }} /> : <TierDot tier={t} />}
            {t === "all" ? "All tiers" : TIER_LABEL[t]}
            <span className="mono muted" style={{ fontSize: 12 }}>{int(counts[t] ?? 0)}</span>
          </button>
        ))}
        <div className="end">
          <label className="search">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--muted)" strokeWidth="2" aria-hidden="true">
              <circle cx="11" cy="11" r="7" /><path d="M20 20l-3.5-3.5" />
            </svg>
            <span className="sr-only">Search CVE, CWE or assigner</span>
            <input type="search" placeholder="CVE, CWE or assigner" value={query} onChange={(e) => { setQuery(e.target.value); reset(); }} />
          </label>
          <button type="button" className="pill" aria-pressed={evidenceOnly} onClick={() => { setEvidenceOnly(!evidenceOnly); reset(); }}>
            Exploit evidence only
          </button>
        </div>
      </section>

      <section className="row">
        <div className="panel grow" style={{ padding: 0, overflow: "hidden" }}>
          <div className="table-wrap">
            <table className="data compact">
              <thead>
                <tr className="label">
                  {header("rank", "Rank")}
                  <th>CVE</th>
                  <th>Tier</th>
                  {header("epss", "EPSS")}
                  <th title="CISA's SSVC assessment: exploitation status / automatable / technical impact">SSVC E / A / I</th>
                  <th>Exploit evidence</th>
                  {header("age", "Age")}
                  {header("cvss", "CVSS (NVD, else CNA)", "ctx")}
                  <th className="ctx">CWE</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((r) => (
                  <tr key={r.cve} className={r.cve === selected ? "selected" : undefined}>
                    <td className="mono muted">{r.rank}</td>
                    <td>
                      <button type="button" className="linkish" onClick={() => setSelected(r.cve)} aria-pressed={r.cve === selected}>
                        {r.cve}
                      </button>
                    </td>
                    <td><TierName tier={r.tier} /></td>
                    <td className="mono">{epss(r.epss, r.epss_percentile)}</td>
                    <td className="mono muted">{ssvc(r)}</td>
                    <td>{r.exploit_sources.map((s) => <span key={s} className="ev">{EVIDENCE[s] ?? s}</span>)}</td>
                    <td className="mono muted">{r.age_days} d</td>
                    <td className="mono ctx">{cvss(r) >= 0 ? cvss(r).toFixed(1) : "—"}</td>
                    <td className="mono ctx">{r.context.cwes.slice(0, 2).join(", ") || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {shown.length === 0 && <p className="empty">No CVEs match these filters.</p>}
          </div>
          <Pager page={page} pages={pages} total={rows.length} size={PAGE} onPage={setPage} />
        </div>

        <aside className="panel side" style={{ flexBasis: 330 }} aria-label="Selected CVE">
          {detail ? <Detail row={detail} threats={threatsByCve.get(detail.cve) ?? []} threatsBuilt={data.threats.available} epssVersion={meta.epss_model_versions.snapshot?.join(", ") ?? ""} snapshot={meta.snapshot_date} /> : <p className="muted">Select a CVE.</p>}
        </aside>
      </section>
    </>
  );
}

function Detail({
  row,
  threats,
  threatsBuilt,
  epssVersion,
  snapshot,
}: {
  row: RiskRow;
  threats: { family: string; link: ThreatLink }[];
  threatsBuilt: boolean;
  epssVersion: string;
  snapshot: string;
}) {
  const contrib = Object.entries(row.contributions).sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]));
  const max = Math.max(1, ...contrib.map(([, v]) => Math.abs(v)));
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        <span className="label">Rank {row.rank} · {TIER_LABEL[row.tier]}</span>
        <span className="mono" style={{ fontSize: 20, fontWeight: 600 }}>{row.cve}</span>
        {row.context.name && (
          <span style={{ fontSize: 14, color: "var(--text-2)", overflowWrap: "anywhere" }}>
            {row.context.name} <span className="faint" style={{ fontSize: 12 }}>(derived name)</span>
          </span>
        )}
        <span className="muted" style={{ fontSize: 13 }}>
          published {row.published} ({row.age_days} d before the snapshot)
        </span>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        <div className="panel-head" style={{ marginBottom: 0 }}>
          <h2 style={{ fontSize: 15 }}>What moved this CVE up or down</h2>
        </div>
        {contrib.map(([f, v]) => (
          <div key={f} className="bar-row">
            <span>{FEATURE_LABEL[f] ?? f}{row.imputed.includes(f) ? " †" : ""}</span>
            <DivergingBar value={v} max={max} />
            <span className="mono" style={{ textAlign: "right" }}>{signed(v)}</span>
          </div>
        ))}
        <span className="muted" style={{ fontSize: 12 }}>
          Each bar is how much one signal pushed this CVE's score up (blue) or down (grey), compared with an average
          CVE the model was trained on. Bars add up, in model score units (log-odds). † no value at the snapshot, so a
          typical (median) value was used.
        </span>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 6, borderTop: "1px solid var(--border)", paddingTop: 14 }}>
        <span className="label">Context (not used by the model)</span>
        {/* plain text only: descriptions are never rendered as HTML or linkified */}
        <p style={{ margin: 0, fontSize: 13.5, lineHeight: 1.5, color: "var(--text-2)", overflowWrap: "anywhere" }}>
          {row.context.description || "No description."}
        </p>
        <span className="mono muted" style={{ fontSize: 12.5 }}>
          CVSS {row.context.cvss_nvd ?? "—"} (NVD) · {row.context.cvss_cna ?? "—"} (CNA) ·{" "}
          {row.context.cwes.join(", ") || "no CWE"}
        </span>
        <span className="mono muted" style={{ fontSize: 12, overflowWrap: "anywhere" }}>assigner {row.context.assigner ?? "unknown"}</span>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8, borderTop: "1px solid var(--border)", paddingTop: 14 }}>
        <span className="label">Linked threats (not used by the model)</span>
        {!threatsBuilt && <span className="muted" style={{ fontSize: 13 }}>Threat catalog not built for this snapshot.</span>}
        {threatsBuilt && threats.length === 0 && (
          <span className="muted" style={{ fontSize: 13 }}>No malware family is linked to this CVE.</span>
        )}
        {threats.map(({ family, link }) => (
          <LinkRow key={`${family}-${link.via}`} link={link} label={family} />
        ))}
      </div>
      <div className="mono muted" style={{ fontSize: 12, borderTop: "1px solid var(--border)", paddingTop: 12 }}>
        EPSS {epss(row.epss, row.epss_percentile)} · model {epssVersion} · scored {snapshot}
      </div>
    </div>
  );
}
