import type { Data } from "../types";
import { cveHref } from "../App";
import { PageHead, TierDot, TierName, IntervalBar } from "../components/ui";
import { TIER_BAND, TIERS, epss, int, pct, interval, wilson, FEATURE_LABEL } from "../format";

const logScale = (v: number) => (Math.log10(Math.max(v, 1e-4)) + 4) / 3; // 0.01% .. 10%

export function Overview({ data }: { data: Data }) {
  const { meta, risk, iocs, evals } = data;
  const counts = Object.fromEntries(risk.tiers.map((t) => [t.name, t.cves]));
  const hist = Object.fromEntries(risk.historical_tiers.map((t) => [t.name, t]));
  const decision = evals.risk.decision["logistic_minus_epss_hits@100"];
  const paired = typeof decision === "object" ? decision : null;
  const positives = evals.risk.methods.logistic?.pooled.positives ?? 0;
  const critical = hist.critical;
  const top = risk.rows.slice(0, 5);
  const uniqueIndicators = Object.values(iocs.by_type).reduce((a, b) => a + b, 0);

  return (
    <>
      <PageHead
        title="Which unlisted CVEs are most likely to be exploited next?"
        lede={
          <>
            CVEs not yet in CISA KEV, ranked by the pre-registered model using only what was known on{" "}
            {meta.snapshot_date}. Rank and tier only: the model's raw output is not a probability.
          </>
        }
      >
        <a href="#/queue" className="pill" style={{ background: "var(--accent)", color: "#0a0a0a", fontWeight: 600, textDecoration: "none" }}>
          Open risk queue
        </a>
      </PageHead>

      <section className="grid tiles">
        <div className="panel tile">
          <span className="label">CVEs ranked</span>
          <span className="value">{int(risk.ranked_cves)}</span>
          <span className="muted">eligible at snapshot · KEV excluded</span>
        </div>
        <div className="panel tile">
          <span className="label">Critical tier</span>
          <span className="value">{int(counts.critical ?? 0)}</span>
          <span className="muted">top 0.1% by rank</span>
        </div>
        <div className="panel tile">
          <span className="label">Model vs EPSS · top 100</span>
          <span className="value">{paired ? `${paired.difference_hits >= 0 ? "+" : ""}${paired.difference_hits} hits` : "—"}</span>
          <span className="muted">
            {paired ? `95% CI ${paired.ci95[0]} to ${paired.ci95[1]} · ${positives} KEV additions, 3 test folds` : ""}
          </span>
        </div>
        <div className="panel tile">
          <span className="label">Indicator strings</span>
          <span className="value">{int(uniqueIndicators)}</span>
          <span className="muted">unique, defanged · not vetted as malicious</span>
        </div>
      </section>

      <section className="row">
        <div className="panel grow">
          <div className="panel-head">
            <h2>Risk tiers</h2>
            <span className="muted" style={{ fontSize: 12.5 }}>
              Historical KEV rate: same procedure, rolling-origin test folds, next 180 days
            </span>
          </div>
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr className="label">
                  <th>Tier</th>
                  <th>Rank band</th>
                  <th className="num">CVEs now</th>
                  <th style={{ paddingLeft: 24 }}>Historical KEV rate (95% CI)</th>
                </tr>
              </thead>
              <tbody>
                {TIERS.map((t) => {
                  const h = hist[t];
                  return (
                    <tr key={t}>
                      <td><TierName tier={t} /></td>
                      <td className="mono muted">{TIER_BAND[t]}</td>
                      <td className="num">{int(counts[t] ?? 0)}</td>
                      <td style={{ paddingLeft: 24 }}>
                        {h && (
                          <span style={{ display: "inline-flex", alignItems: "center", gap: 10 }}>
                            <IntervalBar value={h.kev_positives / h.cves} ci={wilson(h.kev_positives, h.cves)} color={`var(--${t})`} scale={logScale} />
                            <span className="mono">{pct(h.kev_positives / h.cves)}</span>
                            <span className="mono muted" style={{ fontSize: 12.5 }}>{interval(wilson(h.kev_positives, h.cves))}</span>
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {critical && hist.baseline && (
            <p className="note" style={{ marginTop: 14 }}>
              Read this as a triage order, not a forecast: about {pct(1 - critical.hit_rate, 0)} of critical-tier
              CVEs did <strong>not</strong> enter KEV within 180 days. The critical tier's rate is still about{" "}
              {int(critical.kev_positives / critical.cves / (hist.baseline.kev_positives / hist.baseline.cves))}× the
              baseline tier's. Log scale.
            </p>
          )}
        </div>

        <div className="panel side">
          <div className="panel-head"><h2>Top of the queue</h2></div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {top.map((r) => {
              const driver = Object.entries(r.contributions).sort((a, b) => b[1] - a[1])[0];
              return (
                <a key={r.cve} href={cveHref(r.cve)} style={{ textDecoration: "none", color: "var(--text)", display: "grid", gridTemplateColumns: "26px 1fr", gap: "2px 8px", padding: "10px 12px", borderRadius: 8, background: "var(--raised)" }}>
                  <span className="mono muted" style={{ fontSize: 12.5 }}>{r.rank}</span>
                  <span className="mono" style={{ fontSize: 13.5, whiteSpace: "nowrap" }}><TierDot tier={r.tier} />{r.cve}</span>
                  <span />
                  <span className="muted" style={{ fontSize: 12.5 }}>
                    top driver: {driver ? FEATURE_LABEL[driver[0]] : "—"} · EPSS {epss(r.epss, r.epss_percentile)}
                  </span>
                </a>
              );
            })}
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Data &amp; disclosures</h2>
          <span className="mono muted" style={{ fontSize: 12 }}>
            commit {String(meta.git.commit ?? "unknown").slice(0, 7)}
            {meta.git.dirty ? " (uncommitted changes)" : ""} · config sha256 {meta.config_sha256.slice(0, 8)}… ·
            KEV {meta.kev_catalog_version}
          </span>
        </div>
        <ul className="plain">
          {meta.disclosures.map((d) => <li key={d}>{d}</li>)}
        </ul>
        <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", marginTop: 16 }}>
          {Object.entries(meta.epss_model_versions).map(([asOf, versions]) => (
            <div key={asOf} style={{ border: "1px solid var(--border)", borderRadius: 8, padding: "10px 12px" }}>
              <div style={{ fontSize: 13.5, fontWeight: 550 }}>EPSS at {asOf} ({meta.as_of_dates[asOf]})</div>
              <div className="mono muted" style={{ fontSize: 12 }}>{versions.join(", ")}</div>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}
