import { useMemo, useState } from "react";
import type { Data, Tier } from "../types";
import { DivergingBar, PageHead, TierDot, useTooltip } from "../components/ui";
import { FEATURE_LABEL, TIERS, TIER_LABEL, epss, int, pct, signed } from "../format";
import { openCve } from "../App";

const W = 720, H = 420, L = 84, R = 16, T = 12, B = 52;
const PW = W - L - R, PH = H - T - B;
// x: EPSS percentile on a "nines" scale, so the crowded top end spreads out
const nines = (p: number) => -Math.log10(Math.max(1 - p, 1e-4)); // 0.5 -> 0.3, 0.99 -> 2
const X_MAX = 4;
const xs = (p: number) => L + (Math.min(nines(p), X_MAX) / X_MAX) * PW;
const X_TICKS: [number, string][] = [[0.5, "50th"], [0.9, "90th"], [0.99, "99th"], [0.999, "99.9th"]];

const SIGNALS: [string, string][] = [
  ["public_exploit", "Public exploit (EDB / MSF)"],
  ["nuclei_template", "Nuclei template"],
  ["ssvc_exploitation_poc_or_active", "SSVC exploitation: PoC or active"],
  ["ssvc_automatable", "SSVC automatable: yes"],
  ["ssvc_missing", "SSVC not yet scored"],
  ["epss_missing", "EPSS not scored"],
];

function heat(p: number): [string, string] {
  if (p >= 0.6) return ["#3987e5", "#0a0a0a"];
  if (p >= 0.3) return ["#1c5cab", "#ededed"];
  if (p >= 0.1) return ["#184f95", "#ededed"];
  if (p >= 0.02) return ["#16263b", "#d4d4d4"];
  return ["#1b1b1b", "#a3a3a3"];
}

export function RiskLandscape({ data }: { data: Data }) {
  const { risk } = data;
  const tip = useTooltip();
  const [hidden, setHidden] = useState<Set<Tier>>(new Set());
  const n = risk.ranked_cves;
  const yMin = Math.log10(1 / n), yMax = Math.log10(0.05);
  const ys = (rank: number) => T + ((Math.log10(rank / n) - yMin) / (yMax - yMin)) * PH;

  const points = useMemo(
    () =>
      risk.rows
        .map((r, i) => ({ i, r })) // index into risk.rows before filtering (tooltip lookup)
        .filter(({ r }) => r.epss_percentile !== null)
        .map(({ i, r }) => ({ i, r, x: xs(r.epss_percentile!), y: ys(r.rank) }))
        .reverse(), // critical drawn last, on top
    [risk.rows, n],
  );
  const shown = points.filter((p) => !hidden.has(p.r.tier));
  const coefMax = Math.max(...risk.coefficients.flatMap((c) => [Math.abs(c.refit), Math.abs(c.evaluated_last_fold)]));
  const months = Object.entries(risk.published_by_month).slice(-18);
  const monthMax = Math.max(1, ...months.map(([, c]) => (c.critical ?? 0) + (c.high ?? 0)));
  const coverageTiers = TIERS;

  const toggle = (t: Tier) => {
    const next = new Set(hidden);
    if (next.has(t)) next.delete(t);
    else next.add(t);
    setHidden(next);
  };

  return (
    <>
      <PageHead
        title="Risk landscape"
        lede="Where the model agrees with EPSS, where it doesn't, and what the top tiers are made of."
      />
      {tip.node}
      <section className="row">
        <figure className="panel grow" style={{ margin: 0 }}>
          <div className="panel-head">
            <h2>Model rank vs EPSS percentile</h2>
            <div className="toolbar">
              {(["critical", "high", "elevated"] as Tier[]).map((t) => (
                <button key={t} type="button" className="pill" aria-pressed={!hidden.has(t)} onClick={() => toggle(t)}>
                  <TierDot tier={t} />{TIER_LABEL[t]}
                </button>
              ))}
            </div>
          </div>
          <svg
            className="chart"
            viewBox={`0 0 ${W} ${H}`}
            role="img"
            aria-label="Scatter of each tiered CVE's model rank against its EPSS percentile, coloured by tier"
            onMouseMove={(e) => {
              const i = (e.target as SVGElement).dataset?.i;
              const p = i !== undefined ? risk.rows[Number(i)] : undefined;
              if (p) tip.show(e, <><b className="mono">{p.cve}</b><br />rank {p.rank} · {TIER_LABEL[p.tier]}<br />EPSS {epss(p.epss, p.epss_percentile)}</>);
              else tip.hide();
            }}
            onMouseLeave={tip.hide}
            onClick={(e) => {
              const i = (e.target as SVGElement).dataset?.i;
              const p = i !== undefined ? risk.rows[Number(i)] : undefined;
              if (p) openCve(p.cve);
            }}
          >
            <rect x={L} y={T} width={PW} height={PH} fill="var(--bar)" />
            {[1e-3, 1e-2, 5e-2].map((f) => {
              const y = T + ((Math.log10(f) - yMin) / (yMax - yMin)) * PH;
              return (
                <g key={f}>
                  <line x1={L} x2={L + PW} y1={y} y2={y} stroke="var(--border)" />
                  <text className="ax" x={L - 8} y={y + 4} textAnchor="end">top {f * 100}%</text>
                </g>
              );
            })}
            <text className="ax" x={L - 8} y={T + 10} textAnchor="end">#1</text>
            {X_TICKS.map(([p, label]) => (
              <g key={label}>
                <line x1={xs(p)} x2={xs(p)} y1={T} y2={T + PH} stroke="var(--grid)" />
                <text className="ax" x={xs(p)} y={T + PH + 16} textAnchor="middle">{label}</text>
              </g>
            ))}
            <text className="ax-title" x={L + PW / 2} y={H - 10} textAnchor="middle">EPSS percentile at the snapshot →</text>
            <text className="ax-title" x={12} y={T + PH / 2} textAnchor="middle" transform={`rotate(-90 12 ${T + PH / 2})`}>
              model rank (log) ↑ better
            </text>
            {shown.map((p) => (
              <circle key={p.r.cve} className="hit" data-i={p.i} cx={p.x} cy={p.y} r={p.r.tier === "critical" ? 4.5 : 3}
                fill={`var(--${p.r.tier})`} stroke="var(--bar)" strokeWidth="1" />
            ))}
          </svg>
          <figcaption className="caption">
            Each point is one tiered CVE ({int(points.length)} with an EPSS score). Points high on the chart but toward
            the left are CVEs the model ranks well above where EPSS alone would. Hover for details; click to open in the
            risk queue.
          </figcaption>
        </figure>

        <figure className="panel side" style={{ margin: 0 }}>
          <div className="panel-head"><h2>What drives the model</h2></div>
          <div className="legend" style={{ marginBottom: 8 }}>
            <span>
              How much each signal counts (bar); last tested version in brackets
            </span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {[...risk.coefficients].sort((a, b) => Math.abs(b.refit) - Math.abs(a.refit)).map((c) => (
              <div key={c.feature} className="bar-row" style={{ gridTemplateColumns: "128px 1fr 118px" }}>
                <span>{FEATURE_LABEL[c.feature] ?? c.feature}</span>
                <DivergingBar value={c.refit} max={coefMax} />
                <span className="mono" style={{ textAlign: "right" }}>
                  {signed(c.refit)} <span className="faint">({signed(c.evaluated_last_fold)})</span>
                </span>
              </div>
            ))}
          </div>
          <figcaption className="caption">
            Negative age weight = newer CVEs rank higher. Weights describe correlated signals, not causes. Refit on{" "}
            {int(risk.training_rows)} CVE-windows with {Object.values(risk.training_positives).reduce((a, b) => a + b, 0)} KEV
            additions.
          </figcaption>
        </figure>
      </section>

      <section className="row">
        <figure className="panel grow" style={{ margin: 0, flexBasis: 520 }}>
          <div className="panel-head"><h2>Signal coverage by tier</h2></div>
          <div className="table-wrap">
            <table className="heat">
              <thead>
                <tr className="label">
                  <th style={{ textAlign: "left" }}>Share of the tier's CVEs with…</th>
                  {coverageTiers.map((t) => <th key={t}><TierDot tier={t} />{TIER_LABEL[t]}</th>)}
                </tr>
              </thead>
              <tbody>
                {SIGNALS.filter(([k]) => risk.signal_coverage[k]).map(([k, label]) => (
                  <tr key={k}>
                    <td className="name">{label}</td>
                    {coverageTiers.map((t) => {
                      const v = risk.signal_coverage[k]![t] ?? 0;
                      const [bg, fg] = heat(v);
                      return <td key={t} style={{ background: bg, color: fg }}>{pct(v, 0)}</td>;
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <figcaption className="caption">Share of all CVEs in the tier, missing values counted as "no".</figcaption>
        </figure>

        <figure className="panel grow" style={{ margin: 0, flexBasis: 520 }}>
          <div className="panel-head">
            <h2>Critical + high CVEs by publication month</h2>
            <div className="legend">
              <span><TierDot tier="critical" />Critical</span>
              <span><TierDot tier="high" />High</span>
            </div>
          </div>
          <MonthBars months={months} max={monthMax} onHover={tip.show} onLeave={tip.hide} />
          <figcaption className="caption">
            Last 18 months; the latest month is partial (snapshot {risk.snapshot_date}). The newest month dominates:
            the model gives recent CVEs a large weight (see the disclosures).
          </figcaption>
        </figure>
      </section>
    </>
  );
}

function MonthBars({
  months,
  max,
  onHover,
  onLeave,
}: {
  months: [string, Partial<Record<Tier, number>>][];
  max: number;
  onHover: (e: React.MouseEvent, text: React.ReactNode) => void;
  onLeave: () => void;
}) {
  const w = 560, h = 240, l = 44, b = 34, t = 10;
  const ph = h - b - t;
  const bw = Math.max(6, (w - l - 10) / Math.max(months.length, 1) - 6);
  const scale = (v: number) => (v / max) * ph;
  const ticks = [0, Math.round(max / 2), max];
  return (
    <svg className="chart" viewBox={`0 0 ${w} ${h}`} role="img" aria-label="Monthly counts of critical and high tier CVEs" onMouseLeave={onLeave}>
      {ticks.map((v) => (
        <g key={v}>
          <line x1={l} x2={w - 4} y1={t + ph - scale(v)} y2={t + ph - scale(v)} stroke={v === 0 ? "var(--border-2)" : "var(--grid)"} />
          <text className="ax" x={l - 6} y={t + ph - scale(v) + 4} textAnchor="end">{v}</text>
        </g>
      ))}
      {months.map(([m, c], i) => {
        const crit = c.critical ?? 0, high = c.high ?? 0;
        const x = l + 6 + i * (bw + 6);
        const hc = scale(crit), hh = scale(high);
        return (
          <g key={m} onMouseMove={(e) => onHover(e, <><b>{m}</b><br />critical {crit} · high {high}</>)}>
            <rect x={x} y={t} width={bw} height={ph} fill="transparent" />
            {high > 0 && <rect x={x} y={t + ph - hc - hh} width={bw} height={Math.max(hh - (crit ? 2 : 0), 1)} rx="2" fill="var(--high)" />}
            {crit > 0 && <rect x={x} y={t + ph - hc} width={bw} height={hc} fill="var(--critical)" />}
            {(i % 3 === 0 || i === months.length - 1) && (
              <text className="ax" x={x + bw / 2} y={h - 12} textAnchor="middle">{m.slice(2)}</text>
            )}
          </g>
        );
      })}
    </svg>
  );
}
