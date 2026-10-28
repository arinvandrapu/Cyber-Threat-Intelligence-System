import { useState } from "react";
import type { Data } from "../types";
import { IntervalBar, PageHead, Seg, TierName, useTooltip } from "../components/ui";
import { TIERS, hits, int, interval, pct, wilson } from "../format";

const METHODS: [string, string, string][] = [
  ["logistic", "Logistic (headline)", "var(--model)"],
  ["boosting", "Boosting (challenger)", "var(--boosting)"],
  ["epss", "EPSS", "var(--epss)"],
  ["ssvc_rule", "SSVC rule", "var(--faint)"],
  ["cvss_cna", "CVSS (snapshot) †", "var(--other)"],
];
type Budget = "100" | "1%";
const logScale = (v: number) => (Math.log10(Math.max(v, 1e-4)) + 4) / 3;

export function Evaluation({ data }: { data: Data }) {
  const ev = data.evals;
  const r = ev.risk;
  const [budget, setBudget] = useState<Budget>("100");
  const tip = useTooltip();
  const d = r.decision["logistic_minus_epss_hits@100"];
  const decision = typeof d === "object" ? d : null;
  const at1 = r.secondary_paired["logistic_minus_epss_hits@1%"];
  const positives = r.methods.logistic?.pooled.positives ?? 0;
  const eligible = Object.values(r.folds).reduce((s, f) => s + f.eligible, 0);
  const folds = Object.entries(r.folds).sort((a, b) => a[1].cutoff.localeCompare(b[1].cutoff));
  const key = budget === "100" ? "recall@100" : "recall@1%";
  const hitKey = budget === "100" ? "hits@100" : "hits@1%";
  const rows = METHODS.filter(([m]) => r.methods[m]).map(([m, label, color]) => {
    const p = r.methods[m]!.pooled;
    return { m, label, color, value: p[key], ci: p[`${key}_wilson95`], hits: p[hitKey] };
  });
  const random = r.random_expected[key] ?? 0;
  const xMax = Math.max(0.05, ...rows.map((x) => x.ci[1])) * 1.1;
  const W = 700, L = 190, PW = 440, rowH = 44;
  const xs = (v: number) => L + (v / xMax) * PW;
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => f * xMax);
  const att = ev.attack.test_nvd;
  const cweTf = ev.cwe.test.tfidf?.name_absent, cweEmb = ev.cwe.test.embedding?.name_absent;
  const refPrec = ev.extract.per_origin.reference_page;

  return (
    <>
      <PageHead
        title="Evaluation"
        lede={`Forward-looking test: score CVEs with only what was known at a cutoff, then check which ones CISA added to KEV in the next 180 days (the last window, 177). ${folds.length} rolling-origin test folds, ${positives} KEV additions. Every choice was committed before any test score.`}
      />
      {tip.node}
      {decision && (
        <section className="panel banner">
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="2" aria-hidden="true">
              <circle cx="12" cy="12" r="9" />{decision.excludes_zero ? <path d="M8 12.5l2.8 2.8L16 10" /> : <path d="M8 12h8" />}
            </svg>
            <div>
              <div className="label">Pre-registered decision rule</div>
              <div style={{ fontSize: 17, fontWeight: 600 }}>
                {r.decision.verdict === "logistic better" ? "Met: the model beats EPSS in the top 100" : `Result: ${r.decision.verdict}`}
              </div>
            </div>
          </div>
          <div style={{ display: "flex", gap: 28, flexWrap: "wrap" }}>
            <Stat value={`${decision.difference_hits >= 0 ? "+" : ""}${hits(decision.difference_hits)}`} label={`extra KEV hits (${hits(r.methods.logistic!.pooled["hits@100"])} vs ${hits(r.methods.epss!.pooled["hits@100"])})`} />
            <Stat value={`[${hits(decision.ci95[0])}, ${hits(decision.ci95[1])}]`} label="paired bootstrap 95% CI" />
            {at1 && <Stat value={`${hits(r.methods.logistic!.pooled["hits@1%"])} vs ${hits(r.methods.epss!.pooled["hits@1%"])}`} label={at1.excludes_zero ? "top 1%: model ahead" : "top 1%: no detectable difference"} />}
          </div>
        </section>
      )}

      <section className="row">
        <figure className="panel grow" style={{ margin: 0, flexBasis: 600 }}>
          <div className="panel-head">
            <h2>KEV additions caught (of {positives}), pooled over {folds.length} folds</h2>
            <Seg label="Budget" options={[["100", "Top 100 per fold"], ["1%", "Top 1% per fold"]] as const} value={budget} onChange={setBudget} />
          </div>
          <svg className="chart" viewBox={`0 0 ${W} ${rows.length * rowH + 60}`} role="img" aria-label="Recall by method with Wilson 95 percent intervals" onMouseLeave={tip.hide}>
            {ticks.map((t) => (
              <g key={t}>
                <line x1={xs(t)} x2={xs(t)} y1={10} y2={rows.length * rowH + 20} stroke={t === 0 ? "var(--border-2)" : "var(--grid)"} />
                <text className="ax" x={xs(t)} y={rows.length * rowH + 38} textAnchor="middle">{pct(t, 0)}</text>
              </g>
            ))}
            <line x1={xs(random)} x2={xs(random)} y1={10} y2={rows.length * rowH + 20} stroke="var(--faint)" strokeDasharray="3 4" />
            <text className="ax" x={xs(random) + 4} y={rows.length * rowH + 16}>random</text>
            {rows.map((x, i) => {
              const y = 30 + i * rowH;
              return (
                <g key={x.m} onMouseMove={(e) => tip.show(e, <><b>{x.label}</b><br />{hits(x.hits)} of {positives} · {pct(x.value)} (CI {interval(x.ci)})</>)}>
                  <rect x={0} y={y - 18} width={W} height={rowH - 4} fill="transparent" />
                  <text x={L - 12} y={y + 4} textAnchor="end" style={{ fontSize: 13, fill: "var(--text-2)" }}>{x.label}</text>
                  <line x1={xs(x.ci[0])} x2={xs(x.ci[1])} y1={y} y2={y} stroke={x.color} strokeWidth="2" strokeLinecap="round" opacity="0.6" />
                  <circle cx={xs(x.value)} cy={y} r="6.5" fill={x.color} stroke="var(--panel)" strokeWidth="2" />
                  <text className="ax" x={xs(x.ci[1]) + 10} y={y + 4} style={{ fill: "var(--text)" }}>{hits(x.hits)} ({pct(x.value)})</text>
                </g>
              );
            })}
          </svg>
          <figcaption className="caption">
            Dot = pooled recall, line = Wilson 95% interval, dashed = random expectation. † CVSS uses snapshot-time
            scores, so it is an illustration only, not a fair baseline.
          </figcaption>
        </figure>

        <div className="panel side" style={{ flexBasis: 440 }}>
          <div className="panel-head"><h2>Per fold · hits in the top 100</h2></div>
          <div className="table-wrap">
            <table className="data compact">
              <thead>
                <tr className="label">
                  <th>Cutoff</th><th className="num">CVEs</th><th className="num">KEV</th>
                  <th className="num">Model</th><th className="num">EPSS</th><th className="num">Boost.</th>
                </tr>
              </thead>
              <tbody>
                {folds.map(([f, info]) => (
                  <tr key={f}>
                    <td className="mono">{info.cutoff}</td>
                    <td className="num">{int(info.eligible)}</td>
                    <td className="num">{info.positives}</td>
                    {["logistic", "epss", "boosting"].map((m) => (
                      <td key={m} className="num">{hits(r.methods[m]?.per_fold[f]?.["hits@100"] ?? 0)}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="kv" style={{ gridTemplateColumns: "repeat(3, minmax(0, 1fr))", marginTop: 14 }}>
            <div><span className="label">Mean AP</span><span className="mono">EPSS {r.methods.epss?.pooled.mean_average_precision.toFixed(3)}</span><span className="mono muted">model {r.methods.logistic?.pooled.mean_average_precision.toFixed(3)}</span></div>
            <div><span className="label">Base rate</span><span className="mono">{pct(positives / eligible)}</span><span className="muted" style={{ fontSize: 12 }}>{positives} / {int(eligible)}</span></div>
            <div><span className="label">Per hit</span><span className="mono">{pct(1 / positives)}</span><span className="muted" style={{ fontSize: 12 }}>of recall</span></div>
          </div>
          <p className="caption">EPSS wins on average precision; the model's gain is concentrated at the very top of the list.</p>
        </div>
      </section>

      <section className="row">
        <div className="panel grow" style={{ flexBasis: 520 }}>
          <div className="panel-head">
            <h2>Tier hit rates (evaluation folds)</h2>
            <span className="muted" style={{ fontSize: 12.5 }}>{r.tiers.monotonic ? "Monotonic, as pre-registered" : "Not monotonic"} · log scale</span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {TIERS.map((t) => {
              const h = r.tiers.tiers[t];
              if (!h) return null;
              return (
                <div key={t} style={{ display: "grid", gridTemplateColumns: "100px 226px 1fr", gap: 10, alignItems: "center", fontSize: 13 }}>
                  <TierName tier={t} />
                  <IntervalBar value={h.kev_positives / h.cves} ci={wilson(h.kev_positives, h.cves)} color={`var(--${t})`} scale={logScale} />
                  <span className="mono">{pct(h.kev_positives / h.cves)} · {h.kev_positives}/{int(h.cves)} · CI {interval(wilson(h.kev_positives, h.cves))}</span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="panel grow" style={{ flexBasis: 520 }}>
          <div className="panel-head"><h2>Other pipeline evaluations</h2></div>
          <Other
            name="ATT&CK technique mapping"
            value={att["prior+biencoder"]?.exploitation_technique ? `hit@5 ${att["prior+biencoder"].exploitation_technique["hit@5"].value.toFixed(3)}` : "—"}
            detail={att["prior+biencoder"]?.exploitation_technique ? `CTID KEV ground truth · test n=${att["prior+biencoder"].exploitation_technique.cves} · CI ${interval(att["prior+biencoder"].exploitation_technique["hit@5"].ci95, (x) => x.toFixed(3))}` : ""}
            base={att.majority?.exploitation_technique ? `majority baseline ${att.majority.exploitation_technique["hit@5"].value.toFixed(3)}` : ""}
          />
          <Other
            name="CWE classification (CWE name absent)"
            value={cweTf ? `macro-F1 ${cweTf.macro_f1.toFixed(3)}` : "—"}
            detail={cweTf ? `TF-IDF + LR · ${ev.cwe.classes} classes · test n=${int(cweTf.n)} · top-5 ${pct(cweTf.top5, 0)}` : ""}
            base={cweEmb ? `SecureBERT ${cweEmb.macro_f1.toFixed(3)}` : ""}
          />
          <Other
            name="IOC extraction (reference pages)"
            value={refPrec ? `precision ${refPrec.precision.toFixed(3)}` : "—"}
            detail={refPrec ? `${refPrec.labelled} AI-labelled under a written criterion, of ${int(refPrec.population)}; weighted, dominated by CVE IDs · CI ${interval(refPrec.ci95, (x) => x.toFixed(3))}` : ""}
            base={ev.extract.per_type.ipv4 ? `weakest: IPv4 ${ev.extract.per_type.ipv4.precision.toFixed(2)} (all origins)` : ""}
          />
          <Other
            name="SecureBERT NER (Malware)"
            value={ev.ner.overlap.Malware ? `recall ${ev.ner.overlap.Malware.recall.toFixed(2)} (overlap)` : "—"}
            detail="rule-generated gold set, so precision (and F1) are lower bounds; context only, never used for scoring"
            base={ev.ner.exact.Malware ? `exact-match recall ${ev.ner.exact.Malware.recall.toFixed(2)}` : ""}
          />
        </div>
      </section>

      <section className="panel">
        <div className="panel-head"><h2>Limitations</h2></div>
        <ul className="plain" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "8px 32px" }}>
          <li>KEV is a lagging, incomplete label: exploited-but-unlisted CVEs count as misses.</li>
          <li>{positives} positives: one hit is about {pct(1 / positives)} of recall, so only large gains are detectable.</li>
          <li>The snapshot uses a newer EPSS model than training saw; that shift is untested.</li>
          <li>Only CVEs published inside the NVD window are ranked; older CVEs are out of scope.</li>
          <li>Exploratory results (no-EPSS ablation, text features) are not shown as findings.</li>
          <li>ATT&amp;CK and CWE ground truths have known biases (KEV-only mappings; assigner-dependent labels).</li>
        </ul>
      </section>
    </>
  );
}

function Stat({ value, label }: { value: string; label: string }) {
  return (
    <div style={{ display: "flex", flexDirection: "column" }}>
      <span className="mono" style={{ fontSize: 24, fontWeight: 600 }}>{value}</span>
      <span className="muted" style={{ fontSize: 12.5 }}>{label}</span>
    </div>
  );
}

function Other({ name, value, detail, base }: { name: string; value: string; detail: string; base: string }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: "4px 16px", padding: "10px 0", borderBottom: "1px solid var(--grid)" }}>
      <span style={{ fontSize: 14, fontWeight: 550 }}>{name}</span>
      <span className="mono" style={{ fontSize: 14 }}>{value}</span>
      <span className="muted" style={{ fontSize: 12.5 }}>{detail}</span>
      <span className="mono muted" style={{ fontSize: 12.5, textAlign: "right" }}>{base}</span>
    </div>
  );
}
