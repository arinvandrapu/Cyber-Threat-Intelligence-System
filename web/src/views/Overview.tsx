import type { Data } from "../types";
import { cveHref } from "../App";
import { PageHead, TierDot, TierName, IntervalBar, type View } from "../components/ui";
import { TIER_BAND, TIERS, epss, int, linkReview, pct, interval, signed, wilson, FEATURE_LABEL } from "../format";

const logScale = (v: number) => (Math.log10(Math.max(v, 1e-4)) + 4) / 3; // 0.01% .. 10%

export function Overview({ data }: { data: Data }) {
  const { meta, risk, evals, threats } = data;
  const counts = Object.fromEntries(risk.tiers.map((t) => [t.name, t.cves]));
  const hist = Object.fromEntries(risk.historical_tiers.map((t) => [t.name, t]));
  const decision = evals.risk.decision["logistic_minus_epss_hits@100"];
  const paired = typeof decision === "object" ? decision : null;
  const critical = hist.critical;
  const overallRate =
    risk.historical_tiers.reduce((s, t) => s + t.kev_positives, 0) /
    risk.historical_tiers.reduce((s, t) => s + t.cves, 0);
  const epssAp = evals.risk.methods.epss?.pooled.mean_average_precision;
  const logisticAp = evals.risk.methods.logistic?.pooled.mean_average_precision;
  const logisticHits = evals.risk.methods.logistic?.pooled["hits@100"];
  const epssHits = evals.risk.methods.epss?.pooled["hits@100"];
  const positives = evals.risk.methods.logistic?.pooled.positives;
  const top = risk.rows.slice(0, 5);
  const kev = data.kev.entries;
  const kevLinked = kev.filter((e) => e.families.length > 0).length;
  const kevRansomware = kev.filter((e) => e.ransomware_use === "Known").length;
  const kevFirst = kev[0];
  // queued CVEs a threat is tied to by a link that counts (same rule as the KEV order)
  const queued = new Set(risk.rows.map((r) => r.cve));
  const earlyWarnings = new Set(
    threats.families.flatMap((f) => f.links.filter((l) => l.counts_for_priority && queued.has(l.cve)).map((l) => l.cve)),
  ).size;

  return (
    <>
      <PageHead
        guide="overview"
        title="Which threats deserve attention first, and why?"
        lede={<>Public feeds as of {meta.snapshot_date}: exploited CVEs to patch now, CVEs likeliest to be exploited next, and the threats behind them.</>}
      />

      <section className="panel brief" aria-label="How this dashboard works">
        <div className="brief-col">
          <div className="brief-head">
            <h2>Which exploited CVEs to patch first</h2>
            <p>
              Every CVE in CISA KEV: someone has exploited it. {threats.available ? "Threat-linked first, then ransomware use" : "Ransomware use first"}, then newest.
            </p>
          </div>
          <dl className="stats">
            <div className="stat">
              <dt>CVEs in CISA KEV</dt>
              <dd>{int(kev.length)}</dd>
            </div>
            {threats.available && (
              <div className="stat">
                <dt>linked to a threat</dt>
                <dd>{int(kevLinked)}</dd>
              </div>
            )}
            <div className="stat">
              <dt>known ransomware use</dt>
              <dd>{int(kevRansomware)}</dd>
            </div>
          </dl>
          {kevFirst && (
            <p className="brief-note">
              First: <a href={`#/kev/${kevFirst.cve}`} className="mono">{kevFirst.cve}</a>
              {kevFirst.vendor || kevFirst.product ? ` (${[kevFirst.vendor, kevFirst.product].filter(Boolean).join(" ")})` : ""}. {kevFirst.why}.
            </p>
          )}
          <a href="#/kev" className="pill brief-cta">Open known exploited</a>
        </div>

        <div className="brief-col">
          <div className="brief-head">
            <h2>Which CVEs to fix next</h2>
            <p>The {int(risk.rows.length)} CVEs in the queue: those likeliest to join CISA KEV, best first.</p>
          </div>
          <dl className="stats">
            <div className="stat">
              <dt>CVEs scored, not in CISA KEV</dt>
              <dd>{int(risk.ranked_cves)}</dd>
            </div>
            <div className="stat">
              <dt>in the critical tier, top 0.1% by rank</dt>
              <dd>{int(counts.critical ?? 0)}</dd>
            </div>
            <div className="stat">
              <dt>vs EPSS in the top 100</dt>
              <dd>{paired ? `${signed(paired.difference_hits, 0)} hits` : "—"}</dd>
            </div>
          </dl>
          {paired && (
            <p className="brief-note">
              {`${logisticHits} vs ${epssHits} of ${positives} later KEV additions, over ${Object.keys(evals.risk.folds).length} past test periods (95% CI ${signed(paired.ci95[0], 0)} to ${signed(paired.ci95[1], 0)})`}
              {epssAp !== undefined && logisticAp !== undefined && epssAp > logisticAp ? ". EPSS has the higher mean average precision." : "."}
            </p>
          )}
          <a href="#/queue" className="pill brief-cta">Open risk queue</a>
        </div>

        <div className="brief-col">
          <div className="brief-head">
            <h2>Which attackers' tools matter most</h2>
            <p>
              {threats.available
                ? "Active malware and attack tools, with the CVEs linked to them."
                : "Not built for this snapshot yet."}
            </p>
          </div>
          <dl className="stats">
            <div className="stat">
              <dt>top threat</dt>
              <dd>{threats.families[0]?.family ?? "—"}</dd>
            </div>
          </dl>
          <p className="brief-note">{threats.families[0]?.why[0] ?? "threat catalog not built"}</p>
          <a href="#/threats" className="pill brief-cta">Open threats</a>
        </div>

        <p className="brief-foot">
          {threats.available ? (
            <>
              <strong>How they connect: threats explain exploited CVEs.</strong> {int(kevLinked)} of the {int(kev.length)} KEV
              CVEs are tied to a threat family, and they lead the patch-first list. A threat tied to a queued CVE is rarer
              ({int(earlyWarnings)} today): an early warning, flagged in the risk queue, that never changes its rank.
            </>
          ) : (
            <>
              <strong>Patch exploited CVEs first, then work down the risk queue.</strong> Threat links weren't built for
              this snapshot.
            </>
          )}
        </p>
      </section>

      <section className="row match">
        <div className="panel grow">
          <div className="panel-head">
            <h2>Risk tiers</h2>
            <span className="muted" style={{ fontSize: 12.5 }}>share later added to CISA KEV, in past tests</span>
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
              A triage order, not a forecast: most critical CVEs never reached KEV, but they reached it about{" "}
              {int(critical.kev_positives / critical.cves / overallRate)}× as often as CVEs overall (95% CI{" "}
              {interval(wilson(critical.kev_positives, critical.cves), (x) => int(x / overallRate))}×, overall rate taken as fixed).
            </p>
          )}
        </div>

        <div className="panel side queue-card">
          <div className="panel-head">
            <h2>Top of the queue</h2>
            <span className="muted" style={{ fontSize: 12.5 }}>top {top.length} of {int(risk.rows.length)}</span>
          </div>
          <div className="queue-viewport">
            <div className="queue-scroll" tabIndex={0} role="region" aria-label={`Top ${top.length} CVEs in the risk queue`}>
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
        </div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>What each tab is for</h2>
        </div>
        <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))" }}>
          {guide(data).map((g) => (
            <div key={g.view} className="guide">
              <a href={`#/${g.view}`} style={{ fontWeight: 600, color: "var(--text)", textDecoration: "none" }}>{g.title} →</a>
              <span>{g.what}</span>
              <details>
                <summary className="muted" style={{ cursor: "pointer", fontSize: 12.5 }}>How it works</summary>
                <p style={{ margin: "6px 0 0" }}>{g.why} {g.how}</p>
                <a href={`#/guide/${g.view}`} style={{ fontSize: 12.5 }}>Full guide to {g.title} →</a>
              </details>
            </div>
          ))}
        </div>
      </section>

      <p className="muted" style={{ fontSize: 12.5, margin: 0 }}>
        Data as of {meta.snapshot_date}. Methods, data versions and limitations: <a href="#/evaluation">Evaluation</a>.
      </p>
    </>
  );
}

/** Plain-language description of every tab; numbers come from the export. */
function guide(data: Data): { view: View; title: string; what: string; why: string; how: string }[] {
  const { threats, evals } = data;
  const d = evals.risk.decision["logistic_minus_epss_hits@100"];
  const vsEpss = typeof d === "object" ? `${signed(d.difference_hits, 0)} (95% CI ${signed(d.ci95[0], 0)} to ${signed(d.ci95[1], 0)})` : "?";
  const extract = evals.extract.per_origin.reference_page;
  const review = threats.review;
  const epssAp = evals.risk.methods.epss?.pooled.mean_average_precision;
  const logisticAp = evals.risk.methods.logistic?.pooled.mean_average_precision;
  const apNote = epssAp !== undefined && logisticAp !== undefined && epssAp > logisticAp ? ", though EPSS has the higher mean average precision" : "";
  const kevLinked = data.kev.entries.filter((e) => e.families.length > 0).length;
  return [
    {
      view: "kev",
      title: "Known exploited",
      what: "Every CVE in CISA KEV, in the order to patch them, each with its reasons.",
      why: "Someone has already exploited these, so they come before anything predicted.",
      how: `A fixed rule agreed before it was run, not a model: CVEs a threat family is tied to come first (${kevLinked} today), then CISA's known ransomware use, then the newest CISA listing. A threat link counts only if it was reviewed correct, or is an unreviewed ThreatFox tag or ATT&CK citation. KEV says someone exploited the CVE, not necessarily the linked family.`,
    },
    {
      view: "queue",
      title: "Risk queue",
      what: "Which vulnerabilities to patch next, best first, each with its reasons.",
      why: "So you know which vulnerabilities outside CISA KEV to patch next.",
      how: `A scoring model fixed before testing combines signals known on the snapshot date: EPSS, CISA's SSVC assessment, public exploit code (ExploitDB, Metasploit, Nuclei) and the CVE's age. It was trained to predict which CVEs CISA adds to KEV within 180 days. In back-tests of the same procedure, summed over ${Object.keys(evals.risk.folds).length} periods, its top-100 lists caught ${vsEpss} later KEV additions vs EPSS${apNote}; this snapshot's ranking itself cannot be scored yet. Tiers are rank bands, not probabilities.`,
    },
    {
      view: "threats",
      title: "Threats",
      what: "Which malware and attack tools are active, and which CVEs are linked to them.",
      why: "So you know which attackers' tools are active and which vulnerabilities sources tie to them.",
      how: review
        ? `Ranked by a fixed rule, not a trained model: linked CVEs in CISA KEV, then linked high-risk queue CVEs, ransomware, then 30-day growth in indicators. Categories of the top families were labelled by an AI reviewer (Claude) on the owner's behalf, not by MISP name matching; ${linkReview(review)}. Only reviewed-correct links, or unreviewed ThreatFox or ATT&CK links, count. A KEV CVE is exploited by someone, not necessarily by the family linked to it.`
        : "Not built for this snapshot.",
    },
    {
      view: "landscape",
      title: "Risk landscape",
      what: "Charts of the whole ranking and what drives it.",
      why: "To see where the model agrees or disagrees with EPSS, and what drives it.",
      how: "Computed from the same ranking as the risk queue; the weights are the model's, measured per standard deviation of each signal.",
    },
    {
      view: "weakness",
      title: "Weakness graph",
      what: "The kinds of bug behind the highest-risk CVEs.",
      why: "Recurring weakness types point to root causes worth fixing across products.",
      how: "Each critical/high CVE is joined to the CWE that NVD or the reporting organisation (CNA) assigned, and each CWE to its top-level CWE category.",
    },
    {
      view: "attack",
      title: "ATT&CK graph",
      what: "How exploited CVEs are used in attacks (MITRE ATT&CK).",
      why: "To connect vulnerabilities to attacker behaviour and the defences that detect it.",
      how: "MITRE Center for Threat-Informed Defense expert mappings of KEV CVEs, not predictions. A tested automatic mapping was too weak to show here (see Evaluation).",
    },
    {
      view: "indicators",
      title: "Indicators",
      what: "IPs, domains, URLs and hashes found around these CVEs.",
      why: "Context for hunting and blocking, and for seeing infrastructure shared across CVEs.",
      how: `Pattern matching with validation; every value is defanged so it can't be clicked. ${extract ? `On a reviewed sample from reference pages, ${pct(extract.precision)} of extracted values were real values of their type, but most of those are CVE IDs; IP addresses are much weaker (see Evaluation).` : ""} Nothing here is vetted as malicious. abuse.ch data is shown only as counts (licence).`,
    },
    {
      view: "evaluation",
      title: "Evaluation",
      what: "How well each part works, plus data sources and limitations.",
      why: "So you know how much to trust each number on the other tabs.",
      how: "The risk model, CWE classifier and ATT&CK re-test were set up in advance and scored on data they were not built from; indicator extraction was scored on a hand-reviewed sample. Anything changed after seeing results is disclosed, and weak results are shown, not hidden.",
    },
  ];
}
