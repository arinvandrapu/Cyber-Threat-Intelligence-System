import type { Data } from "../types";
import { cveHref } from "../App";
import { PageHead, TierDot, TierName, IntervalBar } from "../components/ui";
import { TIER_BAND, TIERS, epss, int, pct, interval, wilson, FEATURE_LABEL } from "../format";

const logScale = (v: number) => (Math.log10(Math.max(v, 1e-4)) + 4) / 3; // 0.01% .. 10%

export function Overview({ data }: { data: Data }) {
  const { meta, risk, evals, threats } = data;
  const counts = Object.fromEntries(risk.tiers.map((t) => [t.name, t.cves]));
  const hist = Object.fromEntries(risk.historical_tiers.map((t) => [t.name, t]));
  const decision = evals.risk.decision["logistic_minus_epss_hits@100"];
  const paired = typeof decision === "object" ? decision : null;
  const positives = evals.risk.methods.logistic?.pooled.positives ?? 0;
  const critical = hist.critical;
  const top = risk.rows.slice(0, 5);

  return (
    <>
      <PageHead
        title="Which threats deserve attention first, and why?"
        lede={
          <>
            Built from public feeds as of {meta.snapshot_date}. Two linked lists answer it: which vulnerabilities to fix
            next, and which attackers' tools matter most. Every ranking says why, and every score shows how well it was
            tested.
          </>
        }
      />

      <section className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))" }} aria-label="How this dashboard works">
        <div className="panel" style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <span className="label">1 · Vulnerabilities</span>
          <h2 style={{ margin: 0, fontSize: 17 }}>Which CVEs to fix next</h2>
          <p className="muted" style={{ margin: 0, fontSize: 13.5, lineHeight: 1.5 }}>
            {int(risk.ranked_cves)} CVEs published since 2024 and not yet in CISA's list are scored on how likely CISA is to add them to its
            Known Exploited Vulnerabilities (KEV) list within 180 days; the top {int(risk.rows.length)} form the queue.
            Each one shows what moved it up or down.
          </p>
          <a href="#/queue" className="pill" style={{ alignSelf: "flex-start", textDecoration: "none" }}>Open risk queue</a>
        </div>
        <div className="panel" style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <span className="label">2 · Threats</span>
          <h2 style={{ margin: 0, fontSize: 17 }}>Which attackers' tools matter most</h2>
          <p className="muted" style={{ margin: 0, fontSize: 13.5, lineHeight: 1.5 }}>
            {threats.available
              ? `${int(threats.families_total)} malware and tool families seen in ThreatFox. The top ${int(threats.families.length)} are shown with a category (ransomware, botnet, infostealer…), their ATT&CK techniques where matched, and any CVEs linked to them.`
              : "The threat catalog has not been built for this snapshot."}
          </p>
          <a href="#/threats" className="pill" style={{ alignSelf: "flex-start", textDecoration: "none" }}>Open threats</a>
        </div>
        <div className="panel" style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <span className="label">How they connect</span>
          <h2 style={{ margin: 0, fontSize: 17 }}>Threats explain CVEs</h2>
          <p className="muted" style={{ margin: 0, fontSize: 13.5, lineHeight: 1.5 }}>
            A CVE linked to a threat (e.g. a botnet exploiting it) is more urgent; a threat linked to CVEs tells you what
            to patch to defend against it. CVEs already in KEV are confirmed exploited: patch those first. They are not
            ranked; their CISA entry opens from the threats linked to them. Threats never change a CVE's rank.
          </p>
        </div>
      </section>

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
          <span className="label">Model vs EPSS · KEV additions caught in the top 100</span>
          <span className="value">{paired ? `${paired.difference_hits >= 0 ? "+" : ""}${paired.difference_hits} hits` : "—"}</span>
          <span className="muted">
            {paired ? `95% range ${paired.ci95[0]} to ${paired.ci95[1]} · ${positives} KEV additions over 3 test periods` : ""}
          </span>
        </div>
        <div className="panel tile">
          <span className="label">Top threat</span>
          <span className="value" style={{ fontSize: 22 }}>{threats.families[0]?.family ?? "—"}</span>
          <span className="muted">{threats.families[0]?.why[0] ?? "threat catalog not built"}</span>
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
          <h2>Guide to each tab</h2>
          <span className="muted" style={{ fontSize: 12.5 }}>what it is · why it's there · how it's calculated</span>
        </div>
        <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))" }}>
          {guide(data).map((g) => (
            <a key={g.view} href={`#/${g.view}`} className="guide">
              <span style={{ fontWeight: 600, color: "var(--text)" }}>{g.title}</span>
              <span><strong>What:</strong> {g.what}</span>
              <span><strong>Why:</strong> {g.why}</span>
              <span><strong>How:</strong> {g.how}</span>
            </a>
          ))}
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

/** Plain-language description of every tab; numbers come from the export. */
function guide(data: Data): { view: string; title: string; what: string; why: string; how: string }[] {
  const { risk, threats, evals } = data;
  const d = evals.risk.decision["logistic_minus_epss_hits@100"];
  const vsEpss = typeof d === "object" ? `${d.difference_hits >= 0 ? "+" : ""}${d.difference_hits}` : "?";
  const extract = evals.extract.per_origin.reference_page;
  const review = threats.review;
  return [
    {
      view: "queue",
      title: "Risk queue",
      what: `The ${int(risk.rows.length)} highest-risk CVEs that are not yet in CISA KEV, best first, in critical, high and elevated tiers.`,
      why: "So you know which unexploited vulnerabilities to patch next, before attackers start using them.",
      how: `A scoring model fixed before testing combines signals known on the snapshot date: EPSS, CISA's SSVC assessment, public exploit code (ExploitDB, Metasploit, Nuclei) and the CVE's age. It was trained to predict which CVEs CISA adds to KEV within 180 days. In back-tests of the same procedure it caught ${vsEpss} more later KEV additions than EPSS in each period's top 100; this snapshot's ranking itself cannot be scored yet. Tiers are rank bands, not probabilities.`,
    },
    {
      view: "threats",
      title: "Threats",
      what: "Malware and tool families seen in abuse.ch ThreatFox, with category, ATT&CK techniques and linked CVEs.",
      why: "So you know which attackers' tools are active and which vulnerabilities they exploit.",
      how: review
        ? `Ranked by a fixed rule, not a trained model: linked CVEs confirmed exploited (KEV), then linked high-risk queue CVEs, ransomware, then 30-day growth in indicators. Categories of the top families were labelled by an AI reviewer (Claude) on the owner's behalf, not by MISP name matching; ${review.links_correct} of ${review.links_reviewed} CVE links were reviewed correct, and only reviewed-correct links or ThreatFox's own tags count.`
        : "Not built for this snapshot.",
    },
    {
      view: "landscape",
      title: "Risk landscape",
      what: "Charts of the whole ranking: model rank against EPSS, how much each signal counts, signal coverage by tier, and ranked CVEs by month.",
      why: "To see where the model agrees or disagrees with EPSS, and what drives it.",
      how: "Computed from the same ranking as the risk queue; the weights are the model's, measured per standard deviation of each signal.",
    },
    {
      view: "weakness",
      title: "Weakness graph",
      what: "The kinds of bug behind critical and high-risk CVEs, grouped by CWE category.",
      why: "Recurring weakness types point to root causes worth fixing across products.",
      how: "Each critical/high CVE is joined to the CWE that NVD or the reporting organisation (CNA) assigned, and each CWE to its top-level CWE category.",
    },
    {
      view: "attack",
      title: "ATT&CK graph",
      what: "How known-exploited CVEs are used in attacks: CVE → ATT&CK technique → tactic.",
      why: "To connect vulnerabilities to attacker behaviour and the defences that detect it.",
      how: "MITRE Center for Threat-Informed Defense expert mappings of KEV CVEs, not predictions. A tested automatic mapping was too weak to show here (see Evaluation).",
    },
    {
      view: "indicators",
      title: "Indicators",
      what: "IP addresses, domains, URLs and file hashes found in CVE reference pages, plus abuse.ch feed totals.",
      why: "Context for hunting and blocking, and for seeing infrastructure shared across CVEs.",
      how: `Pattern matching with validation; every value is defanged so it can't be clicked. ${extract ? `On a reviewed sample from reference pages, ${pct(extract.precision)} of extracted values were real values of their type, but most of those are CVE IDs; IP addresses are much weaker (see Evaluation).` : ""} Nothing here is vetted as malicious. abuse.ch data is shown only as counts (licence).`,
    },
    {
      view: "evaluation",
      title: "Evaluation",
      what: "How well each part works, on data it was not built from.",
      why: "So you know how much to trust each number on the other tabs.",
      how: "The risk model, CWE classifier and ATT&CK re-test were set up in advance and scored on data they were not built from; indicator extraction was scored on a hand-reviewed sample. Anything changed after seeing results is disclosed, and weak results are shown, not hidden.",
    },
  ];
}
