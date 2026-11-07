import { FEATURE_LABEL, int, pct } from "../../format";
import { Defs, Example, G, Misreads, type SectionBuilder } from "../common";

export const overview: SectionBuilder = (data) => {
  const { risk } = data;
  const hist = Object.fromEntries(risk.historical_tiers.map((t) => [t.name, t]));
  const overall =
    risk.historical_tiers.reduce((s, t) => s + t.kev_positives, 0) / Math.max(1, risk.historical_tiers.reduce((s, t) => s + t.cves, 0));
  const crit = hist.critical;
  const lrAp = data.evals.risk.methods.logistic?.pooled.mean_average_precision;
  const epAp = data.evals.risk.methods.epss?.pooled.mean_average_precision;
  const critRate = crit && crit.cves > 0 ? crit.kev_positives / crit.cves : null;
  const top = risk.rows[0];
  const topDriver = top
    ? Object.entries(top.contributions).reduce((a, b) => (b[1] > a[1] ? b : a), ["", -Infinity])[0]
    : null;
  return {
    id: "overview",
    title: "Overview",
    view: "overview",
    intro: <p>A one-screen briefing: what to patch now, what to patch next, and the threats sources tie to some of them. Each panel is a summary of a deeper tab and links to it.</p>,
    parts: [
      {
        id: "briefing",
        title: "The briefing panel",
        body: (
          <>
            <p>Three columns, one per question, each with a button that opens the full tab:</p>
            <Defs
              rows={[
                ["Which exploited CVEs to patch first", <>Counts from CISA KEV: all KEV CVEs, how many are tied to a threat family, how many CISA says ransomware has used. "First:" names the CVE at the top of the <G to="kev">Known exploited</G> order and why it is there.</>],
                ["Which CVEs to fix next", <>The size of the <G to="queue">risk queue</G>, how many CVEs were scored, the critical-tier count, and how the model did against EPSS in past tests ("vs EPSS in the top 100"). The 95% range in brackets is for the <em>difference</em> between the two, not for either count. Top-100 hits is the one comparison fixed in advance{lrAp !== undefined && epAp !== undefined && epAp > lrAp ? "; on mean average precision EPSS scored higher, and the note says so" : ""}.</>],
                ["Which attackers' tools matter most", <>The top family on the <G to="threats">Threats</G> tab and its first reason.</>],
                ["How they connect", "The strip under the columns: how many KEV CVEs are tied to a threat, and how many queued CVEs have a threat link that counts (reviewed correct, or an unreviewed ThreatFox tag or ATT&CK citation): a possible early warning that never changes the rank."],
              ]}
            />
          </>
        ),
      },
      {
        id: "tiers",
        title: "Risk tiers table",
        body: (
          <>
            <p>
              One row per tier. Tiers are <G to="concepts-ranking">rank bands</G>, not probabilities: critical is the top 0.1%
              of scored CVEs by rank, high the next 0.9%, elevated the next 4%, baseline the rest.
            </p>
            <Defs
              rows={[
                ["CVEs now", "How many CVEs in today's snapshot fall in the tier (baseline included). Ties share a rank, so the counts are close to, not exactly, 0.1 / 1 / 5%."],
                [
                  "Historical KEV rate",
                  <>
                    From past back-tests, not today's list: the share of CVEs in that tier that CISA added to KEV within 180 days.
                    The dot (in the tier's colour) is the rate and the faint band its 95% interval (<G to="concepts-stats">Wilson</G>).
                  </>,
                ],
                ["Log scale", "The bar runs from 0.01% on the left to 10% on the right on a log scale: each step to the right is ten times the rate, so equal gaps are equal ratios. Rates outside that range sit at an end."],
              ]}
            />
            <p>
              The note under the table compares the critical tier with all scored CVEs: "about N× as often". It rests on few KEV
              additions{crit ? ` (${int(crit.kev_positives)} of ${int(crit.cves)} critical CVEs)` : ""}, so the range is wide: read the bracketed interval.
            </p>
          </>
        ),
      },
      {
        id: "top",
        title: "Top of the queue and tab cards",
        body: (
          <p>
            "Top of the queue" lists the first five risk-queue rows. "Top driver" is the signal that pushed that CVE{" "}
            <em>up</em> the most (the largest contribution, normally positive); the full breakdown, including signals that pushed it down,
            is in the risk-queue detail. "What each tab is for" gives one line per tab; this guide is the long version.
          </p>
        ),
      },
      {
        id: "misreads",
        title: "Common misreadings",
        body: (
          <Misreads
            items={[
              ["\"Critical means it will be exploited.\"", "No: most critical CVEs never reached KEV in past tests. Critical means it ranks in the top 0.1%, where KEV additions were far more common than average."],
              ["\"CVEs now\" and \"Historical KEV rate\" describe the same CVEs.", "They don't: the count is today's snapshot; the rate comes from past test periods."],
              ["\"Top driver: Age (older ranks lower)\" means the CVE is old.", "The label names the direction of the weight. On a new CVE it means youth pushed it up."],
            ]}
          />
        ),
      },
      {
        id: "example",
        title: "Example",
        body: (
          <Example>
            {critRate !== null && overall > 0
              ? <>In past tests {pct(critRate)} of critical-tier CVEs ({int(crit!.kev_positives)} of {int(crit!.cves)}) were added to KEV within 180 days, against {pct(overall, 2)} of all scored CVEs. </>
              : null}
            {top && topDriver
              ? <>The top of today's queue is {top.cve}; its top driver is "{FEATURE_LABEL[topDriver] ?? topDriver}". </>
              : null}
            {int(risk.ranked_cves)} CVEs were scored.
          </Example>
        ),
      },
    ],
  };
};
