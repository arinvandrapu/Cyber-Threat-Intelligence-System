import { int } from "../../format";
import { Defs, G, type SectionBuilder } from "../common";

export const start: SectionBuilder = (data) => {
  const { meta, kev, risk, threats } = data;
  const synthetic = meta.git.commit === "fixture";
  const kevLinked = kev.entries.filter((e) => e.families.length > 0).length;
  const queued = new Set(risk.rows.map((r) => r.cve));
  const early = new Set(
    threats.families.flatMap((f) => f.links.filter((l) => l.counts_for_priority && queued.has(l.cve)).map((l) => l.cve)),
  ).size;
  return {
    id: "start",
    title: "Start here",
    intro: (
      <p>
        This guide explains each tab in depth: what it answers, how to read every panel, how it is built,
        and the readings that are easy to get wrong. The tab names in the menu match the tabs at the top
        of the page. Every count and example in the guide is read from the same export as the dashboard,
        so it matches what you see.
      </p>
    ),
    parts: [
      {
        id: "workflow",
        title: "How the tabs fit together",
        body: (
          <>
            <p>The dashboard answers one question: which vulnerabilities and threats deserve attention first, and why. Read it in this order:</p>
            <ol className="gd-steps">
              <li>
                <strong><a href="#/kev">Known exploited</a></strong>: the {int(kev.entries.length)} CVEs CISA lists as already
                exploited. Patch these first. Their order is a fixed rule, not a prediction.
              </li>
              <li>
                <strong><a href="#/queue">Risk queue</a></strong>: the {int(risk.rows.length)} CVEs, out of{" "}
                {int(risk.ranked_cves)} scored, that a model ranks likeliest to be added to CISA KEV next. Work down it
                after the known-exploited list.
              </li>
              <li>
                <strong><a href="#/threats">Threats</a></strong>: the malware and attack tools behind those CVEs.
                {threats.available
                  ? ` Sources tie a family to only some CVEs (${int(kevLinked)} in KEV, ${int(early)} in the queue today), and a link doesn't show the family exploited the CVE. Threats never change a CVE's rank.`
                  : " Not built for this snapshot."}
              </li>
              <li>
                The remaining tabs explain the ranking (<a href="#/landscape">Risk landscape</a>), the weaknesses
                and attack techniques behind the CVEs (<a href="#/weakness">Weakness graph</a>,{" "}
                <a href="#/attack">ATT&amp;CK graph</a>), the indicator strings found around them (
                <a href="#/indicators">Indicators</a>) and how far each part can be trusted (
                <a href="#/evaluation">Evaluation</a>).
              </li>
            </ol>
            <p>Both lists cover every product in the feeds; there is no asset inventory, so act on the CVEs in software you actually run.</p>
          </>
        ),
      },
      {
        id: "conventions",
        title: "Conventions used on every tab",
        body: (
          <Defs
            rows={[
              ["Snapshot", <>All data is a frozen copy of public feeds taken on {meta.snapshot_date}. Nothing updates live; a new snapshot means re-running the pipeline. See <G to="data">Data &amp; freshness</G>.</>],
              ["Read-only", <>The header chip "{meta.snapshot_date} · read-only" means the dashboard only reads files: it is served on your own machine (127.0.0.1), has no accounts and sends nothing you type anywhere.</>],
              ...(synthetic
                ? ([["SYNTHETIC DATA", "This copy is running on made-up test records (the orange header chip). Numbers in this guide are from that test data, not real feeds."]] as [string, string][])
                : []),
              ["Colours", <>Risk tiers run pink to cherry: the redder, the higher the risk. Orange marks CISA KEV (and the synthetic-data warning chip). Blue marks links, selections, positive model pushes and the model in charts. See <G to="concepts-ranking">tiers</G>.</>],
              ["Clicking a CVE", <>Most CVE IDs open a detail: in the risk queue if it is in the queue (top 5%), in Known exploited if it is in KEV; otherwise a note saying why it isn't in the queue, with its NVD record when the export has one.</>],
              ["Links you can share", <>Addresses like <span className="mono">#/queue/{risk.rows[0]?.cve ?? "CVE-…"}</span>, <span className="mono">#/kev/{kev.entries[0]?.cve ?? "CVE-…"}</span> and <span className="mono">#/threats/&lt;family&gt;</span> open a tab with that item selected. Filters, searches and rows you click inside a tab are not saved in the address.</>],
              ["Hover", "Charts and graphs show the exact values in a tooltip when you hover a mark."],
              ["Caveats on the page", "Grey captions under each chart say what it does not show. They are part of the reading, not small print."],
            ]}
          />
        ),
      },
    ],
  };
};
