import { int, linkReview, signed } from "../../format";
import { Defs, Example, G, Misreads, type SectionBuilder } from "../common";

export const threats: SectionBuilder = (data) => {
  const t = data.threats;
  const top = t.families[0];
  // the fixed top N: families shown with consecutive ranks from 1 (later rows can skip ranks)
  const gap = t.families.findIndex((f, i) => f.rank !== i + 1);
  const topN = gap < 0 ? t.families.length : gap;
  const kevLinked = data.kev.entries.filter((e) => e.families.length > 0).length;
  return {
    id: "threats",
    title: "Threats",
    view: "threats",
    intro: (
      <p>
        Which malware and attack tools are active, and which CVEs sources tie to them. It explains the few CVEs sources tie to a
        family ({int(kevLinked)} in KEV today); it never changes a CVE's rank.{t.available ? "" : " The threat catalog wasn't built for this snapshot, so the tab shows only how to build it."}
      </p>
    ),
    parts: [
      {
        id: "ranking",
        title: "How families are ranked",
        body: (
          <>
            <p>
              Families come from abuse.ch <G to="concepts-threat">ThreatFox</G>. They are ranked by a fixed rule, not a trained
              model, comparing each item in turn and only using the next to break a tie:
            </p>
            <ol className="gd-steps">
              <li>linked CVEs that are in CISA KEV;</li>
              <li>linked critical- or high-tier CVEs from the risk queue;</li>
              <li>ransomware;</li>
              <li>30-day growth in indicators (new in the last 30 days minus the 30 days before);</li>
              <li>total indicators, then name.</li>
            </ol>
            <p>
              A fixed top {topN} are shown, plus any lower family with a link that wasn't rejected, so rank numbers can jump past {topN}.
              {t.available ? <> "Families tracked" counts all {int(t.families_total)} named families.</> : null}
            </p>
          </>
        ),
      },
      {
        id: "table",
        title: "Tiles and the family table",
        body: (
          <Defs
            rows={[
              ["Tiles", "Families tracked; shown families linked to KEV CVEs; shown ransomware families; and KEV CVEs CISA says ransomware used, which counts all of KEV, not just the shown families."],
              ["Category pills", "Show only families with that category. Only categories a shown family has get a pill."],
              ["Category badge", "Solid border: reviewed label. Dashed border: an unreviewed match from the MISP galaxy, where names can collide. \"unknown\" on a reviewed family means none of the categories fits."],
              ["Why it ranks here", "Only the first reason. The full list is in the side panel. \"(no linked CVEs in our data)\" means none of its ranking comes from CVEs: it ranks on ransomware, then indicator activity."],
              ["KEV CVEs", "Linked KEV CVEs that count toward the ranking (0 is greyed)."],
              ["IOCs (30-day change)", "ThreatFox indicator count, and in brackets the difference between the last 30 days and the 30 before. It is a count difference, not a percentage."],
            ]}
          />
        ),
      },
      {
        id: "family",
        title: "The selected family panel",
        body: (
          <Defs
            rows={[
              ["Header", "Rank, name, categories and whether they were reviewed."],
              ["Why it ranks here", "Every reason, in rule order."],
              ["ATT&CK", "The MITRE ATT&CK software whose name or alias matches the family's name (ignoring case and punctuation, and only if exactly one matches), with its techniques and tactics. No fuzzy matching, so a well-known family can be missing, and a same-named program on another platform can be matched by mistake."],
              ["Linked CVEs", "One row per CVE and source. A blue CVE is in the risk queue and opens there; a white one expands its record in place. ▸ shows the source, the review status and, for ATT&CK, MITRE's own sentence."],
            ]}
          />
        ),
      },
      {
        id: "links",
        title: "Threat links and their review",
        body: (
          <>
            <Defs
              rows={[
                ["ThreatFox", "A reporter tagged the family's indicators with the CVE."],
                ["Report", "The family is named on a page the CVE references."],
                ["ATT&CK", "MITRE's description of the software cites the CVE."],
                ["✓ / ✗ / none", "Reviewed correct / reviewed wrong (drawn faded, never counted) / not reviewed."],
              ]}
            />
            <p>
              A link counts toward rankings if it was reviewed correct, or is an unreviewed ThreatFox tag or ATT&amp;CK citation.
              Unreviewed report mentions don't count. Link reviews, and the category labels of the
              {t.review ? ` ${int(t.review.hand_labelled_families)}` : ""} hand-labelled families (including the top {topN}), were done by an AI
              reviewer (Claude) on the owner's behalf, not fully blind; other families' categories come from MISP name matches.{t.review ? <> Result: {linkReview(t.review)}.</> : null}
            </p>
          </>
        ),
      },
      {
        id: "categories",
        title: "Indicators by category chart",
        body: (
          <p>
            One bar per category, length = ThreatFox indicators of families in it. It counts every ThreatFox family, not just the
            shown ones; grey bars are categories no shown family has. "unlabelled" holds named families with no category, and
            "unknown" also holds ThreatFox indicators with no family. A family can be in several categories, so the bars overlap
            and don't add up to the total.
          </p>
        ),
      },
      {
        id: "misreads",
        title: "Common misreadings",
        body: (
          <Misreads
            items={[
              ["\"Linked to a KEV CVE\" means the family exploited it.", "KEV says someone exploited it; ATT&CK can describe what software is able to do rather than observed use."],
              ["\"More indicators means more dangerous.\"", "Raw volume mostly reflects who submits to ThreatFox."],
              ["\"Selecting a family updates the address.\"", "Selecting a row in the table doesn't change the address; links to a family do."],
            ]}
          />
        ),
      },
      {
        id: "example",
        title: "Example",
        body: top ? (
          <Example>
            <a href={`#/threats/${encodeURIComponent(top.family)}`}>{top.family}</a> ranks first: {top.why[0] ?? "no reason recorded"}.
            It has {int(top.ioc_rows)} indicators ({signed(top.ioc_growth, 0)} new in the last 30 days vs the 30 before) and{" "}
            {int(top.linked_kev_cves)} linked KEV CVEs. Open its side panel to see how each link was found: an ATT&amp;CK citation can
            describe capability, not observed use.
          </Example>
        ) : (
          <Example>No threat families in this export.</Example>
        ),
      },
    ],
  };
};
