import { int } from "../../format";
import { Defs, Example, G, Misreads, type SectionBuilder } from "../common";

export const kev: SectionBuilder = (data) => {
  const entries = data.kev.entries;
  const threats = data.threats.available;
  const linked = entries.filter((e) => e.families.length > 0).length;
  const ransomware = entries.filter((e) => e.ransomware_use === "Known").length;
  const first = entries[0];
  return {
    id: "kev",
    title: "Known exploited",
    view: "kev",
    intro: (
      <p>
        Every CVE in CISA's Known Exploited Vulnerabilities catalog (<G to="concepts-vuln">KEV</G>), in the order to patch
        them. Someone has already exploited each one, so this list comes before anything the model predicts.
      </p>
    ),
    parts: [
      {
        id: "order",
        title: "How the order is built",
        body: (
          <>
            <p>A fixed rule, agreed before it was run. Nothing is predicted or scored. CVEs are sorted by:</p>
            <ol className="gd-steps">
              {threats && <li>Linked to a threat family first.</li>}
              <li>Then CISA's "known ransomware use".</li>
              <li>Then the newest CISA listing date.</li>
              <li>Then the CVE number, as a tie-break.</li>
            </ol>
            {threats && (
              <p>
                A threat link counts only if it was reviewed as correct, or is an unreviewed ThreatFox tag or ATT&amp;CK
                citation. A family merely named on a reference page doesn't count unless it was reviewed as correct. See{" "}
                <G to="threats-links">threat links</G>.
              </p>
            )}
          </>
        ),
      },
      {
        id: "table",
        title: "The table",
        body: (
          <Defs
            rows={[
              ["Order", "Position in the fixed order (1 = patch first). It is a global position: filtering hides rows but keeps their numbers, so gaps are normal."],
              ["CVE", "Click to show its detail on the right."],
              ["Vendor / product", "From CISA's KEV entry."],
              ...(threats ? ([["Linked threats", "Families tied to the CVE by a link that counts. Each opens the family on the Threats tab."]] as [string, string][]) : []),
              ["Ransomware", "\"known\" if CISA records known ransomware use. A dash means CISA's \"Unknown\", not \"no\"."],
              ["Listed", "The date CISA added the CVE to KEV. It is not a measure of how active exploitation is."],
            ]}
          />
        ),
      },
      {
        id: "filters",
        title: "Filters and search",
        body: (
          <p>
            {threats ? "\"Linked to a threat\" and " : ""}"Known ransomware use" are on/off filters; when both are on, a row must
            match both. The search box matches part of the CVE ID, CISA's name, vendor, product
            {threats ? " or a threat name" : ""}, ignoring case, and suggests vendors as you type. Results show 100 rows per page.
          </p>
        ),
      },
      {
        id: "detail",
        title: "The detail panel",
        body: (
          <Defs
            rows={[
              ["Heading", "The CVE and its place in the order."],
              ["Why line", "The reasons behind its position, e.g. which source ties a threat to it, ransomware use and the listing date."],
              ["Card", "CISA's name for the vulnerability, vendor and product, date added, the US federal due date (if any), the description, its CWE IDs and any linked threats."],
              ["Federal due date", "The deadline US federal agencies have under CISA directive BOD 22-01. A past date doesn't mean the CVE is fixed or no longer exploited."],
            ]}
          />
        ),
      },
      {
        id: "misreads",
        title: "Common misreadings",
        body: (
          <Misreads
            items={[
              ["\"#1 is the most dangerous CVE.\"", "It is first by the sort rule. Nothing ranks one KEV CVE as more dangerous than another, so the order isn't evaluated."],
              ...(threats
                ? ([["\"The linked family exploited this CVE.\"", "KEV says someone exploited it. The link says a source ties the family to the CVE; an ATT&CK entry may describe what the software can do rather than observed use, and a family named on a reference page only appears on a page about the CVE."]] as [string, string][])
                : []),
              ["\"Not in the risk queue means low risk.\"", "KEV CVEs are left out of the queue on purpose: they are already known to be exploited, so they need no prediction. Likewise, CVEs published before 2024 aren't scored at all."],
            ]}
          />
        ),
      },
      {
        id: "example",
        title: "Example",
        body: (
          <Example>
            This snapshot has {int(entries.length)} KEV CVEs
            {threats ? <>, {int(linked)} linked to a threat family</> : null} and {int(ransomware)} with known ransomware use.
            {first ? <> First in the order: <a href={`#/kev/${first.cve}`}>{first.cve}</a> ({first.why}).</> : null}
          </Example>
        ),
      },
    ],
  };
};
