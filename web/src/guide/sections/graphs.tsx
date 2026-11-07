import { int, pct } from "../../format";
import { Defs, Example, G, Misreads, Swatch, type SectionBuilder } from "../common";

export const weakness: SectionBuilder = (data) => {
  const nodes = data.graphs.weakness.nodes;
  const cwes = nodes.filter((n) => n.kind === "cwe").sort((a, b) => (b.count ?? 0) - (a.count ?? 0) || a.id.localeCompare(b.id));
  const pillars = nodes.filter((n) => n.kind === "pillar").length;
  return {
    id: "weakness",
    title: "Weakness graph",
    view: "weakness",
    intro: (
      <p>
        The kinds of bug behind the highest-risk CVEs. Recurring weakness types point to root causes worth fixing across
        products, not just one patch at a time.
      </p>
    ),
    parts: [
      {
        id: "read",
        title: "How to read it",
        body: (
          <>
            <p>Three columns, read left to right:</p>
            <Defs
              rows={[
                ["CWE pillar", <>The top level of MITRE's <G to="concepts-vuln">CWE</G> Research Concepts view (CWE-1000), reached through each weakness's primary parent. The sub-line counts the CVEs under it in scope, including ones whose CWE isn't drawn.</>],
                ["CWE", "A specific weakness, e.g. an out-of-bounds write. The 16 with the most CVEs in scope are drawn; the number on the right is how many. Names are cut at 30 characters; hover for the full name."],
                ["CVEs", <>The CVEs of the selected CWE, best rank first (up to 26), as dots in their tier colour (<Swatch color="critical">critical</Swatch> <Swatch color="high">high</Swatch>).</>],
                ["Line width", "Pillar → CWE lines are thicker for CWEs with more CVEs. The selected CWE's line is blue."],
              ]}
            />
            <p>
              Click a CWE (or tab to it and press Enter) to select it; the panel on the right lists all its CVEs with tier counts,
              and a CVE opens in the risk queue. The "Tiers" switch picks the scope: critical only, or critical + high.
            </p>
          </>
        ),
      },
      {
        id: "computed",
        title: "Where the labels come from",
        body: (
          <p>
            Each CVE's CWE labels are those NVD or the reporting organisation (CNA) assigned. Only labels that are real weaknesses
            with a pillar are drawn; CVEs with no CWE or only a broad category label are left out (the caption counts them), as
            are placeholders (NVD-CWE-Other, NVD-CWE-noinfo) and deprecated IDs. The
            CWE is context only: the risk model never used it.
          </p>
        ),
      },
      {
        id: "misreads",
        title: "Common misreadings",
        body: (
          <Misreads
            items={[
              ["\"Pillar counts should equal the sum of their CWE rows.\"", "A pillar counts each CVE once, including undrawn CWEs; a CVE with two CWEs appears in both rows."],
              ["\"This CWE makes CVEs high-risk.\"", "It shows which weaknesses the top tiers contain. Labels depend on who assigned them."],
              ["\"The right column lists every CVE.\"", "It stops at 26; the side panel has all of them."],
            ]}
          />
        ),
      },
      {
        id: "example",
        title: "Example",
        body: cwes[0] ? (
          <Example>
            Across critical and high CVEs, the most common weakness is {cwes[0].id} ({cwes[0].label}) with {int(cwes[0].count ?? 0)} CVEs. The graph has {pillars} pillars in all; only those above the drawn CWEs appear.
          </Example>
        ) : (
          <Example>No weakness labels in this export.</Example>
        ),
      },
    ],
  };
};

export const attack: SectionBuilder = (data) => {
  const g = data.graphs.attack.exploitation_technique;
  const techniques = g ? g.nodes.filter((n) => n.kind === "technique").sort((a, b) => (b.count ?? 0) - (a.count ?? 0)) : [];
  const cves = g ? g.nodes.filter((n) => n.kind === "cve").length : 0;
  const mapper = data.evals.attack.test_nvd["prior+biencoder"]?.exploitation_technique;
  const majority = data.evals.attack.test_nvd.majority?.exploitation_technique;
  return {
    id: "attack",
    title: "ATT&CK graph",
    view: "attack",
    intro: (
      <p>
        How the KEV CVEs that MITRE's Center for Threat-Informed Defense has mapped (a subset of KEV) are used in attacks, in{" "}
        <G to="concepts-attack">ATT&amp;CK</G> terms: CVE → technique → tactic. It connects vulnerabilities to attacker behaviour,
        which ATT&amp;CK links to detection guidance (not shown here).
      </p>
    ),
    parts: [
      {
        id: "read",
        title: "How to read it",
        body: (
          <>
            <p>A wheel, read from the centre outwards:</p>
            <Defs
              rows={[
                [<Swatch color="kev">Centre dots</Swatch>, "KEV CVEs. Their positions inside the disc are spread at random to avoid overlap; position means nothing."],
                ["Middle ring", "Techniques. Bigger circle = more KEV CVEs mapped to it. IDs are labelled for techniques with 8 or more."],
                ["Outer ring", "Tactics (the attacker's goal), in attack-chain order clockwise from the top."],
                ["Slices", "Each technique sits in the slice of its first tactic; a wider slice has more techniques, not more CVEs. Lines from a technique go to all its tactics."],
              ]}
            />
            <p>
              Click a technique to select it: its CVE lines turn orange and its tactics blue, and the side panel lists its CVEs (most
              expand to CISA's entry). The "Mapping type" switch shows how a CVE is exploited ("Exploitation technique") or what
              exploiting it lets the attacker do (primary or secondary impact).
            </p>
          </>
        ),
      },
      {
        id: "computed",
        title: "Where the mappings come from",
        body: (
          <p>
            Expert mappings of KEV CVEs published by MITRE's Center for Threat-Informed Defense, not predictions. Sub-techniques are
            merged into their parent technique. An automatic text-based mapper was also built and tested, but it wasn't strong
            enough to show here; the side panel's footnote and <G to="evaluation">Evaluation</G> give its score.
          </p>
        ),
      },
      {
        id: "misreads",
        title: "Common misreadings",
        body: (
          <Misreads
            items={[
              ["\"CVEs near each other are related.\"", "Positions in the centre are random spreading."],
              ["\"These CVEs are in the risk queue.\"", "All are already in KEV, so none is in the queue."],
              ["\"The footnote score describes this graph.\"", "It is the score of the automatic mapper, whose output isn't drawn. The graph itself is expert ground truth."],
            ]}
          />
        ),
      },
      {
        id: "example",
        title: "Example",
        body: techniques[0] ? (
          <Example>
            {int(cves)} KEV CVEs have an exploitation-technique mapping. The most common exploitation technique is {techniques[0].id} ({techniques[0].label}) with{" "}
            {int(techniques[0].count ?? 0)} CVEs.
            {mapper && majority ? <> In a first test the automatic mapper put a correct technique in its top 5 for {pct(mapper["hit@5"].value, 0)} of held-out CVEs, against {pct(majority["hit@5"].value, 0)} for always guessing the most common ones. That gain was fragile. A later pre-registered test on older, non-KEV CVEs found at most a small gain, resting on a rule written after the counts were seen, so the mapper's output isn't drawn.</> : null}
          </Example>
        ) : (
          <Example>No ATT&amp;CK mappings in this export.</Example>
        ),
      },
    ],
  };
};
