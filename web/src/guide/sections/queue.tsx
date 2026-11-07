import { FEATURE_LABEL, epss, int, signed } from "../../format";
import { Defs, Example, G, Misreads, Swatch, type SectionBuilder } from "../common";

export const queue: SectionBuilder = (data) => {
  const { risk, threats } = data;
  const count = (t: string) => risk.tiers.find((x) => x.name === t)?.cves ?? 0;
  const top = risk.rows[0];
  const r = data.evals.risk;
  const d = r.decision["logistic_minus_epss_hits@100"];
  const paired = typeof d === "object" ? d : null;
  const lr = r.methods.logistic?.pooled;
  const ep = r.methods.epss?.pooled;
  const queued = new Set(risk.rows.map((x) => x.cve));
  const early = new Set(
    threats.families.flatMap((f) => f.links.filter((l) => l.counts_for_priority && queued.has(l.cve)).map((l) => l.cve)),
  ).size;
  const drivers = top ? Object.entries(top.contributions).sort((a, b) => Math.abs(b[1]) - Math.abs(a[1])).slice(0, 3) : [];
  return {
    id: "queue",
    title: "Risk queue",
    view: "queue",
    intro: (
      <p>
        The CVEs not yet in KEV that a model ranks likeliest to be added to it, best first, each with the signals that moved it.
        It is the "patch next" list after <G to="kev">Known exploited</G>.
      </p>
    ),
    parts: [
      {
        id: "scope",
        title: "What is in the queue",
        body: (
          <>
            <p>
              CVEs published from 2024 onward and not in KEV are scored ({int(risk.ranked_cves)} today) and given a{" "}
              <G to="concepts-ranking">tier</G> by rank. The queue is the top three tiers:
            </p>
            <Defs
              rows={[
                [<Swatch color="critical">Critical</Swatch>, `Top 0.1% by rank (${int(count("critical"))} CVEs).`],
                [<Swatch color="high">High</Swatch>, `Top 0.1–1% (${int(count("high"))}).`],
                [<Swatch color="elevated">Elevated</Swatch>, `Top 1–5% (${int(count("elevated"))}).`],
                [<Swatch color="baseline">Baseline</Swatch>, "The rest: scored, but below the queue, so not listed here."],
              ]}
            />
            <p>
              A CVE missing from the queue is in one of three places: already in KEV (patch it first), scored below the queue, or
              published before 2024 and not scored. A KEV CVE opens in Known exploited. Any other CVE shows a note; when the export
              holds the CVE (one referenced on another tab), the note says which case applies and shows its NVD record.
            </p>
          </>
        ),
      },
      {
        id: "table",
        title: "The table",
        body: (
          <Defs
            rows={[
              ["Rank", "1 is the highest score. Tied scores share their average rank, so a rank like 12.5 is possible."],
              ["CVE", <>Click to show its detail.{threats.available ? " A \"threat\" badge means a counted threat link; it never changes the rank." : ""}</>],
              ["Tier", "The rank band (dot colour as above)."],
              ["EPSS", <>FIRST's <G to="concepts-vuln">EPSS</G> probability and, in brackets, its percentile among all CVEs. Percentiles are rounded down, so you'll see "99.98th", never "100th".</>],
              ["SSVC", <>CISA's <G to="concepts-vuln">SSVC</G> assessment as three parts: exploited (no / PoC / yes) · automatable (yes / no) · technical impact (partial / full control). "?" means that part is missing; "no SSVC data" means all three are.</>],
              ["Exploit evidence", "EDB (ExploitDB entry), MSF (Metasploit module), Nuclei (Nuclei scanner template): public exploit or detection code that existed on the snapshot date."],
              ["Age", "Days from publication to the snapshot."],
              ["CVSS, CWE", "Severity (NVD's score, else the reporting organisation's) and weakness labels, in grey because they are context only: the model never used them. CVSS, CWE and SSVC are hidden on narrow screens."],
            ]}
          />
        ),
      },
      {
        id: "controls",
        title: "Filters, search and sorting",
        body: (
          <ul className="plain">
            <li>Tier pills show one tier at a time; "All tiers" shows the whole queue. Counts are queue rows.</li>
            <li>Search matches part of the CVE ID, a CWE, the assigner, vendor, product or derived name, ignoring case.</li>
            <li>"Exploit evidence only" keeps rows with at least one of EDB / MSF / Nuclei.</li>
            {threats.available && <li>"Linked to a threat" keeps rows with a counted threat link ({int(early)} today): a possible early warning, since a source ties the family to the CVE before CISA lists it. It hasn't been evaluated as a predictor.</li>}
            <li>Sortable headers: Rank (best first), EPSS (by percentile, highest first), Age (newest first), CVSS (highest first). The arrow marks the active sort.</li>
            <li>100 rows per page; any change returns to page 1.</li>
          </ul>
        ),
      },
      {
        id: "detail",
        title: "\"What moved this CVE up or down\"",
        body: (
          <>
            <p>The detail panel breaks the CVE's score into one bar per signal, largest first.</p>
            <Defs
              rows={[
                [<Swatch color="accent" square>Blue, to the right</Swatch>, "This signal pushed the CVE up compared with an average CVE the model was trained on."],
                [<Swatch color="faint" square>Grey, to the left</Swatch>, "This signal pushed it down."],
                ["Number", <>The push in model score units (log-odds). The bars <G to="concepts-model">add up</G> to the score, before a constant common to every CVE.</>],
                ["†", "The CVE had no value for this signal on the snapshot date, so a typical (median) value was used."],
                ["Bar length", "Scaled to this CVE's largest bar (or to 1.0 if every bar is smaller), so bar lengths can't be compared between CVEs; compare the numbers instead."],
              ]}
            />
            <p>
              Signals: EPSS percentile, whether EPSS is missing, SSVC exploitation / automatable / full-control impact, whether SSVC
              is missing, ExploitDB, Metasploit, Nuclei, and age. "Age (older ranks lower)" names the weight's direction: on a new
              CVE its bar is blue.
            </p>
            <p>
              Below the bars: the description, CVSS, CWEs, the assigner (the CVE Numbering Authority that issued the ID) and
              {threats.available ? " any threat links not reviewed as wrong, with their source and review status," : ""} then the EPSS model version used.
            </p>
          </>
        ),
      },
      {
        id: "model",
        title: "How the ranking is computed",
        body: (
          <p>
            A logistic regression trained to predict whether CISA adds a CVE to KEV within 180 days, using only signals known on
            the snapshot date. Its set-up was fixed before it was tested, and it was checked on past periods it never saw.
            {paired && lr && ep ? (
              <>
                {" "}On the pre-registered measure, top-100 hits, it caught {signed(paired.difference_hits, 0)} later KEV additions compared
                with EPSS (95% range {signed(paired.ci95[0], 0)} to {signed(paired.ci95[1], 0)}, out of {int(lr.positives)})
                {ep.mean_average_precision > lr.mean_average_precision ? ", but EPSS had the higher mean average precision" : ""}.
              </>
            ) : null}{" "}
            The details and results are on <G to="evaluation">Evaluation</G>; how the weights look is on{" "}
            <G to="landscape">Risk landscape</G>.
          </p>
        ),
      },
      {
        id: "misreads",
        title: "Common misreadings",
        body: (
          <Misreads
            items={[
              ["\"Rank 1 has the highest chance of exploitation.\"", "Rank is an order, not a probability, and the score was never checked as one. Use tiers and their past hit rates for scale."],
              ["\"A grey ExploitDB or SSVC PoC bar means exploit code lowers risk.\"", "Once Metasploit, Nuclei and EPSS are counted, these add almost nothing (weights near zero); because they are rare, a near-zero weight can still show as a visible bar. The panel notes this when it happens."],
              ["\"Bars compare to zero evidence.\"", "They compare to an average training CVE."],
              ["\"Age 900 d counts more than 400 d.\"", "The model caps age at a year, so every CVE over a year old gets the same age push."],
              ["\"CVSS 9.8 should be near the top.\"", "CVSS is not a model input. Severity and likelihood of exploitation are different questions."],
            ]}
          />
        ),
      },
      {
        id: "example",
        title: "Example",
        body: top ? (
          <Example>
            <a href={`#/queue/${top.cve}`}>{top.cve}</a> is rank {top.rank} with EPSS {epss(top.epss, top.epss_percentile)}. Its
            biggest pushes: {drivers.map(([f, v], i) => (
              <span key={f}>
                {i > 0 ? (i === drivers.length - 1 ? " and " : ", ") : ""}
                {FEATURE_LABEL[f] ?? f} ({signed(v)})
              </span>
            ))}.
          </Example>
        ) : (
          <Example>The queue is empty in this export.</Example>
        ),
      },
    ],
  };
};
