import { hits, int, pct } from "../../format";
import { Defs, Example, G, Misreads, Swatch, type SectionBuilder } from "../common";

export const evaluation: SectionBuilder = (data) => {
  const r = data.evals.risk;
  const folds = Object.keys(r.folds).length;
  const lr = r.methods.logistic?.pooled;
  const ep = r.methods.epss?.pooled;
  const d = r.decision["logistic_minus_epss_hits@100"];
  const paired = typeof d === "object" ? d : null;
  const epssAhead = lr && ep ? ep.mean_average_precision > lr.mean_average_precision : false;
  // hit counts can be fractional under ties: never round them to a whole number
  const sHits = (x: number) => `${x > 0 ? "+" : x < 0 ? "−" : ""}${hits(Math.abs(x))}`;
  const boost = r.methods.boosting?.pooled;
  return {
    id: "evaluation",
    title: "Evaluation",
    view: "evaluation",
    intro: (
      <p>
        How well each part works on data it never saw, plus data versions and limitations. Read it to know how much to trust the
        numbers on the other tabs.
      </p>
    ),
    parts: [
      {
        id: "setup",
        title: "How the risk model was tested",
        body: (
          <p>
            The test re-runs history. At each of {folds} past cutoff dates, CVEs were scored using only what was known then, and
            the result was checked against which ones CISA added to KEV in the next 180 days (a{" "}
            <G to="concepts-stats">rolling-origin back-test</G>). Only CVEs published from 2024 and not yet in KEV at each cutoff
            count. The model, its settings and the decision rule were written down
            and committed before any test score was seen (<G to="concepts-stats">pre-registered</G>).
          </p>
        ),
      },
      {
        id: "banner",
        title: "The decision banner",
        body: (
          <Defs
            rows={[
              ["Rule", "The model beats EPSS only if the 95% range for (model hits − EPSS hits) in the top 100, summed over the test periods, is entirely above 0."],
              ["Extra KEV hits", "How many more later-KEV CVEs the model put in its top 100 than EPSS did."],
              ["95% range", <>From a <G to="concepts-stats">paired bootstrap</G>: both methods re-ranked on the same resampled CVEs many times, within each period and keeping the KEV / non-KEV mix. Models aren't refit, so it covers sampling noise, not training variation.</>],
              ["Top 1%", "A secondary check with a bigger list (1% of each period's CVEs)."],
            ]}
          />
        ),
      },
      {
        id: "recall",
        title: "KEV additions caught",
        body: (
          <>
            <p>One row per method; the "Budget" switch picks the top 100 or the top 1% of each period.</p>
            <Defs
              rows={[
                ["Dot", "Share of all later KEV additions the method put in its list (recall), with the count."],
                ["Line", <>The 95% interval (<G to="concepts-stats">Wilson</G>).</>],
                ["Dashed line", "What a random order would catch."],
                [<><Swatch color="model">Logistic</Swatch> <Swatch color="boosting">Boosting</Swatch></>, <>The headline model, and a more complex challenger{boost && lr ? ` (${hits(boost["hits@100"])} top-100 hits vs ${hits(lr["hits@100"])})` : ""} that doesn't rank the dashboard because the headline model was fixed in advance; its result is secondary.</>],
                [<><Swatch color="epss">EPSS</Swatch> <Swatch color="faint">SSVC rule</Swatch> <Swatch color="other">CVSS †</Swatch></>, "Baselines. CVSS uses today's scores, which can reflect later exploitation, so it is shown for illustration only."],
              ]}
            />
            <p>The axis ends just past the largest interval, so tick values aren't round numbers.</p>
          </>
        ),
      },
      {
        id: "folds",
        title: "Per-fold table, AP and base rate",
        body: (
          <Defs
            rows={[
              ["Per fold", "For each test period: its cutoff date, eligible CVEs, KEV additions, and top-100 hits for the model, EPSS and boosting. Always top 100, whatever the switch says."],
              ["Mean AP", <><G to="concepts-stats">Average precision</G> judges the whole ranking, not just the top; a random order scores about the base rate.{epssAhead ? " EPSS scores higher on it: the model's gain sits at the very top of the list." : ""}</>],
              ["Base rate", "The share of all eligible CVEs that were added to KEV: what a random pick would hit."],
              ["Per hit", "How much one extra hit moves recall. With few additions, single hits matter."],
            ]}
          />
        ),
      },
      {
        id: "tiers",
        title: "Tier hit rates",
        body: (
          <p>
            For each tier, the share of its CVEs added to KEV in the test periods, with a 95% interval on a log scale (0.01% to
            10%). "Monotonic" means each tier's rate is above the next one down, as the pre-registered check expected. These are historical rates
            from the back-test, not a check of today's ranking, which can't be scored until time passes.
          </p>
        ),
      },
      {
        id: "other",
        title: "Other pipeline evaluations",
        body: (
          <Defs
            rows={[
              ["ATT&CK technique mapping", <>The automatic mapper's <G to="concepts-stats">hit@5</G> (a correct technique in its top 5) against always guessing the most common techniques, from an early test; a later test on new CVEs found no reliable gain. Not shown on the ATT&amp;CK graph.</>],
              ["CWE classification", <>Predicting a CVE's weakness from its description, scored by <G to="concepts-stats">macro-F1</G> on descriptions that don't name the weakness. A simple word-weight model (TF-IDF) beat a security language model (SecureBERT).</>],
              ["IOC extraction", "Share of extracted values that were real values of their type, on a sample labelled by an AI reviewer. The weighted figure is dominated by CVE IDs. The weakest figure shown, IPv4 across all sources, is pulled down by IPs in NVD descriptions; samples per type are small."],
              ["SecureBERT NER (Malware)", "How many malware names a language model finds, against rule-made labels. Context only; never used for scoring."],
            ]}
          />
        ),
      },
      {
        id: "limits",
        title: "Limitations and disclosures",
        body: (
          <p>
            "Limitations" lists what the tests can't show, such as that KEV is a lagging, incomplete label. "Data versions &amp;
            disclosures" gives the exact code commit, config hash, KEV catalog version, the EPSS model version at each date, and
            every disclosure the export makes about choices that could affect the numbers.
          </p>
        ),
      },
      {
        id: "misreads",
        title: "Common misreadings",
        body: (
          <Misreads
            items={[
              ["\"The decision says which method is better overall.\"", "It is about the top 100 only. Average precision judges the whole list and can disagree."],
              ["\"Tier hit rates measure today's list.\"", "They come from past periods; today's ranking isn't evaluated yet."],
              ["\"Hits of 1.5 are a bug.\"", "Tied scores split credit, so hits can be fractional."],
              ["\"Small differences are findings.\"", "With so few KEV additions, only large gains are detectable."],
            ]}
          />
        ),
      },
      {
        id: "example",
        title: "Example",
        body: (
          <Example>
            {lr && ep && paired ? (
              <>
                Over {folds} test periods with {int(lr.positives)} KEV additions, the model's top-100 lists caught {hits(lr["hits@100"])} and
                EPSS's {hits(ep["hits@100"])}: {sHits(paired.difference_hits)} (95% range {sHits(paired.ci95[0])} to{" "}
                {sHits(paired.ci95[1])}). Verdict: {r.decision.verdict}. Mean AP: model {lr.mean_average_precision.toFixed(3)}, EPSS{" "}
                {ep.mean_average_precision.toFixed(3)}. One hit is {pct(1 / Math.max(1, lr.positives))} of recall.
              </>
            ) : (
              "Risk evaluation results are missing from this export."
            )}
          </Example>
        ),
      },
    ],
  };
};
