import { FEATURE_LABEL, int, signed } from "../../format";
import { Defs, Example, G, Misreads, Swatch, type SectionBuilder } from "../common";

export const landscape: SectionBuilder = (data) => {
  const { risk } = data;
  const coefs = [...risk.coefficients].sort((a, b) => Math.abs(b.refit) - Math.abs(a.refit));
  const big = coefs[0];
  const positives = Object.values(risk.training_positives).reduce((s, n) => s + n, 0);
  return {
    id: "landscape",
    title: "Risk landscape",
    view: "landscape",
    intro: <p>Charts of the whole ranking: where the model agrees with EPSS, what it weighs, and what the top tiers are made of.</p>,
    parts: [
      {
        id: "scatter",
        title: "Model rank vs EPSS percentile",
        body: (
          <>
            <p>One point per queue CVE that has an EPSS score.</p>
            <Defs
              rows={[
                ["Up", "Better model rank; rank 1 is at the top. The axis is logarithmic and its gridlines are the tier edges (top 0.1%, 1%, 5%)."],
                ["Right", "Higher EPSS percentile. The axis stretches the crowded top end: 90th → 99th takes the same width as 99th → 99.9th. That squeezes the bottom: everything below the 50th percentile shares the leftmost sliver, and in this snapshot that is most of the queue."],
                ["Colour", <><Swatch color="critical">critical</Swatch> <Swatch color="high">high</Swatch> <Swatch color="elevated">elevated</Swatch> (critical drawn on top, slightly larger). The tier pills show or hide each tier.</>],
                ["High and to the left", "CVEs the model ranks well above where EPSS alone would put them: where the two disagree."],
              ]}
            />
            <p>Hover for the rank and EPSS values; click to open the CVE in the risk queue.</p>
          </>
        ),
      },
      {
        id: "weights",
        title: "What drives the model",
        body: (
          <>
            <p>One row per signal: how much it counts in the model ranking today.</p>
            <Defs
              rows={[
                [<Swatch color="accent" square>Blue, right</Swatch>, "A higher value of this signal ranks a CVE higher."],
                [<Swatch color="faint" square>Grey, left</Swatch>, "A higher value ranks it lower (e.g. age: older CVEs rank lower)."],
                ["Number", <>The weight per one standard deviation of the signal (<G to="concepts-model">standardized</G>), so weights of different signals can be compared.</>],
                ["Bracketed number", "The weight in the version tested on the last back-test period. Only the first number is drawn as a bar, and only the bracketed version was back-tested: the refit used every labelled period, so nothing is left to test it on."],
              ]}
            />
            <p>
              The bar version was refit on all {int(risk.training_rows)} CVE-windows with {int(positives)} KEV additions. With so few
              additions, single weights move between fits, likely because related signals share credit. Weights describe signals
              that go together with KEV listing, not causes.
            </p>
          </>
        ),
      },
      {
        id: "coverage",
        title: "Signal coverage by tier",
        body: (
          <p>
            Each cell is the share of all CVEs in a tier with that signal (missing counted as "no"): public exploit (ExploitDB or
            Metasploit), Nuclei template, SSVC exploitation PoC or active, SSVC automatable, no SSVC assessment, no EPSS score.
            Below 2% the cell is grey; from 2% up, brighter blue means a larger share (steps at 10%, 30% and 60%). Unlike the scatter, it includes the
            baseline tier, so you can see which signals separate the queue from the rest.
          </p>
        ),
      },
      {
        id: "months",
        title: "Critical + high CVEs by publication month",
        body: (
          <p>
            Stacked bars: <Swatch color="critical">critical</Swatch> at the bottom, <Swatch color="high">high</Swatch> on top, for
            the last 18 months that have any. The newest month is partial (it ends on the snapshot date) yet usually tallest,
            mostly because the model weights recency heavily, so don't read it as a trend.
          </p>
        ),
      },
      {
        id: "misreads",
        title: "Common misreadings",
        body: (
          <Misreads
            items={[
              ["\"Points are spread evenly across EPSS.\"", "Both axes are stretched; look at the tick labels."],
              ["\"A big weight means the signal causes exploitation.\"", "Weights show which signals go together with KEV listing in the training data."],
              ["\"Grey means the signal is switched off.\"", "Grey means a negative weight."],
              ["\"A grey bar on an exploit signal means exploits make a CVE safer.\"", "Near-zero weights on signals that overlap with others are credit-sharing, not protection."],
              ["\"The monthly chart shows vulnerability trends.\"", "It shows where the model's top tiers fall, which leans toward new CVEs."],
            ]}
          />
        ),
      },
      {
        id: "example",
        title: "Example",
        body: big ? (
          <Example>
            The largest weight in size is "{FEATURE_LABEL[big.feature] ?? big.feature}" at {signed(big.refit)} ({signed(big.evaluated_last_fold)} in
            the tested version).
          </Example>
        ) : (
          <Example>No model weights in this export.</Example>
        ),
      },
    ],
  };
};
