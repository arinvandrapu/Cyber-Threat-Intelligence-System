import { int } from "../../format";
import { Defs, G, type SectionBuilder } from "../common";

/** Glossary. Part ids are link targets: concepts-vuln, -threat, -attack, -ranking, -model, -stats. */
export const concepts: SectionBuilder = () => ({
  id: "concepts",
  title: "Concepts",
  intro: <p>The terms used across the dashboard, with the exact meaning this project gives them.</p>,
  parts: [
    {
      id: "vuln",
      title: "Vulnerability data",
      body: (
        <Defs
          rows={[
            ["CVE", "A public ID for one vulnerability (CVE-year-number)."],
            ["CISA KEV", "CISA's Known Exploited Vulnerabilities catalog: CVEs with reliable evidence that someone has exploited them and clear remediation guidance. It is US-government-focused and lags real exploitation. The risk model's target is whether a CVE is added to it."],
            ["EPSS", "FIRST's Exploit Prediction Scoring System: a daily probability that exploitation activity against a CVE is observed (by EPSS's data partners) in the next 30 days, and its percentile among all CVEs. A public baseline the model is compared with; the model uses the percentile as a signal."],
            ["SSVC", "Stakeholder-Specific Vulnerability Categorization, a CERT/CC framework. Here: the decision-point values CISA publishes (Vulnrichment): exploitation (none / PoC / active), automatable (yes / no) and technical impact (partial / total, shown as full control)."],
            ["CVSS", "A 0–10 severity score from NVD or the reporting organisation. Severity, not likelihood; not a risk-model input."],
            ["CWE", "MITRE's list of weakness types (the kind of bug). A pillar is the top level of its Research Concepts view (CWE-1000)."],
            ["NVD, CNA", "NIST's National Vulnerability Database, and the CVE Numbering Authority (often the vendor) that issued the ID and its first description."],
            ["Derived name", "A short name built from the affected product and weakness when CISA has none. Not an official title."],
            ["ExploitDB, Metasploit, Nuclei", "Public collections of exploit code, attack modules and scanner templates. Commonly read as signs of exploitability; in this model Nuclei carries weight and ExploitDB and Metasploit little once the others are counted (see Risk landscape)."],
          ]}
        />
      ),
    },
    {
      id: "threat",
      title: "Threat data",
      body: (
        <Defs
          rows={[
            ["Threat family", "A named piece of malware or attack tool, as ThreatFox names it."],
            ["ThreatFox, URLhaus", "abuse.ch's community feeds of malware indicators and malicious URLs. This project publishes only counts from them, per its reading of abuse.ch's terms."],
            ["MISP galaxy", "Open, community-maintained lists of malware names by type, used to suggest categories for unreviewed families."],
            ["Threat link", "A source tying a family to a CVE: a ThreatFox tag, a reference-page mention, or an ATT&CK citation. See the Threats section."],
            ["IOC", "Indicator of compromise: an IP, domain, URL or hash that can reveal an attack. On Indicators it means a string of that shape, not a vetted one."],
            ["Defanged", "Altered so it can't be clicked or resolved (hxxp, [.], [:])."],
          ]}
        />
      ),
    },
    {
      id: "attack",
      title: "MITRE ATT&CK",
      body: (
        <Defs
          rows={[
            ["Tactic", "The attacker's goal at a step, e.g. initial access or privilege escalation."],
            ["Technique", "How the goal is reached (T-number). Sub-techniques are merged into their parent here."],
            ["Software", "An ATT&CK entry for a malware family or tool (S-number)."],
            ["CTID mappings", "MITRE Center for Threat-Informed Defense's expert mapping of a subset of KEV CVEs to the techniques used to exploit them and their impact."],
          ]}
        />
      ),
    },
    {
      id: "ranking",
      title: "Ranking terms",
      body: (
        <Defs
          rows={[
            ["Scored", "Given a rank and tier: published from 2024 onward and not in KEV."],
            ["Tier", "A rank band: critical top 0.1%, high 0.1–1%, elevated 1–5%, baseline the rest. Not a probability."],
            ["In the queue", "Critical, high or elevated."],
            ["Below the queue", "Scored, but in the baseline tier."],
            ["Not scored", "Published before 2024 (outside the window) or already in KEV."],
            ["Rank", "Position by model score; tied scores share their average rank."],
          ]}
        />
      ),
    },
    {
      id: "model",
      title: "Model terms",
      body: (
        <Defs
          rows={[
            ["Logistic regression", "A simple model that adds up weighted signals into a score. Chosen because each CVE's score can be split into exact per-signal parts."],
            ["Standardized", "Each signal is rescaled so one unit is one standard deviation, making weights comparable."],
            ["Weight", "How much a signal counts per standard deviation; its sign is the direction."],
            ["Contribution", "Weight × this CVE's standardized value: how far this signal moved it from an average training CVE. Contributions add up (in log-odds)."],
            ["Imputed (†)", "A missing value replaced with the training median."],
            ["Refit", "The model retrained on all labelled periods to rank today's CVEs, after testing; not itself back-tested."],
          ]}
        />
      ),
    },
    {
      id: "stats",
      title: "Evaluation terms",
      body: (
        <Defs
          rows={[
            ["Pre-registered", "Method, settings and decision rule committed before any test score was seen, so results couldn't steer the choices."],
            ["Rolling-origin back-test (folds)", "Train on everything before a cutoff, test on the period after it; repeat for several cutoffs. Each is a fold."],
            ["Hits@100, recall", "How many later KEV additions landed in the top 100 of each period, summed (ties give fractional credit), and that as a share of all of them."],
            ["Average precision (AP)", "The average of the precision at each positive's position in the ranking: how high the positives sit across the whole list. A random order scores about the base rate."],
            ["Wilson interval", "A 95% range for a proportion computed from its counts. It stays closer to its stated coverage than the simple ±1.96 × standard error interval when counts are small or the rate is near 0."],
            ["Paired bootstrap", "Resampling the test CVEs many times (within each period, keeping the KEV / non-KEV mix) and re-ranking both methods' existing scores on each resample, to get a 95% range for their difference."],
            ["hit@5", "Whether any of the reference labels is among a method's top five guesses."],
            ["Macro-F1", "The average, over the known weakness classes ('other' excluded), of a balance of precision and recall, so rare classes count equally."],
          ]}
        />
      ),
    },
  ],
});

export const dataSection: SectionBuilder = (data) => {
  const { meta } = data;
  return {
    id: "data",
    title: "Data & freshness",
    intro: <p>Where the numbers come from and when they were true.</p>,
    parts: [
      {
        id: "snapshot",
        title: "One snapshot",
        body: (
          <p>
            One snapshot of the public feeds, dated {meta.snapshot_date}, stored unchanged; every refetch is logged in its manifest,
            and a few reference files (such as the ATT&amp;CK mappings) are pinned separately. Everything else is computed from that
            copy. The dashboard fetches nothing external: only the exported JSON files served with it. To update it, take a new
            snapshot and re-run the pipeline.
          </p>
        ),
      },
      {
        id: "pinning",
        title: "Point-in-time data",
        body: (
          <p>
            For the back-tests, each model signal is taken as it was on the cutoff date (for example the EPSS score that day), so
            the model never sees information from after its cutoff. The exceptions are labelled snapshot-time: the CVSS baseline
            and the NVD context fields. The cutoff dates are listed on <G to="evaluation">Evaluation</G>.
          </p>
        ),
      },
      {
        id: "versions",
        title: "Versions",
        body: (
          <Defs
            rows={[
              ["KEV catalog", meta.kev_catalog_version],
              ["Code", `commit ${String(meta.git.commit ?? "").slice(0, 7)}${meta.git.dirty ? " (uncommitted changes)" : ""}`],
              ["Disclosures", `${int(meta.disclosures.length)} statements, listed on Evaluation`],
            ]}
          />
        ),
      },
      {
        id: "licences",
        title: "Licences and attribution",
        body: (
          <p>
            abuse.ch data (ThreatFox, URLhaus) appears only as counts, per this project's reading of its terms. ATT&amp;CK techniques and quoted
            ATT&amp;CK sentences are © The MITRE Corporation, reproduced with its permission. CISA KEV and Vulnrichment data are public domain (CC0); EPSS scores are by FIRST; the CTID mappings are
            Apache-2.0; CWE is © MITRE. This product uses NVD data but is not endorsed or certified by the NVD.
          </p>
        ),
      },
    ],
  };
};
