import { int, pct } from "../../format";
import { Defs, Example, G, Misreads, Swatch, type SectionBuilder } from "../common";

export const indicators: SectionBuilder = (data) => {
  const { iocs, evals } = data;
  const pages = evals.extract.per_origin.reference_page;
  const hosts = data.graphs.shared_hosts.nodes.filter((n) => n.kind === "host").sort((a, b) => (b.count ?? 0) - (a.count ?? 0));
  return {
    id: "indicators",
    title: "Indicators",
    view: "indicators",
    intro: (
      <p>
        IP addresses, domains, URLs and file hashes found on the web pages CVEs reference. Context for hunting and blocking, and
        for spotting infrastructure shared across CVEs. They are indicator-<em>shaped</em> strings, not vetted as malicious:
        many are vendor advisories, patch hashes or researchers' sites.
      </p>
    ),
    parts: [
      {
        id: "safety",
        title: "Defanged values",
        body: (
          <p>
            Every value is <G to="concepts-threat">defanged</G> so it can't be clicked or resolved by accident:{" "}
            <span className="mono">http</span> becomes <span className="mono">hxxp</span>, dots become{" "}
            <span className="mono">[.]</span>, IPv6 colons become <span className="mono">[:]</span> (ftp and sftp become{" "}
            <span className="mono">fxp</span> and <span className="mono">sfxp</span>). Values are shown as text, never
            links, and "Copy" copies the defanged form. Re-fang a value only in a tool built to handle it safely.
          </p>
        ),
      },
      {
        id: "graph",
        title: "Shared-host graph",
        body: (
          <>
            <p>Hosts that appear on the reference pages of two or more CVEs.</p>
            <Defs
              rows={[
                [<Swatch color="model" square>Squares on the ring</Swatch>, "Hosts, largest (most CVEs) first, clockwise from the top. Bigger square = more CVEs, counting all of them even though at most 30 dots are drawn per host. The 10 largest are labelled."],
                ["Dots inside", "CVEs. A CVE with one shared host sits near it; one with several sits between them, towards the centre."],
                ["Dot colour", <><Swatch color="critical">tier</Swatch> if scored, <Swatch color="kev">orange</Swatch> if in KEV, <Swatch color="other">grey</Swatch> if not scored. Baseline dots use the palest pink.</>],
              ]}
            />
            <p>
              Click a host to highlight its CVEs (click again to clear); click a CVE to open it. Common sites like cve.org and
              nvd.nist.gov are left out, as are non-public IP addresses, and the graph stops at 30 hosts and 30 CVEs per host (the caption says when it was cut).
              Vendor and advisory sites dominate: a shared host is a lead, not a link to an attacker.
            </p>
          </>
        ),
      },
      {
        id: "feeds",
        title: "abuse.ch feeds (aggregates only)",
        body: (
          <p>
            Record counts from abuse.ch's ThreatFox and URLhaus feeds, the top ThreatFox malware families by record count, and
            ThreatFox records by threat type (the infrastructure's role, such as payload or botnet C2 server). abuse.ch's terms allow
            only counts here, so no feed value is exported. These bars are feed volume, not the <G to="threats">Threats</G> ranking.
          </p>
        ),
      },
      {
        id: "table",
        title: "Indicator table",
        body: (
          <>
            <Defs
              rows={[
                ["Type", "URL, domain, IPv4, IPv6, MD5, SHA-1 or SHA-256."],
                ["Value", "The defanged string."],
                ["CVEs", "The two lowest-numbered CVEs whose references contain it; \"+N more\" expands the rest (up to 10 are kept per value)."],
                ["Seen", "How many times it was extracted across reference pages, not how many CVEs."],
                ["IP scope", "Public or non-public (private, loopback, documentation ranges). Non-public IPs are hidden until you switch them on."],
              ]}
            />
            <p>
              Search matches the defanged text, so type <span className="mono">example[.]com</span>, not{" "}
              <span className="mono">example.com</span>; it also matches CVE IDs. Rows are ordered by how many CVEs share the value.
              50 per page.
            </p>
          </>
        ),
      },
      {
        id: "misreads",
        title: "Common misreadings",
        body: (
          <Misreads
            items={[
              ["\"These are IOCs from attacks.\"", "They are strings of an indicator's shape found on CVE references; nothing here is vetted as malicious."],
              ["\"A host shared by many CVEs is attacker infrastructure.\"", "It is usually a vendor or advisory site."],
              ["\"The headline extraction precision applies to every row.\"", "It is weighted and dominated by CVE IDs, which this table leaves out. Hashes and IPs scored lower on small samples (see Evaluation)."],
            ]}
          />
        ),
      },
      {
        id: "example",
        title: "Example",
        body: (
          <Example>
            {int(iocs.indicators.length)} unique values from {int(iocs.reference_pages)} reference pages.
            {hosts[0] ? <> The most shared host is <span className="mono">{hosts[0].label}</span>, on {int(hosts[0].count ?? 0)} CVEs' references.</> : null}
            {pages ? <> On an AI-labelled sample, {pct(pages.precision)} of reference-page extractions were real values of their type, a figure dominated by CVE IDs, which this table leaves out.</> : null}
          </Example>
        ),
      },
    ],
  };
};
