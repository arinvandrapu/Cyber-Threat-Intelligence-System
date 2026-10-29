import { useMemo, useState } from "react";
import type { Data, KevEntry, ThreatFamily, ThreatLink } from "../types";
import { cveHref } from "../App";
import { PageHead, TierName } from "../components/ui";
import { int, signed } from "../format";

const SOURCE_LABEL: Record<ThreatFamily["category_source"], string> = {
  owner: "hand-labelled",
  misp: "MISP galaxy name match",
  none: "no category",
};
const REVIEW_LABEL: Record<ThreatLink["review"], string> = {
  correct: "reviewed: correct",
  rejected: "reviewed: rejected",
  unreviewed: "unreviewed",
};
const VIA_LABEL: Record<ThreatLink["via"], string> = {
  threatfox_tag: "ThreatFox CVE tag",
  "mention:reference_page": "named on a CVE reference page",
};

export function Threats({ data }: { data: Data }) {
  const { threats } = data;
  const [category, setCategory] = useState("all");
  const [selected, setSelected] = useState<string | null>(threats.families[0]?.family ?? null);

  // only categories some shown family has, so no filter leads to an empty table
  const categories = useMemo(
    () => ["all", ...[...new Set(threats.families.flatMap((f) => f.categories))].sort()],
    [threats.families],
  );
  const kevByCve = useMemo(() => new Map(threats.kev.map((k) => [k.cve, k])), [threats.kev]);
  const rows = useMemo(
    () => threats.families.filter((f) => category === "all" || f.categories.includes(category)),
    [threats.families, category],
  );

  if (!threats.available) {
    return (
      <>
        <PageHead title="Threats" />
        <div className="panel empty">
          <p>The threat catalog has not been built for this snapshot.</p>
          <pre className="mono note">cti threats --date {data.meta.snapshot_date}{"\n"}cti export --date {data.meta.snapshot_date}</pre>
        </div>
      </>
    );
  }

  const review = threats.review;
  // keep the side panel on a family the table still shows
  const detail = rows.find((f) => f.family === selected) ?? rows[0] ?? null;
  const maxRows = Math.max(1, ...threats.categories.map((c) => c.ioc_rows));

  return (
    <>
      <PageHead
        title="Threats"
        lede={
          <>
            Malware and tool families seen in ThreatFox, ranked by a pre-declared heuristic: linked CVEs confirmed exploited
            in CISA KEV, then linked high-risk queue CVEs, ransomware, and 30-day indicator growth. Each row says why. This
            ranking is not a validated model, and threats never change a CVE's risk rank.
          </>
        }
      />

      <section className="grid tiles">
        <div className="panel tile">
          <span className="label">Families tracked</span>
          <span className="value">{int(threats.families_total)}</span>
          <span className="muted">{int(threats.families.length)} shown: top by priority, plus any with a CVE link</span>
        </div>
        <div className="panel tile">
          <span className="label">Hand-labelled categories</span>
          <span className="value">{int(review?.hand_labelled_families ?? 0)}</span>
          <span className="muted">the rest use MISP name matches, which can collide</span>
        </div>
        <div className="panel tile">
          <span className="label">CVE links reviewed correct</span>
          <span className="value">
            {review ? `${review.links_correct} / ${review.links_reviewed}` : "—"}
          </span>
          <span className="muted">
            {review?.link_precision_ci95
              ? `95% CI ${Math.round(review.link_precision_ci95[0] * 100)}–${Math.round(review.link_precision_ci95[1] * 100)}% · ranking counts reviewed-correct links and unreviewed ThreatFox tags`
              : ""}
          </span>
        </div>
        <div className="panel tile">
          <span className="label">KEV CVEs used by ransomware</span>
          <span className="value">{int(threats.kev_ransomware_cves)}</span>
          <span className="muted">CISA names no family, so these link to the category only</span>
        </div>
      </section>

      <section className="toolbar" aria-label="Filter by category">
        {categories.map((c) => (
          <button key={c} type="button" className="pill" aria-pressed={category === c} onClick={() => setCategory(c)}>
            {c === "all" ? "All categories" : c}
          </button>
        ))}
      </section>

      <section className="row">
        <div className="panel grow" style={{ padding: 0, overflow: "hidden" }}>
          <div className="table-wrap">
            <table className="data compact">
              <thead>
                <tr className="label">
                  <th>Rank</th>
                  <th>Family</th>
                  <th>Category</th>
                  <th>Why it ranks here</th>
                  <th>KEV CVEs</th>
                  <th>IOCs (30-day change)</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((f) => (
                  <tr key={f.family} className={f.family === detail?.family ? "selected" : undefined}>
                    <td className="mono muted">{f.rank}</td>
                    <td>
                      <button type="button" className="linkish" onClick={() => setSelected(f.family)} aria-pressed={f.family === detail?.family}>
                        {f.family}
                      </button>
                    </td>
                    <td>
                      {f.categories.map((c) => (
                        <span key={c} className="ev" style={f.category_source === "owner" ? undefined : { borderStyle: "dashed" }}>
                          {c}
                        </span>
                      ))}
                      {f.categories.length === 0 && <span className="muted">—</span>}
                    </td>
                    <td style={{ fontSize: 13, whiteSpace: "normal", minWidth: 220 }}>{f.why[0]}</td>
                    <td className="mono">{f.linked_kev_cves || <span className="muted">0</span>}</td>
                    <td className="mono muted">
                      {int(f.ioc_rows)} ({signed(f.ioc_growth, 0)})
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {rows.length === 0 && <p className="empty">No shown family has this category.</p>}
          </div>
          <p className="caption" style={{ padding: "0 16px 14px" }}>
            Solid badges: hand-checked category. Dashed: unchecked MISP name match (names can collide). The top of the
            ranking is always hand-checked (the export refuses otherwise); lower families appear only because of a CVE link
            not reviewed as wrong.
          </p>
        </div>

        <aside className="panel side" style={{ flexBasis: 360 }} aria-label="Selected family">
          {detail ? <FamilyDetail key={detail.family} family={detail} kev={kevByCve} /> : <p className="muted">Select a family.</p>}
        </aside>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Indicators by category</h2>
          <span className="muted" style={{ fontSize: 12.5 }}>
            ThreatFox IOC rows · categories overlap, so rows can count twice
          </span>
        </div>
        {threats.categories.map((c) => (
          <div key={c.category} className="bar-row">
            <span>{c.category}</span>
            <svg className="chart" viewBox="0 0 100 10" preserveAspectRatio="none" height="10" aria-hidden="true">
              <rect x="0" y="1" width={(100 * c.ioc_rows) / maxRows} height="8" fill="var(--accent)" />
            </svg>
            <span className="mono" style={{ textAlign: "right" }}>{int(c.ioc_rows)}</span>
          </div>
        ))}
        <p className="caption">
          Unlabelled rows belong to families with no category yet; unknown rows were submitted without a family. Counts
          are aggregates only: abuse.ch terms forbid redistributing the indicators themselves.
        </p>
      </section>
    </>
  );
}

function FamilyDetail({ family: f, kev }: { family: ThreatFamily; kev: Map<string, KevEntry> }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        <span className="label">Rank {f.rank}</span>
        {/* family names come from ThreatFox: plain text, never a link */}
        <span style={{ fontSize: 20, fontWeight: 600, overflowWrap: "anywhere" }}>{f.family}</span>
        <span className="muted" style={{ fontSize: 13 }}>
          {f.categories.join(", ") || "no category"} · {SOURCE_LABEL[f.category_source]}
        </span>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        <span className="label">Why it ranks here</span>
        <ul style={{ margin: 0, paddingLeft: 18, fontSize: 13.5, lineHeight: 1.6, color: "var(--text-2)" }}>
          {f.why.map((w) => <li key={w}>{w}</li>)}
        </ul>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 6, borderTop: "1px solid var(--border)", paddingTop: 14 }}>
        <span className="label">ATT&amp;CK</span>
        {f.attack_software ? (
          <>
            <span className="mono" style={{ fontSize: 13 }}>
              {f.attack_software} · {f.attack_name}
            </span>
            <span className="muted" style={{ fontSize: 12.5 }}>
              {f.techniques.length} techniques across {f.tactics.length} tactics:{" "}
              {f.tactics.join(", ")}
            </span>
            <details>
              <summary className="muted" style={{ fontSize: 12.5, cursor: "pointer" }}>Techniques</summary>
              <ul className="mono" style={{ margin: "6px 0 0", paddingLeft: 18, fontSize: 12, lineHeight: 1.6 }}>
                {f.techniques.map((t) => <li key={t.id}>{t.id} {t.name}</li>)}
              </ul>
            </details>
          </>
        ) : (
          <span className="muted" style={{ fontSize: 13 }}>No ATT&amp;CK software with this exact name.</span>
        )}
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 8, borderTop: "1px solid var(--border)", paddingTop: 14 }}>
        <span className="label">Linked CVEs</span>
        {f.links.length === 0 && <span className="muted" style={{ fontSize: 13 }}>None found.</span>}
        {f.links.map((l) => <LinkRow key={`${l.cve}-${l.via}`} link={l} kev={kev.get(l.cve)} />)}
        {f.links.some((l) => !l.tier) && (
          <span className="muted" style={{ fontSize: 12 }}>
            Blue CVEs are in the risk queue. KEV CVEs are confirmed exploited, so they are never ranked: open one for its
            CISA entry.
          </span>
        )}
      </div>
    </div>
  );
}

export function LinkRow({ link: l, label, kev }: { link: ThreatLink; label?: string; kev?: KevEntry }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 2, opacity: l.review === "rejected" ? 0.55 : 1 }}>
      <span style={{ display: "flex", gap: 8, alignItems: "baseline", flexWrap: "wrap" }}>
        {label ? (
          <span style={{ fontWeight: 600 }}>{label}</span>
        ) : l.tier ? (
          <a className="mono" href={cveHref(l.cve)}>{l.cve}</a>
        ) : kev ? (
          <button type="button" className="linkish" style={{ textDecoration: "underline dotted" }} aria-expanded={open} onClick={() => setOpen(!open)}>
            {l.cve} {open ? "▾" : "▸"}
          </button>
        ) : (
          <span className="mono">{l.cve}</span>
        )}
        {/* in a CVE's own detail (label = family) its KEV status and tier are already shown */}
        {!label && l.in_kev && <span className="ev">in KEV</span>}
        {!label && l.tier && <TierName tier={l.tier} />}
      </span>
      <span className="muted" style={{ fontSize: 12 }}>
        {VIA_LABEL[l.via]}
        {l.surface.length ? ` ("${l.surface.join('", "')}")` : ""} · {REVIEW_LABEL[l.review]}
        {l.counts_for_priority ? "" : " · not counted in the ranking"}
      </span>
      {open && kev && <KevCard entry={kev} />}
    </div>
  );
}

/** A KEV CVE's CISA entry: its only detail, since KEV CVEs are never in the risk queue. */
export function KevCard({ entry: k }: { entry: KevEntry }) {
  return (
    <div className="note" style={{ display: "flex", flexDirection: "column", gap: 4, marginTop: 4 }}>
      {/* CISA text: plain text only, never HTML or a link */}
      <span style={{ fontWeight: 600, color: "var(--text)" }}>{k.name}</span>
      <span className="muted" style={{ fontSize: 12.5 }}>
        {k.vendor} {k.product} · added to KEV {k.date_added}
        {k.due_date ? ` · federal due date ${k.due_date}` : ""}
        {k.ransomware_use === "Known" ? " · known ransomware use" : ""}
      </span>
      <span style={{ fontSize: 13, overflowWrap: "anywhere" }}>{k.description}</span>
      <span className="mono muted" style={{ fontSize: 12 }}>
        {k.cwes.join(", ") || "no CWE"} · linked threats: {k.families.join(", ")}
      </span>
    </div>
  );
}
