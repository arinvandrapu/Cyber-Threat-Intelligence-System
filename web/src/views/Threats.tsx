import { useMemo, useState } from "react";
import type { Data, LinkedCve, ThreatFamily, ThreatLink } from "../types";
import { cveHref } from "../App";
import { PageHead, TierName } from "../components/ui";
import { int, signed } from "../format";

const SOURCE_LABEL: Record<ThreatFamily["category_source"], string> = {
  owner: "reviewed",
  misp: "unreviewed (MISP name match)",
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
  "attack:software": "cited by MITRE ATT&CK for this software",
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
  const cardByCve = useMemo(() => new Map(threats.linked_cves.map((k) => [k.cve, k])), [threats.linked_cves]);
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
        lede="Active malware and attack tools, ranked by what they exploit and how active they are. Each row says why."
      />

      <section className="grid tiles">
        <div className="panel tile">
          <span className="label">Families tracked</span>
          <span className="value">{int(threats.families_total)}</span>
          <span className="muted">top {int(threats.families.length)} shown</span>
        </div>
        <div className="panel tile">
          <span className="label">Exploiting known CVEs</span>
          <span className="value">{int(threats.families.filter((f) => f.linked_kev_cves > 0).length)}</span>
          <span className="muted">shown families linked to CISA KEV CVEs</span>
        </div>
        <div className="panel tile">
          <span className="label">Ransomware</span>
          <span className="value">{int(threats.families.filter((f) => f.categories.includes("ransomware")).length)}</span>
          <span className="muted">shown families</span>
        </div>
        <div className="panel tile">
          <span className="label">KEV CVEs used by ransomware</span>
          <span className="value">{int(threats.kev_ransomware_cves)}</span>
          <span className="muted">per CISA</span>
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
          <p className="caption" style={{ padding: "0 16px 14px" }}>Dashed badge: category not yet reviewed.</p>
        </div>

        <aside className="panel side" style={{ flexBasis: 360 }} aria-label="Selected family">
          {detail ? <FamilyDetail key={detail.family} family={detail} cards={cardByCve} /> : <p className="muted">Select a family.</p>}
        </aside>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Indicators by category</h2>
          <span className="muted" style={{ fontSize: 12.5 }}>ThreatFox indicators per category</span>
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
      </section>

      <details className="panel">
        <summary style={{ cursor: "pointer", fontWeight: 600 }}>How this list is built</summary>
        <div className="caption" style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <span>
            Families come from abuse.ch ThreatFox. They are ranked by a fixed rule, not a trained model: CVEs they are
            linked to that CISA lists as exploited (KEV), then linked high-risk CVEs from the risk queue, ransomware, and
            30-day growth in indicators. Threats never change a CVE's own rank.
          </span>
          <span>
            Links come from ThreatFox tags, MITRE ATT&amp;CK's descriptions of the software, and threat reports that name
            the family.{" "}
            {review
              ? `${review.links_correct} of ${review.links_reviewed} links were reviewed as correct; only reviewed-correct links and unreviewed ThreatFox or ATT&CK links count toward the ranking (✓ correct, ✗ wrong).`
              : ""}
          </span>
          <span>
            Categories of the top families were labelled by Claude on the owner's behalf; a dashed badge is an unreviewed
            match from the MISP galaxy, where names can collide. Indicator counts overlap across categories and are
            aggregates only (abuse.ch terms).
          </span>
          <span>
            ATT&amp;CK techniques and quoted ATT&amp;CK sentences: © The MITRE Corporation. This work is reproduced and
            distributed with the permission of The MITRE Corporation.
          </span>
        </div>
      </details>
    </>
  );
}

function FamilyDetail({ family: f, cards }: { family: ThreatFamily; cards: Map<string, LinkedCve> }) {
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
              {f.techniques.length} techniques across {f.tactics.length} tactics
            </span>
            <details>
              <summary className="muted" style={{ fontSize: 12.5, cursor: "pointer" }}>Techniques</summary>
              <p className="muted" style={{ margin: "6px 0 0", fontSize: 12 }}>Tactics: {f.tactics.join(", ")}</p>
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
        {f.links.map((l) => <LinkRow key={`${l.cve}-${l.via}`} link={l} card={cards.get(l.cve)} />)}
        {f.links.some((l) => !l.tier) && (
          <span className="muted" style={{ fontSize: 12 }}>Blue CVEs open in the risk queue; ▸ shows details.</span>
        )}
      </div>
    </div>
  );
}

const SOURCE_SHORT: Record<ThreatLink["via"], string> = {
  threatfox_tag: "ThreatFox",
  "mention:reference_page": "Report",
  "attack:software": "ATT&CK",
};
const REVIEW_MARK: Record<ThreatLink["review"], string> = { correct: "✓", rejected: "✗", unreviewed: "" };

export function LinkRow({ link: l, label, card }: { link: ThreatLink; label?: string; card?: LinkedCve }) {
  const [open, setOpen] = useState(false);
  const detail = `${VIA_LABEL[l.via]}${l.surface.length ? ` ("${l.surface.join('", "')}")` : ""} · ${REVIEW_LABEL[l.review]}${
    l.counts_for_priority ? "" : " · not counted in the ranking"
  }`;
  const toggle = (
    <button type="button" className="linkish" aria-expanded={open} onClick={() => setOpen(!open)} title={detail}>
      {label ?? l.cve} {open ? "▾" : "▸"}
    </button>
  );
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 2, opacity: l.review === "rejected" ? 0.55 : 1 }}>
      <span style={{ display: "flex", gap: 8, alignItems: "baseline", flexWrap: "wrap" }}>
        {/* a queued CVE opens in the risk queue; anything else expands in place */}
        {!label && l.tier ? <a className="mono" href={cveHref(l.cve)}>{l.cve}</a> : toggle}
        {!label && l.tier && (
          <button type="button" className="linkish muted" aria-expanded={open} onClick={() => setOpen(!open)} title={detail}>
            {open ? "▾" : "▸"}
          </button>
        )}
        {!label && l.in_kev && <span className="ev">in KEV</span>}
        {!label && l.tier && <TierName tier={l.tier} />}
        <span className="ev" title={detail}>
          {SOURCE_SHORT[l.via]} {REVIEW_MARK[l.review]}
        </span>
      </span>
      {open && (
        <div style={{ display: "flex", flexDirection: "column", gap: 4, marginTop: 2 }}>
          <span className="muted" style={{ fontSize: 12 }}>{detail}</span>
          {/* MITRE's sentence: plain text, never HTML or a link */}
          {l.evidence_text && (
            <span style={{ fontSize: 12, fontStyle: "italic", color: "var(--text-2)", overflowWrap: "anywhere" }}>
              “{l.evidence_text}”
            </span>
          )}
          {card && <CveCard entry={card} />}
        </div>
      )}
    </div>
  );
}

/** A linked CVE that is not in the risk queue: CISA's KEV entry, else its NVD record. */
export function CveCard({ entry: k }: { entry: LinkedCve }) {
  const what = [k.vendor, k.product].filter(Boolean).join(" ");
  return (
    <div className="note" style={{ display: "flex", flexDirection: "column", gap: 4, marginTop: 4 }}>
      {/* CISA/NVD text: plain text only, never HTML or a link */}
      <span style={{ fontWeight: 600, color: "var(--text)" }}>
        {k.name ?? k.cve}
        {k.source === "nvd" && k.name && <span className="faint" style={{ fontSize: 12, fontWeight: 400 }}> (derived name)</span>}
      </span>
      <span className="muted" style={{ fontSize: 12.5 }}>
        {k.source === "kev" ? (
          <>
            In CISA KEV (confirmed exploited){what ? ` · ${what}` : ""} · added {k.date_added}
            {k.due_date ? ` · federal due date ${k.due_date}` : ""}
            {k.ransomware_use === "Known" ? " · known ransomware use" : ""}
          </>
        ) : (
          <>
            Not in KEV and not in the risk queue (published {k.published ?? "?"}
            {k.published && k.published < "2024" ? ", before the queue's 2024 window" : ""}){what ? ` · ${what}` : ""}
          </>
        )}
      </span>
      <span style={{ fontSize: 13, overflowWrap: "anywhere" }}>{k.description}</span>
      <span className="mono muted" style={{ fontSize: 12 }}>
        {k.cwes.join(", ") || "no CWE"}
        {k.families.length > 0 && ` · linked threats: ${k.families.join(", ")}`}
      </span>
    </div>
  );
}
