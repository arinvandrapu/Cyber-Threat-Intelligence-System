import { useMemo, useState } from "react";
import type { Data, GraphNode } from "../types";
import { PageHead, Seg, useTooltip } from "../components/ui";
import { hash01, int } from "../format";

// ATT&CK Enterprise tactics in kill-chain order (positions on the ring)
// (v20 splits defense evasion into stealth and defense impairment; unknown tactics go last)
const TACTICS = [
  "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
  "privilege-escalation", "defense-evasion", "stealth", "defense-impairment", "credential-access",
  "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
];
const OTHER = "other";
const MAPPING = [
  ["exploitation_technique", "Exploitation technique"],
  ["primary_impact", "Primary impact"],
  ["secondary_impact", "Secondary impact"],
] as const;
type Mapping = (typeof MAPPING)[number][0];
const S = 840, C = S / 2, R_TACTIC = 340, R_TECH = 238, R_CVE = 128;

export function AttackGraph({ data }: { data: Data }) {
  const [mapping, setMapping] = useState<Mapping>("exploitation_technique");
  const [picked, setPicked] = useState<string | null>(null);
  const tip = useTooltip();
  const g = data.graphs.attack[mapping];
  const primary = data.evals.attack.test_nvd["prior+biencoder"]?.exploitation_technique;
  const majority = data.evals.attack.test_nvd.majority?.exploitation_technique;

  const model = useMemo(() => {
    if (!g) return null;
    const nodes = new Map(g.nodes.map((n) => [n.id, n]));
    const techTactics = new Map<string, string[]>();
    const techCves = new Map<string, string[]>();
    for (const e of g.edges) {
      const t = nodes.get(e.target);
      if (!t) continue;
      if (t.kind === "tactic") techTactics.set(e.source, [...(techTactics.get(e.source) ?? []), e.target]);
      if (t.kind === "technique") techCves.set(e.target, [...(techCves.get(e.target) ?? []), e.source]);
    }
    const unknown = g.nodes.filter((n) => n.kind === "tactic" && !TACTICS.includes(n.id)).map((n) => n.id).sort();
    const present = [...TACTICS.filter((t) => nodes.has(t)), ...unknown];
    // each technique's home = its first tactic in kill-chain order
    const techs = g.nodes
      .filter((n) => n.kind === "technique")
      .map((n) => {
        const tactics = (techTactics.get(n.id) ?? []).filter((t) => present.includes(t));
        tactics.sort((a, b) => present.indexOf(a) - present.indexOf(b));
        return { n, tactics, home: tactics[0] ?? OTHER, cves: techCves.get(n.id) ?? [] };
      });
    if (techs.some((x) => x.home === OTHER)) present.push(OTHER); // techniques with no tactic
    // every tactic gets an angular sector sized by its home techniques (+1 so empty ones show)
    const weight = (t: string) => techs.filter((x) => x.home === t).length + 1;
    const total = present.reduce((sum, t) => sum + weight(t), 0);
    const angle = new Map<string, number>();
    const placed: { n: GraphNode; a: number; x: number; y: number; tactics: string[]; cves: string[] }[] = [];
    let start = -Math.PI / 2 - (Math.PI * weight(present[0] ?? "")) / total;
    for (const t of present) {
      const span = (2 * Math.PI * weight(t)) / total;
      angle.set(t, start + span / 2);
      const mine = techs.filter((x) => x.home === t).sort((a, b) => (b.n.count ?? 0) - (a.n.count ?? 0) || a.n.id.localeCompare(b.n.id));
      mine.forEach((x, k) => {
        const a = start + (span * (k + 1)) / (mine.length + 1);
        const ring = R_TECH - (k % 2) * 30; // alternate radius so neighbours don't touch
        placed.push({ ...x, a, x: C + Math.cos(a) * ring, y: C + Math.sin(a) * ring });
      });
      start += span;
    }
    placed.sort((a, b) => (b.n.count ?? 0) - (a.n.count ?? 0) || a.n.id.localeCompare(b.n.id));
    const cves = g.nodes
      .filter((n) => n.kind === "cve")
      .map((n) => {
        const a = hash01(n.id) * 2 * Math.PI, r = 18 + Math.sqrt(hash01(`${n.id}r`)) * (R_CVE - 18);
        return { n, x: C + Math.cos(a) * r, y: C + Math.sin(a) * r };
      });
    return { present, angle, placed, cves, cvePos: new Map(cves.map((c) => [c.n.id, c])) };
  }, [g]);

  if (!g || !model) return <p className="empty">No ATT&amp;CK mappings in this export.</p>;
  const selected = model.placed.find((t) => t.n.id === picked) ?? model.placed[0];
  const selectedCves = new Set(selected?.cves ?? []);
  const radius = (n: GraphNode) => 5 + Math.sqrt(n.count ?? 1) * 2.4;

  return (
    <>
      <PageHead
        title="ATT&CK graph"
        lede="How exploited CVEs are used in attacks: CVE → ATT&CK technique → tactic (MITRE expert mappings)."
      >
        <Seg label="Mapping type" options={MAPPING} value={mapping} onChange={(m) => { setMapping(m); setPicked(null); }} />
      </PageHead>
      {tip.node}
      <section className="row">
        <figure className="panel grow" style={{ margin: 0, padding: 12 }}>
          <svg className="chart" viewBox={`0 0 ${S} ${S}`} role="img" aria-label="Radial graph: KEV CVEs in the centre, techniques in the middle ring, tactics on the outer ring" onMouseLeave={tip.hide}>
            <circle cx={C} cy={C} r={R_TACTIC} fill="none" stroke="var(--grid)" strokeDasharray="2 6" />
            <circle cx={C} cy={C} r={R_TECH} fill="none" stroke="var(--grid)" strokeDasharray="2 6" />
            {model.placed.flatMap((t) =>
              t.cves.map((cve) => {
                const p = model.cvePos.get(cve);
                if (!p) return null;
                const on = t === selected;
                return <line key={`${t.n.id}-${cve}`} x1={p.x} y1={p.y} x2={t.x} y2={t.y} stroke={on ? "var(--kev)" : "var(--border-2)"} strokeWidth="1" opacity={on ? 0.6 : 0.25} />;
              }),
            )}
            {model.placed.flatMap((t) =>
              t.tactics.map((tac) => {
                const a = model.angle.get(tac)!, on = t === selected;
                return <line key={`${t.n.id}-${tac}`} x1={t.x} y1={t.y} x2={C + Math.cos(a) * (R_TACTIC - 16)} y2={C + Math.sin(a) * (R_TACTIC - 16)} stroke={on ? "var(--accent)" : "var(--edge)"} strokeWidth={on ? 2 : 1} opacity={on ? 0.9 : 0.5} />;
              }),
            )}
            {model.cves.map(({ n, x, y }) => (
              <circle key={n.id} cx={x} cy={y} r="3.2" fill="var(--kev)" opacity={selectedCves.has(n.id) ? 1 : 0.35}
                onMouseMove={(e) => tip.show(e, <><b className="mono">{n.id}</b><br />in CISA KEV</>)} />
            ))}
            {model.placed.map((t) => {
              const on = t === selected;
              return (
                <g key={t.n.id} className="hit" onClick={() => setPicked(t.n.id)}
                  tabIndex={0} role="button" aria-label={`${t.n.id} ${t.n.label}, ${t.cves.length} KEV CVEs`} aria-pressed={on}
                  onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setPicked(t.n.id); } }}
                  onMouseMove={(e) => tip.show(e, <><b className="mono">{t.n.id}</b> {t.n.label}<br />{t.cves.length} KEV CVEs</>)}>
                  <circle cx={t.x} cy={t.y} r={radius(t.n)} fill={on ? "#262626" : "var(--raised)"} stroke={on ? "var(--accent)" : "var(--edge)"} strokeWidth="2" />
                  {(on || (t.n.count ?? 0) >= 8) && (
                    <text className="node-sub" x={t.x + Math.cos(t.a) * (radius(t.n) + 14)} y={t.y + Math.sin(t.a) * (radius(t.n) + 14) + 4}
                      textAnchor={Math.cos(t.a) > 0.3 ? "start" : Math.cos(t.a) < -0.3 ? "end" : "middle"} style={{ fill: "var(--text)" }}>{t.n.id}</text>
                  )}
                </g>
              );
            })}
            {model.present.map((tac) => {
              const a = model.angle.get(tac)!, x = C + Math.cos(a) * R_TACTIC, y = C + Math.sin(a) * R_TACTIC;
              const on = selected?.tactics.includes(tac);
              const label = tac === OTHER ? "No tactic" : tac.replace(/-/g, " ").replace(/\b\w/g, (m) => m.toUpperCase());
              return (
                <g key={tac}>
                  <rect x={x - 66} y={y - 13} width="132" height="26" rx="13" fill="var(--raised)" stroke={on ? "var(--accent)" : "var(--border-2)"} />
                  <text className="node-label" x={x} y={y + 4} textAnchor="middle" style={{ fontSize: 11 }}>{label}</text>
                </g>
              );
            })}
          </svg>
          <figcaption className="caption">
            Centre: {int(model.cves.length)} KEV CVEs (orange). {g.description}. Node size: KEV CVEs per technique;
            labels for techniques with 8 or more. Every CVE here is already in KEV, so none is in the risk queue.
          </figcaption>
        </figure>

        <aside className="panel side" aria-label="Selected technique">
          {selected && (
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              <span className="label">Selected technique</span>
              <div>
                <div className="mono" style={{ fontSize: 20, fontWeight: 600 }}>{selected.n.id}</div>
                <div style={{ fontSize: 14, color: "var(--text-2)" }}>{selected.n.label}</div>
                <div className="muted" style={{ fontSize: 12.5 }}>
                  tactic: {selected.tactics.map((t) => t.replace(/-/g, " ")).join(", ") || "—"}
                </div>
              </div>
              <div className="kv">
                <div><span className="label">KEV CVEs</span><span className="mono" style={{ fontSize: 20 }}>{selected.cves.length}</span></div>
                <div><span className="label">Techniques (all)</span><span className="mono" style={{ fontSize: 20 }}>{model.placed.length}</span></div>
              </div>
              <div className="mono" style={{ fontSize: 12.5, maxHeight: 220, overflowY: "auto", display: "flex", flexDirection: "column", gap: 3 }}>
                {[...selected.cves].sort().map((c) => <span key={c}><span className="dot" style={{ background: "var(--kev)" }} />{c}</span>)}
              </div>
              {primary && majority && (
                <p className="muted" style={{ margin: 0, fontSize: 12.5, lineHeight: 1.45, borderTop: "1px solid var(--border)", paddingTop: 12 }}>
                  The text-based mapper puts the right exploitation technique in its top 5 for{" "}
                  {(primary["hit@5"].value * 100).toFixed(1)}% of {primary.cves} held-out KEV CVEs (majority baseline{" "}
                  {(majority["hit@5"].value * 100).toFixed(1)}%). See Evaluation.
                </p>
              )}
            </div>
          )}
        </aside>
      </section>
    </>
  );
}
