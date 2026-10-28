import { useMemo, useState } from "react";
import type { Data, GraphNode, Tier } from "../types";
import { PageHead, Seg, TierDot, useTooltip } from "../components/ui";
import { TIER_LABEL, int } from "../format";
import { cveHref, openCve } from "../App";

const W = 980, TOP = 34, ROW = 40, CVE_ROW = 22, MAX_CWES = 16, MAX_CVES = 26;
const PX = 16, PW = 230, CX = 360, CW = 270, VX = 760;

export function WeaknessGraph({ data }: { data: Data }) {
  const g = data.graphs.weakness;
  const tip = useTooltip();
  const [scope, setScope] = useState<"critical" | "both">("both");

  const model = useMemo(() => {
    const byId = new Map(g.nodes.map((n) => [n.id, n]));
    const tierOf = (id: string) => byId.get(id)?.tier ?? null;
    const inScope = (cve: string) => scope === "both" || tierOf(cve) === "critical";
    const cvesOf = new Map<string, string[]>();
    const pillarOf = new Map<string, string>();
    for (const e of g.edges) {
      const s = byId.get(e.source), t = byId.get(e.target);
      if (!s || !t) continue;
      if (t.kind === "cve" && inScope(t.id)) cvesOf.set(s.id, [...(cvesOf.get(s.id) ?? []), t.id]);
      if (s.kind === "pillar" && t.kind === "cwe") pillarOf.set(t.id, s.id);
    }
    const cwes = g.nodes
      .filter((n) => n.kind === "cwe")
      .map((n) => ({ node: n, cves: cvesOf.get(n.id) ?? [] }))
      .filter((c) => c.cves.length > 0)
      .sort((a, b) => b.cves.length - a.cves.length || a.node.id.localeCompare(b.node.id));
    const top = cwes.slice(0, MAX_CWES);
    const pillars = [...new Set(top.map((c) => pillarOf.get(c.node.id)!))]
      .map((id) => byId.get(id)!)
      .filter(Boolean)
      .map((p) => ({ node: p, cwes: top.filter((c) => pillarOf.get(c.node.id) === p.id) }))
      .sort((a, b) => b.cwes.reduce((s, c) => s + c.cves.length, 0) - a.cwes.reduce((s, c) => s + c.cves.length, 0));
    // CWEs ordered under their pillar, so edges don't cross
    const ordered = pillars.flatMap((p) => p.cwes);
    // scope-aware counts: distinct in-scope CVEs per pillar, directly or through a CWE
    const pillarCves = new Map<string, Set<string>>();
    for (const n of g.nodes.filter((x) => x.kind === "pillar")) pillarCves.set(n.id, new Set(cvesOf.get(n.id) ?? []));
    for (const c of cwes) {
      const set = pillarCves.get(pillarOf.get(c.node.id) ?? "");
      c.cves.forEach((v) => set?.add(v));
    }
    const allInScope = new Set([...pillarCves.values()].flatMap((s) => [...s]));
    const tierTotal = data.risk.tiers
      .filter((t) => t.name === "critical" || (scope === "both" && t.name === "high"))
      .reduce((a, t) => a + t.cves, 0);
    return { byId, pillars, ordered, rest: cwes.length - top.length, cveTotal: allInScope.size, tierTotal, pillarOf, pillarCves };
  }, [g, scope, data.risk.tiers]);

  const rankIndex = useMemo(() => new Map(data.risk.rows.map((r) => [r.cve, r.rank])), [data.risk.rows]);
  const [picked, setPicked] = useState<string | null>(null);
  const selected = model.ordered.find((c) => c.node.id === picked) ?? model.ordered[0];

  // layout
  const cweY = new Map(model.ordered.map((c, i) => [c.node.id, TOP + i * ROW]));
  let y = TOP;
  const pillarBoxes = model.pillars.map((p) => {
    const first = cweY.get(p.cwes[0]!.node.id)!;
    const last = cweY.get(p.cwes[p.cwes.length - 1]!.node.id)!;
    const box = { p, y: Math.max(y, first), h: Math.max(last - first + 30, 46) };
    y = box.y + box.h + 10;
    return box;
  });
  // the best-ranked CVEs of the selected CWE (sort first, then cut)
  const ranked = [...(selected?.cves ?? [])].sort((a, b) => rankOf(a) - rankOf(b));
  const cves = ranked.slice(0, MAX_CVES);
  const height = Math.max(TOP + model.ordered.length * ROW, y, TOP + cves.length * CVE_ROW) + 20;
  const selY = selected ? cweY.get(selected.node.id)! + 15 : 0;
  const maxCount = Math.max(1, ...model.ordered.map((c) => c.cves.length));

  function rankOf(cve: string): number {
    return rankIndex.get(cve) ?? Infinity;
  }

  return (
    <>
      <PageHead
        title="Weakness graph"
        lede="Which weakness families the top-tier CVEs come from: CWE pillar → CWE → CVE. CWE labels come from the NVD and CNA records and are context only, never model inputs."
      >
        <Seg label="Tiers" options={[["critical", "Critical tier"], ["both", "Critical + high"]] as const} value={scope} onChange={setScope} />
      </PageHead>
      {tip.node}
      <section className="row">
        <figure className="panel grow" style={{ margin: 0, padding: 12 }}>
          <svg className="chart" viewBox={`0 0 ${W} ${height}`} role="img" aria-label="Layered graph from CWE pillars to CWEs to the CVEs of the selected CWE" onMouseLeave={tip.hide}>
            <text className="node-sub" x={PX} y={18}>CWE PILLAR</text>
            <text className="node-sub" x={CX} y={18}>CWE (top {MAX_CWES} by CVEs)</text>
            <text className="node-sub" x={VX} y={18}>
              {ranked.length > cves.length ? `TOP ${cves.length} OF ${ranked.length} CVEs, BY RANK` : "CVEs OF THE SELECTED CWE"}
            </text>
            {pillarBoxes.map(({ p, y: py, h }) =>
              p.cwes.map((c) => {
                const y1 = py + h / 2, y2 = cweY.get(c.node.id)! + 15, on = c === selected;
                return (
                  <path key={c.node.id} d={`M${PX + PW} ${y1} C${PX + PW + 55} ${y1} ${CX - 55} ${y2} ${CX} ${y2}`} fill="none"
                    stroke={on ? "var(--accent)" : "var(--edge)"} strokeWidth={1 + (c.cves.length / maxCount) * 8} opacity={on ? 0.9 : 0.45} />
                );
              }),
            )}
            {cves.map((cve, i) => {
              const cy = TOP + 6 + i * CVE_ROW;
              return <path key={cve} d={`M${CX + CW} ${selY} C${CX + CW + 60} ${selY} ${VX - 60} ${cy} ${VX - 8} ${cy}`} fill="none" stroke={`var(--${model.byId.get(cve)?.tier ?? "elevated"})`} strokeWidth="1.2" opacity="0.7" />;
            })}
            {pillarBoxes.map(({ p, y: py, h }) => (
              <g key={p.node.id}>
                <rect x={PX} y={py} width={PW} height={h} rx="6" fill="var(--raised)" stroke="var(--border-2)" />
                <text className="node-label" x={PX + 12} y={py + 20}>{truncate(p.node.label, 32)}</text>
                <text className="node-sub" x={PX + 12} y={py + 36}>{p.node.id} · {int(model.pillarCves.get(p.node.id)?.size ?? 0)} CVEs in scope</text>
              </g>
            ))}
            {model.ordered.map((c) => {
              const cy = cweY.get(c.node.id)!, on = c === selected;
              return (
                <g key={c.node.id} className="hit" onClick={() => setPicked(c.node.id)}
                  tabIndex={0} role="button" aria-label={`${c.node.id} ${c.node.label}, ${c.cves.length} CVEs`} aria-pressed={on}
                  onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setPicked(c.node.id); } }}
                  onMouseMove={(e) => tip.show(e, <><b className="mono">{c.node.id}</b> {c.node.label}<br />{c.cves.length} CVEs in scope</>)}>
                  <rect x={CX} y={cy} width={CW} height="30" rx="6" fill={on ? "#262626" : "var(--raised)"} stroke={on ? "var(--accent)" : "var(--border-2)"} />
                  <text className="node-label" x={CX + 10} y={cy + 19}>
                    <tspan className="mono">{c.node.id}</tspan> <tspan className="node-sub">{truncate(c.node.label, 22)}</tspan>
                  </text>
                  <text className="node-sub" x={CX + CW - 10} y={cy + 19} textAnchor="end">{c.cves.length}</text>
                </g>
              );
            })}
            {cves.map((cve, i) => {
              const cy = TOP + 6 + i * CVE_ROW, n = model.byId.get(cve);
              return (
                <g key={cve} className="hit" onClick={() => openCve(cve)}
                  onMouseMove={(e) => tip.show(e, <><b className="mono">{cve}</b><br />{n?.tier ? TIER_LABEL[n.tier] : ""} tier · click to open</>)}>
                  <circle cx={VX} cy={cy} r="5" fill={`var(--${n?.tier ?? "elevated"})`} />
                  <text className="node-sub" x={VX + 12} y={cy + 4} style={{ fill: "var(--text)" }}>{cve}</text>
                </g>
              );
            })}
          </svg>
          <figcaption className="caption">
            {g.description}. Edge width: CVEs per CWE. {model.rest > 0 ? `${model.rest} smaller CWEs not drawn. ` : ""}
            {int(model.cveTotal)} of {int(model.tierTotal)} CVEs in scope carry a weakness CWE; the rest have
            none or only a category label.
          </figcaption>
        </figure>

        <aside className="panel side" aria-label="Selected weakness">
          {selected ? <WeaknessDetail cwe={selected.node} cves={ranked} pillar={model.byId.get(model.pillarOf.get(selected.node.id) ?? "")} tierOf={(c) => model.byId.get(c)?.tier ?? null} /> : <p className="muted">No CWEs in scope.</p>}
        </aside>
      </section>
    </>
  );
}

function WeaknessDetail({ cwe, cves, pillar, tierOf }: { cwe: GraphNode; cves: string[]; pillar?: GraphNode; tierOf: (c: string) => Tier | null }) {
  const byTier = (t: Tier) => cves.filter((c) => tierOf(c) === t).length;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <span className="label">Selected CWE</span>
      <div>
        <div className="mono" style={{ fontSize: 20, fontWeight: 600 }}>{cwe.id}</div>
        <div style={{ fontSize: 14, color: "var(--text-2)" }}>{cwe.label}</div>
        {pillar && <div className="muted" style={{ fontSize: 12.5 }}>pillar {pillar.id} · {pillar.label}</div>}
      </div>
      <div className="kv">
        <div><span className="label">Critical</span><span className="mono" style={{ fontSize: 20 }}>{byTier("critical")}</span></div>
        <div><span className="label">High</span><span className="mono" style={{ fontSize: 20 }}>{byTier("high")}</span></div>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 4, maxHeight: 320, overflowY: "auto" }}>
        {cves.map((c) => {
          const t = tierOf(c);
          return (
            <a key={c} href={cveHref(c)} className="mono" style={{ fontSize: 13, textDecoration: "none", color: "var(--text)" }}>
              {t ? <TierDot tier={t} /> : null}{c}
            </a>
          );
        })}
      </div>
      <span className="muted" style={{ fontSize: 12.5 }}>Click a CWE in the graph to trace it; a CVE opens in the risk queue.</span>
    </div>
  );
}

function truncate(text: string, n: number): string {
  return text.length > n ? `${text.slice(0, n - 1)}…` : text;
}
