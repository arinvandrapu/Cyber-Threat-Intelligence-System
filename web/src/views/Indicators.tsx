import { useMemo, useState } from "react";
import type { Data, Graph } from "../types";
import { PageHead, Pager, TierDot, useTooltip } from "../components/ui";
import { hash01, int } from "../format";
import { openCve } from "../App";

const PAGE = 50;
const TYPE_LABEL: Record<string, string> = {
  url: "URL", domain: "Domain", ipv4: "IPv4", ipv6: "IPv6", md5: "MD5", sha1: "SHA-1", sha256: "SHA-256",
};

export function Indicators({ data }: { data: Data }) {
  const { iocs } = data;
  const [query, setQuery] = useState("");
  const [type, setType] = useState("all");
  const [showLocal, setShowLocal] = useState(false);
  const [page, setPage] = useState(0);
  const [copied, setCopied] = useState<string | null>(null);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return iocs.indicators.filter(
      (i) =>
        (type === "all" || i.type === type) &&
        (showLocal || i.public !== false) &&
        (!q || i.value.toLowerCase().includes(q) || i.cves.some((c) => c.toLowerCase().includes(q))),
    );
  }, [iocs.indicators, query, type, showLocal]);
  const hiddenLocal = iocs.indicators.filter((i) => i.public === false).length;
  const pages = Math.max(1, Math.ceil(rows.length / PAGE));
  const shown = rows.slice(page * PAGE, (page + 1) * PAGE);
  const tf = iocs.feeds.threatfox, uh = iocs.feeds.urlhaus;
  const famMax = Math.max(1, ...(tf?.top_families ?? []).map(([, n]) => n));

  async function copy(value: string) {
    try {
      await navigator.clipboard.writeText(value); // the defanged value, never the live one
      setCopied(value);
      window.setTimeout(() => setCopied((v) => (v === value ? null : v)), 2000);
    } catch {
      setCopied(null);
    }
  }

  return (
    <>
      <PageHead title="Indicators" />
      <span className="sr-only" aria-live="polite">{copied ? `Copied ${copied}` : ""}</span>
      <div className="warn" role="note">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#f5c46b" strokeWidth="2" aria-hidden="true" style={{ flex: "none", marginTop: 1 }}>
          <path d="M12 3l10 18H2L12 3z" /><path d="M12 10v5M12 18h.01" />
        </svg>
        <span>
          {iocs.title}: many are vendor advisories, patch hashes or researchers' hosts. Every value is defanged and
          shown as text, never as a link.
        </span>
      </div>

      <section className="grid tiles" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))" }}>
        <div className="panel tile" style={{ padding: 14 }}>
          <span className="label">Unique values</span>
          <span className="value" style={{ fontSize: 22 }}>{int(iocs.indicators.length)}</span>
        </div>
        {Object.entries(iocs.by_type).map(([t, n]) => (
          <div key={t} className="panel tile" style={{ padding: 14 }}>
            <span className="label">{TYPE_LABEL[t] ?? t}</span>
            <span className="value" style={{ fontSize: 22 }}>{int(n)}</span>
          </div>
        ))}
        <div className="panel tile" style={{ padding: 14 }}>
          <span className="label">Reference pages</span>
          <span className="value" style={{ fontSize: 22 }}>{int(iocs.reference_pages)}</span>
        </div>
      </section>

      <section className="row">
        <SharedHosts graph={data.graphs.shared_hosts} />
        <div className="panel side">
          <div className="panel-head"><h2>abuse.ch feeds (aggregates only)</h2></div>
          <p className="muted" style={{ margin: "0 0 12px", fontSize: 12.5 }}>
            ThreatFox {int(tf?.records ?? 0)} · URLhaus {int(uh?.records ?? 0)} records at the snapshot. Feed values are
            never exported (licence).
          </p>
          <span className="label">Top malware families · ThreatFox</span>
          <div style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 8 }}>
            {(tf?.top_families ?? []).slice(0, 12).map(([name, n]) => (
              <div key={name} className="bar-row" style={{ gridTemplateColumns: "130px 1fr 64px" }}>
                <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{name}</span>
                <svg height="12" viewBox="0 0 200 12" preserveAspectRatio="none" width="100%" aria-hidden="true">
                  <rect x="0" y="2" width={Math.max((n / famMax) * 200, 2)} height="8" rx="2" fill="var(--model)" />
                </svg>
                <span className="mono muted" style={{ textAlign: "right" }}>{int(n)}</span>
              </div>
            ))}
          </div>
          {tf && (
            <>
              <span className="label" style={{ display: "block", marginTop: 16 }}>ThreatFox by threat type</span>
              <div className="mono" style={{ fontSize: 12.5, marginTop: 6, color: "var(--text-2)" }}>
                {Object.entries(tf.by_threat).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${int(v)}`).join(" · ")}
              </div>
            </>
          )}
        </div>
      </section>

      <section className="panel" style={{ padding: 0, overflow: "hidden" }}>
        <div className="toolbar" style={{ padding: "14px 16px", borderBottom: "1px solid var(--border)" }}>
          <h2 style={{ margin: 0, fontSize: 16, marginRight: "auto" }}>Indicator table</h2>
          <label className="search">
            <span className="sr-only">Search indicators</span>
            <input type="search" placeholder="value or CVE" value={query} onChange={(e) => { setQuery(e.target.value); setPage(0); }} />
          </label>
          <label className="search">
            <span className="sr-only">Indicator type</span>
            <select value={type} onChange={(e) => { setType(e.target.value); setPage(0); }}
              style={{ background: "transparent", color: "var(--text)", border: 0, font: "inherit", fontSize: 13.5 }}>
              <option value="all">All types</option>
              {Object.keys(iocs.by_type).map((t) => <option key={t} value={t}>{TYPE_LABEL[t] ?? t}</option>)}
            </select>
          </label>
          <button type="button" className="pill" aria-pressed={showLocal} onClick={() => { setShowLocal(!showLocal); setPage(0); }}>
            Show non-public IPs ({int(hiddenLocal)})
          </button>
        </div>
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr className="label">
                <th>Type</th><th>Value (defanged)</th><th>CVEs</th><th className="num">Seen</th><th>IP scope</th><th />
              </tr>
            </thead>
            <tbody>
              {shown.map((i) => (
                <tr key={`${i.type}:${i.value}`}>
                  <td className="mono muted">{TYPE_LABEL[i.type] ?? i.type}</td>
                  <td className="mono wrap" style={{ maxWidth: 520, overflowWrap: "anywhere" }}>{i.value}</td>
                  <td className="mono muted">
                    {i.cves.slice(0, 2).map((c) => (
                      <button key={c} type="button" className="linkish" style={{ color: "var(--muted)", marginRight: 6 }} onClick={() => openCve(c)}>{c}</button>
                    ))}
                    {i.cve_count > 2 ? `+${i.cve_count - 2}` : ""}
                  </td>
                  <td className="num">{i.occurrences}</td>
                  <td className="muted">{i.public === null ? "—" : i.public ? "public IP" : "non-public IP"}</td>
                  <td style={{ textAlign: "right" }}>
                    <button type="button" className="copy" aria-label={`Copy defanged value ${i.value}`} onClick={() => copy(i.value)}>
                      {copied === i.value ? "Copied" : "Copy"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {shown.length === 0 && <p className="empty">No indicators match.</p>}
        </div>
        <Pager page={page} pages={pages} total={rows.length} size={PAGE} onPage={setPage} />
      </section>
    </>
  );
}

const inQueue = (tier?: string | null) => tier === "critical" || tier === "high" || tier === "elevated";

function SharedHosts({ graph }: { graph: Graph }) {
  const tip = useTooltip();
  const [picked, setPicked] = useState<string | null>(null);
  const W = 760, H = 500, cx = W / 2, cy = H / 2;

  const layout = useMemo(() => {
    const hosts = graph.nodes.filter((n) => n.kind === "host").sort((a, b) => (b.count ?? 0) - (a.count ?? 0));
    // hosts on one ring, largest first clockwise; CVEs inside
    const hostPos = new Map(
      hosts.map((h, i) => {
        const a = -Math.PI / 2 + (i * 2 * Math.PI) / Math.max(hosts.length, 1);
        return [h.id, { x: cx + Math.cos(a) * 185, y: cy + Math.sin(a) * 185, a }];
      }),
    );
    const labelled = new Set(hosts.slice(0, 10).map((h) => h.id));
    const cveHosts = new Map<string, string[]>();
    for (const e of graph.edges) cveHosts.set(e.target, [...(cveHosts.get(e.target) ?? []), e.source]);
    const cves = graph.nodes
      .filter((n) => n.kind === "cve")
      .map((n) => {
        const hs = cveHosts.get(n.id) ?? [];
        const pts = hs.map((h) => hostPos.get(h)!).filter(Boolean);
        const mx = pts.reduce((s, p) => s + p.x, 0) / Math.max(pts.length, 1);
        const my = pts.reduce((s, p) => s + p.y, 0) / Math.max(pts.length, 1);
        // single-host CVEs sit just inside their host; shared ones between their hosts
        const pull = pts.length > 1 ? 0.15 : 0.72 + hash01(`${n.id}d`) * 0.16;
        const jitter = (hash01(n.id) - 0.5) * (pts.length > 1 ? 20 : 34);
        const x = Math.min(W - 6, Math.max(6, cx + (mx - cx) * pull + jitter));
        const y = Math.min(H - 6, Math.max(6, cy + (my - cy) * pull + (hash01(`${n.id}y`) - 0.5) * 20));
        return { n, x, y, hosts: hs };
      });
    return { hosts, hostPos, cves, labelled };
  }, [graph, cx, cy]);

  const linked = (cveHosts: string[]) => picked !== null && cveHosts.includes(picked);
  return (
    <figure className="panel grow" style={{ margin: 0 }}>
      <div className="panel-head">
        <h2>Shared-host graph</h2>
        <div className="legend">
          <span><svg width="10" height="10" aria-hidden="true" style={{ display: "inline", marginRight: 6 }}><rect width="10" height="10" rx="2" fill="var(--model)" /></svg>host</span>
          <span><TierDot tier="critical" />critical</span>
          <span><TierDot tier="high" />high</span>
          <span><TierDot tier="elevated" />elevated</span>
          <span><TierDot tier="baseline" />baseline (below the queue)</span>
          <span><span className="dot" style={{ background: "var(--kev)" }} />in KEV</span>
          <span><span className="dot" style={{ background: "var(--other)" }} />not ranked</span>
        </div>
      </div>
      {tip.node}
      <svg className="chart" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Network of CVEs linked through hosts named on their reference pages" onMouseLeave={tip.hide}>
        <rect width={W} height={H} rx="8" fill="var(--bar)" />
        {layout.cves.flatMap((c) =>
          c.hosts.map((h) => {
            const p = layout.hostPos.get(h)!;
            const on = picked === h;
            return <line key={`${h}-${c.n.id}`} x1={p.x} y1={p.y} x2={c.x} y2={c.y} stroke={on ? "var(--accent)" : "var(--border-2)"} opacity={on ? 0.8 : 0.6} />;
          }),
        )}
        {layout.cves.map((c) => {
          const fill = c.n.tier ? `var(--${c.n.tier})` : c.n.in_kev ? "var(--kev)" : "var(--other)";
          return (
            <circle key={c.n.id} className="hit" cx={c.x} cy={c.y} r={c.hosts.length > 1 ? 5 : 3.8} fill={fill} stroke="var(--bar)" strokeWidth="1.5"
              opacity={picked === null || linked(c.hosts) ? 1 : 0.3}
              onClick={() => (inQueue(c.n.tier) ? openCve(c.n.id) : undefined)}
              onMouseMove={(e) => tip.show(e, <><b className="mono">{c.n.id}</b><br />{inQueue(c.n.tier) ? `${c.n.tier} tier · click to open` : c.n.tier === "baseline" ? "baseline tier (below the queue)" : c.n.in_kev ? "in KEV" : "not ranked"}<br />{c.hosts.length} shared host{c.hosts.length > 1 ? "s" : ""}</>)} />
          );
        })}
        {layout.hosts.map((h) => {
          const p = layout.hostPos.get(h.id)!, s = 9 + Math.sqrt(h.count ?? 1) * 1.6, on = picked === h.id;
          return (
            <g key={h.id} className="hit" onClick={() => setPicked(on ? null : h.id)}
              tabIndex={0} role="button" aria-label={`${h.label}, ${h.count} CVEs`} aria-pressed={on}
              onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setPicked(on ? null : h.id); } }}
              onMouseMove={(e) => tip.show(e, <><b className="mono">{h.label}</b><br />{h.count} CVEs · click to highlight</>)}>
              <rect x={p.x - s / 2} y={p.y - s / 2} width={s} height={s} rx="3" fill="var(--model)" stroke={on ? "var(--text)" : "var(--bar)"} strokeWidth="2" />
              {(layout.labelled.has(h.id) || on) && (
                <text className="node-sub" x={p.x + Math.cos(p.a) * (s / 2 + 8)} y={p.y + Math.sin(p.a) * (s / 2 + 8) + 4}
                  textAnchor={Math.cos(p.a) > 0.2 ? "start" : Math.cos(p.a) < -0.2 ? "end" : "middle"} style={{ fill: "var(--text)" }}>{h.label}</text>
              )}
            </g>
          );
        })}
      </svg>
      <figcaption className="caption">
        {graph.description}. Top {layout.hosts.length} hosts{graph.truncated ? " (truncated)" : ""}; click a host to
        highlight its CVEs; labels on the 10 largest. Shared vendor and advisory sites dominate: a shared host is a lead, not a link to an actor.
      </figcaption>
    </figure>
  );
}
