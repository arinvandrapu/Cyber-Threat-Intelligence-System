import { useState, type ReactNode } from "react";
import type { Tier } from "../types";
import { TIER_LABEL } from "../format";

export const VIEWS = [
  ["overview", "Overview"],
  ["queue", "Risk queue"],
  ["landscape", "Risk landscape"],
  ["weakness", "Weakness graph"],
  ["attack", "ATT&CK graph"],
  ["indicators", "Indicators"],
  ["evaluation", "Evaluation"],
] as const;
export type View = (typeof VIEWS)[number][0];

export function Shell({
  view,
  snapshot,
  synthetic,
  children,
}: {
  view: View;
  snapshot: string;
  synthetic: boolean;
  children: ReactNode;
}) {
  return (
    <>
      <header className="top">
        <div className="brand">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="1.8" aria-hidden="true">
            <path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z" />
            <path d="M8.5 12.5l2.3 2.3 4.7-5" />
          </svg>
          <span>CTI Console</span>
        </div>
        <nav className="tabs" aria-label="Views">
          {VIEWS.map(([id, label]) => (
            <a key={id} className="tab" href={`#/${id}`} aria-current={id === view ? "page" : undefined}>
              {label}
            </a>
          ))}
        </nav>
        <div className="chips">
          {synthetic && <span className="chip" style={{ color: "var(--kev)", borderColor: "var(--kev)" }}>SYNTHETIC DATA</span>}
          <span className="chip">snapshot {snapshot}</span>
          <span className="chip">127.0.0.1 · read-only</span>
        </div>
      </header>
      <main>{children}</main>
    </>
  );
}

export function PageHead({ title, lede, children }: { title: string; lede?: ReactNode; children?: ReactNode }) {
  return (
    <section className="page-head">
      <div>
        <h1>{title}</h1>
        {lede && <p className="lede">{lede}</p>}
      </div>
      {children}
    </section>
  );
}

export function TierDot({ tier }: { tier: Tier }) {
  return <span className="dot" style={{ background: `var(--${tier})` }} aria-hidden="true" />;
}

export function TierName({ tier }: { tier: Tier }) {
  return (
    <span>
      <TierDot tier={tier} />
      {TIER_LABEL[tier]}
    </span>
  );
}

export function Seg<T extends string>({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: readonly (readonly [T, string])[];
  value: T;
  onChange: (v: T) => void;
}) {
  return (
    <div className="seg" role="group" aria-label={label}>
      {options.map(([id, text]) => (
        <button key={id} type="button" aria-pressed={id === value} onClick={() => onChange(id)}>
          {text}
        </button>
      ))}
    </div>
  );
}

/** Horizontal bar centred on zero (contributions, coefficients). */
export function DivergingBar({ value, max }: { value: number; max: number }) {
  const w = Math.max((Math.min(Math.abs(value), max) / max) * 96, 1.5);
  return (
    <svg height="14" viewBox="0 0 200 14" preserveAspectRatio="none" width="100%" aria-hidden="true">
      <line x1="100" y1="0" x2="100" y2="14" stroke="var(--border-2)" />
      <rect x={value >= 0 ? 100 : 100 - w} y="3" width={w} height="8" rx="2" fill={value >= 0 ? "var(--accent)" : "var(--faint)"} />
    </svg>
  );
}

/** A point estimate with its interval on a 0..max (or log) scale. */
export function IntervalBar({
  value,
  ci,
  color,
  scale,
}: {
  value: number;
  ci: [number, number];
  color: string;
  scale: (v: number) => number; // -> 0..1
}) {
  const x = (v: number) => 4 + Math.max(0, Math.min(1, scale(v))) * 212;
  return (
    <svg width="220" height="16" viewBox="0 0 220 16" aria-hidden="true">
      <rect x="0" y="6" width="220" height="4" rx="2" fill="var(--active)" />
      <rect x={x(ci[0])} y="6" width={Math.max(x(ci[1]) - x(ci[0]), 2)} height="4" rx="2" fill={color} opacity="0.4" />
      <circle cx={x(value)} cy="8" r="5.5" fill={color} stroke="var(--panel)" strokeWidth="2" />
    </svg>
  );
}

export interface Tip {
  x: number;
  y: number;
  text: ReactNode;
}

/** One floating tooltip per chart; marks call show/hide. */
export function useTooltip() {
  const [tip, setTip] = useState<Tip | null>(null);
  const node = tip ? (
    <div className="tooltip" aria-hidden="true" style={{ left: tip.x + 14, top: tip.y + 14 }}>
      {tip.text}
    </div>
  ) : null;
  return {
    node,
    show: (e: { clientX: number; clientY: number }, text: ReactNode) => setTip({ x: e.clientX, y: e.clientY, text }),
    hide: () => setTip(null),
  };
}

export function Pager({
  page,
  pages,
  total,
  size,
  onPage,
}: {
  page: number;
  pages: number;
  total: number;
  size: number;
  onPage: (p: number) => void;
}) {
  const from = total === 0 ? 0 : page * size + 1;
  const to = Math.min(total, (page + 1) * size);
  return (
    <div className="pager">
      <span className="muted mono" style={{ fontSize: 12.5 }}>
        {from.toLocaleString()}–{to.toLocaleString()} of {total.toLocaleString()}
      </span>
      <div style={{ display: "flex", gap: 6 }}>
        <button type="button" className="pill" disabled={page === 0} onClick={() => onPage(page - 1)}>
          ‹ Prev
        </button>
        <button type="button" className="pill" disabled={page >= pages - 1} onClick={() => onPage(page + 1)}>
          Next ›
        </button>
      </div>
    </div>
  );
}
