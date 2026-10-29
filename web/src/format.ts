import type { Tier } from "./types";

export const TIERS: Tier[] = ["critical", "high", "elevated", "baseline"];
export const TIER_LABEL: Record<Tier, string> = {
  critical: "Critical",
  high: "High",
  elevated: "Elevated",
  baseline: "Baseline",
};
export const TIER_BAND: Record<Tier, string> = {
  critical: "top 0.1%",
  high: "0.1–1%",
  elevated: "1–5%",
  baseline: "rest",
};

export const FEATURE_LABEL: Record<string, string> = {
  epss_logit: "EPSS percentile",
  epss_missing: "No EPSS score",
  ssvc_exploitation: "SSVC exploitation",
  ssvc_automatable: "SSVC automatable",
  ssvc_total_impact: "SSVC total impact",
  ssvc_missing: "No SSVC assessment",
  exploitdb: "ExploitDB entry",
  metasploit: "Metasploit module",
  nuclei: "Nuclei template",
  log_age_days: "Age (newer = higher)",
};

const intl = new Intl.NumberFormat("en-US");
export const int = (n: number) => intl.format(Math.round(n));

/** A count that may be fractional (expected hits under ties): 1.216 -> "1.2", 6 -> "6". */
export const hits = (n: number) => (Number.isInteger(n) ? String(n) : n.toFixed(1));

/** Percent with enough digits for small rates; `digits` 0 means "round, even if small". */
export function pct(x: number, digits = 1): string {
  const v = x * 100;
  if (digits > 0 && v !== 0 && Math.abs(v) < 0.1) return `${v.toFixed(3)}%`;
  if (digits > 0 && v !== 0 && Math.abs(v) < 1) return `${v.toFixed(2)}%`;
  if (digits === 0 && v !== 0 && Math.abs(v) < 1) return "<1%";
  return `${v.toFixed(digits)}%`;
}

/** Wilson 95% interval from counts (exact, not from rounded rates). */
export function wilson(k: number, n: number, z = 1.959964): [number, number] {
  if (n === 0) return [0, 0];
  const p = k / n, z2 = z * z;
  const centre = (p + z2 / (2 * n)) / (1 + z2 / n);
  const half = (z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / (1 + z2 / n);
  return [Math.max(0, centre - half), Math.min(1, centre + half)];
}

export function ordinal(n: number): string {
  const s = ["th", "st", "nd", "rd"];
  const v = n % 100;
  return `${n}${s[(v - 20) % 10] ?? s[v] ?? s[0]}`;
}

/** EPSS as FIRST recommends: probability first, then percentile. */
export function epss(p: number | null, percentile: number | null): string {
  if (p === null || percentile === null) return "not scored";
  const pctl = percentile * 100;
  // floor, never round up: 99.981 -> "99.98th", not "100.0th"
  const rank =
    pctl >= 99.9 ? `${(Math.floor(pctl * 100) / 100).toFixed(2)}th`
    : pctl >= 99 ? `${(Math.floor(pctl * 10) / 10).toFixed(1)}th`
    : ordinal(Math.floor(pctl + 1e-9)); // 0.29 * 100 = 28.999…
  const prob = p >= 0.995 ? `${(Math.floor(p * 10000) / 100).toFixed(2)}%` : pct(p);
  return `${prob} (${rank} pct)`;
}

export function signed(x: number, digits = 2): string {
  const s = Math.abs(x).toFixed(digits);
  if (Number(s) === 0) return s; // no "−0.00"
  return `${x >= 0 ? "+" : "−"}${s}`;
}

export function interval([lo, hi]: [number, number], f: (x: number) => string = pct): string {
  return `${f(lo)}–${f(hi)}`;
}

/** Stable 0..1 pseudo-random from a string (deterministic graph layouts). */
export function hash01(text: string): number {
  let h = 2166136261;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return ((h >>> 0) % 100000) / 100000;
}
