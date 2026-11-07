import type { ReactElement, ReactNode } from "react";
import type { Data } from "../types";
import type { View } from "../components/ui";

/** One h3 block inside a Guide section; `id` becomes `#/guide/<section>-<id>`. */
export interface Part {
  id: string;
  title: string;
  body: ReactNode;
}

/** One h2 block of the Guide. `view` (if set) is the dashboard tab it documents. */
export interface Section {
  id: string;
  title: string;
  view?: View;
  intro: ReactNode;
  parts: Part[];
}

export type SectionBuilder = (data: Data) => Section;

/** DOM id of a section (`queue`) or part (`queue-detail`); prefixed so it can't clash with view ids. */
export const domId = (key: string) => `guide-${key}`;

/** In-guide link to another section or part, e.g. <G to="concepts-ranking">tier</G>. */
export function G({ to, children }: { to: string; children: ReactNode }): ReactElement {
  return <a href={`#/guide/${to}`}>{children}</a>;
}

/** A colour key: the swatch uses the same CSS variable the chart uses. */
export function Swatch({ color, square, children }: { color: string; square?: boolean; children: ReactNode }) {
  return (
    <span className="gd-swatch">
      <span className={square ? "gd-chip square" : "gd-chip"} style={{ background: `var(--${color})` }} aria-hidden="true" />
      {children}
    </span>
  );
}

/** "Common misreadings" list: each item is the wrong reading, then the right one. */
export function Misreads({ items }: { items: [ReactNode, ReactNode][] }) {
  return (
    <ul className="gd-misreads">
      {items.map(([wrong, right], i) => (
        <li key={i}>
          <span className="gd-wrong">{wrong}</span> {right}
        </li>
      ))}
    </ul>
  );
}

/** A worked example built from this export's numbers. */
export function Example({ children }: { children: ReactNode }) {
  return (
    <div className="gd-example">
      <span className="label">In this snapshot</span>
      <p>{children}</p>
    </div>
  );
}

/** Definition list used for column / encoding keys. */
export function Defs({ rows }: { rows: [ReactNode, ReactNode][] }) {
  return (
    <dl className="gd-defs">
      {rows.map(([term, def], i) => (
        <div key={i}>
          <dt>{term}</dt>
          <dd>{def}</dd>
        </div>
      ))}
    </dl>
  );
}
