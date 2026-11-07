import { useCallback, useEffect, useLayoutEffect, useMemo, useState, type MouseEvent } from "react";
import type { Data } from "../types";
import { PageHead } from "../components/ui";
import { guideSections } from "../guide/content";
import { domId } from "../guide/common";

const PREFIX = "#/guide/";

/** The guide key (`queue`, `queue-detail`) named by a hash, or null. */
function keyOf(hash: string): string | null {
  if (!hash.startsWith(PREFIX)) return null;
  try {
    return decodeURIComponent(hash.slice(PREFIX.length)) || null;
  } catch {
    return null;
  }
}

/** How far below the top of the window a heading counts as "being read" (px). */
const READ_LINE = 120;

/**
 * In-depth guide to every tab. Sidebar and in-text links are plain `#/guide/<key>` anchors: the
 * browser changes the hash (no element has that id, so it doesn't jump), and this view's own
 * hashchange listener scrolls. Scrolling updates the address with replaceState, which fires no
 * hashchange, so App doesn't re-render or scroll to the top.
 */
export function Guide({ data, focus }: { data: Data; focus: string | null }) {
  const sections = useMemo(() => guideSections(data), [data]);
  const keys = useMemo(() => new Set(sections.flatMap((s) => [s.id, ...s.parts.map((p) => `${s.id}-${p.id}`)])), [sections]);
  const sectionOf = useCallback(
    (key: string | null) => (key ? sections.find((s) => key === s.id || key.startsWith(`${s.id}-`))?.id ?? null : null),
    [sections],
  );
  const [active, setActive] = useState<{ section: string; part: string | null }>({ section: sections[0]!.id, part: null });

  const go = useCallback(
    (key: string | null, moveFocus: boolean) => {
      const el = key && keys.has(key) ? document.getElementById(domId(key)) : null;
      if (!el) {
        window.scrollTo(0, 0);
        return;
      }
      el.scrollIntoView({ block: "start" });
      if (moveFocus) el.querySelector<HTMLElement>("h2, h3")?.focus({ preventScroll: true });
    },
    [keys],
  );

  // deep link on first render: the content exists by now, so scroll straight to it
  useLayoutEffect(() => {
    go(focus, false);
    // once, on mount: later moves come from the hashchange listener below
  }, []);

  // links, Back and Forward between guide entries
  useEffect(() => {
    const onHash = () => {
      if (window.location.hash.startsWith(PREFIX) || window.location.hash === "#/guide") go(keyOf(window.location.hash), true);
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, [go]);

  // scroll-spy: the section and part whose heading is last above the reading line. A layout
  // effect, so a deep link never paints with "Start here" highlighted first.
  useLayoutEffect(() => {
    let frame = 0;
    let timer = 0;
    const top = (key: string) => document.getElementById(domId(key))?.getBoundingClientRect().top ?? Infinity;
    const measure = () => {
      frame = 0;
      const atBottom = window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2;
      // headings near the end can't scroll up to the reading line: at the bottom, keep the
      // linked heading if it is on screen, else take the last section
      const target = keyOf(window.location.hash);
      const targetTop = target !== null && keys.has(target) ? top(target) : -1;
      const onScreen = atBottom && target !== null && targetTop >= 0 && targetTop < window.innerHeight;
      let key: string;
      if (onScreen) key = target;
      else if (atBottom) {
        const last = sections[sections.length - 1]!;
        const lastPart = last.parts[last.parts.length - 1];
        key = lastPart ? `${last.id}-${lastPart.id}` : last.id;
      } else {
        const s = [...sections].reverse().find((x) => top(x.id) <= READ_LINE) ?? sections[0]!;
        const p = [...s.parts].reverse().find((x) => top(`${s.id}-${x.id}`) <= READ_LINE);
        key = p ? `${s.id}-${p.id}` : s.id;
      }
      const section = sectionOf(key) ?? sections[0]!.id;
      const next = { section, part: key === section ? null : key };
      setActive((cur) => (cur.section === next.section && cur.part === next.part ? cur : next));
      // keep the address on the section being read (not every part), without a history entry;
      // skip it if the address changed meanwhile (a link or Back won the race)
      window.clearTimeout(timer);
      const scheduled = window.location.hash;
      timer = window.setTimeout(() => {
        if (window.location.hash !== scheduled || sectionOf(keyOf(scheduled)) === section) return;
        history.replaceState(history.state, "", `${PREFIX}${section}`);
      }, 200);
    };
    const onScroll = () => {
      if (!frame) frame = window.requestAnimationFrame(measure);
    };
    measure();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll, { passive: true });
    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
      window.cancelAnimationFrame(frame);
      window.clearTimeout(timer);
    };
  }, [sections, sectionOf, keys]);

  // a link to the address already showing fires no hashchange: scroll here instead
  const onClick = (e: MouseEvent<HTMLElement>) => {
    const a = (e.target as HTMLElement).closest("a");
    const href = a?.getAttribute("href");
    if (href && href.startsWith(PREFIX) && href === window.location.hash) {
      e.preventDefault();
      go(keyOf(href), true);
    }
  };

  const current = sections.find((s) => s.id === active.section) ?? sections[0]!;
  return (
    <>
      <PageHead
        guide={null}
        title="Guide"
        lede="How to read every tab in depth: what each panel shows, how it is built, and the readings that are easy to get wrong."
      />
      <div className="gd-layout" onClick={onClick}>
        {/* sections never move; only the "In this section" block below them changes as you scroll */}
        <nav className="gd-toc" aria-label="Guide sections">
          <ul>
            {sections.map((s) => (
              <li key={s.id}>
                <a href={`${PREFIX}${s.id}`} aria-current={s.id === active.section ? "location" : undefined}>
                  {s.title}
                </a>
              </li>
            ))}
          </ul>
          {current.parts.length > 0 && (
            <div className="gd-toc-parts">
              <span className="label">In {current.title}</span>
              <ul>
                {current.parts.map((p) => {
                  const key = `${current.id}-${p.id}`;
                  return (
                    <li key={key}>
                      <a href={`${PREFIX}${key}`} aria-current={key === active.part ? "location" : undefined}>
                        {p.title}
                      </a>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}
        </nav>

        <label className="gd-select">
          <span className="label">Jump to</span>
          <select value={active.part ?? active.section} onChange={(e) => go(e.target.value, false)}>
            {sections.map((s) => (
              <optgroup key={s.id} label={s.title}>
                <option value={s.id}>{s.title}</option>
                {s.parts.map((p) => (
                  <option key={p.id} value={`${s.id}-${p.id}`}>
                    {p.title}
                  </option>
                ))}
              </optgroup>
            ))}
          </select>
        </label>

        <div className="gd-content">
          {sections.map((s) => (
            <section key={s.id} id={domId(s.id)} className="panel gd-section" aria-labelledby={`${domId(s.id)}-h`}>
              <div className="gd-section-head">
                <h2 id={`${domId(s.id)}-h`} tabIndex={-1}>
                  {s.title}
                </h2>
                {s.view && (
                  <a className="pill" href={`#/${s.view}`}>
                    Open {s.title} →
                  </a>
                )}
              </div>
              {s.intro}
              {s.parts.map((p) => (
                <div key={p.id} id={domId(`${s.id}-${p.id}`)} className="gd-part">
                  <h3 tabIndex={-1}>{p.title}</h3>
                  {p.body}
                </div>
              ))}
            </section>
          ))}
        </div>
      </div>
    </>
  );
}
