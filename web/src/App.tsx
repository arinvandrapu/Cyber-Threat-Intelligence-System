import { useEffect, useState, type ReactElement } from "react";
import { DataError, loadAll } from "./data";
import type { Data } from "./types";
import { Shell, VIEWS, type View } from "./components/ui";
import { Overview } from "./views/Overview";
import { RiskQueue } from "./views/RiskQueue";
import { KnownExploited } from "./views/KnownExploited";
import { RiskLandscape } from "./views/RiskLandscape";
import { WeaknessGraph } from "./views/WeaknessGraph";
import { AttackGraph } from "./views/AttackGraph";
import { Indicators } from "./views/Indicators";
import { Evaluation } from "./views/Evaluation";
import { Threats } from "./views/Threats";
import { Guide } from "./views/Guide";

/** Hash routes: #/<view>[/<CVE or encoded family name>] (no server rewrites needed under
 * `cti serve`). `arg` is set only for a CVE ID; `name` is the decoded raw segment, which a
 * view must check against its own data (Threats: a shown family) before using it. */
function parseHash(): { view: View; arg: string | null; name: string | null } {
  const [, view = "", raw = ""] = window.location.hash.split("/");
  const known = VIEWS.some(([id]) => id === view);
  let name: string | null = null;
  try {
    name = raw ? decodeURIComponent(raw) : null;
  } catch {
    name = null; // malformed escape: ignore it
  }
  return { view: known ? (view as View) : "overview", arg: CVE_ID.test(raw) ? raw : null, name };
}

/** In-app link to a threat family on the Threats view (the name is URI-encoded). */
export function threatHref(family: string): string {
  return `#/threats/${encodeURIComponent(family)}`;
}

export const CVE_ID = /^CVE-\d{4}-\d{4,7}$/;

/** In-app link to a CVE in the risk queue; anything that isn't a CVE ID goes nowhere. */
export function cveHref(cve: string): string {
  return CVE_ID.test(cve) ? `#/queue/${cve}` : "#/queue";
}

export function openCve(cve: string) {
  window.location.hash = cveHref(cve);
}

export function App() {
  const [route, setRoute] = useState(parseHash);
  const [data, setData] = useState<Data | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const onHash = () => {
      const next = parseHash();
      setRoute(next);
      if (next.view !== "guide") window.scrollTo(0, 0); // the Guide scrolls to its own sections
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  useEffect(() => {
    loadAll()
      .then(setData)
      .catch((e: unknown) => setError(e instanceof DataError ? e.message : "could not load the export"));
  }, []);

  // a KEV CVE opened in the risk queue (any older link) shows its place in Known exploited;
  // replace(), not a new history entry, so Back doesn't bounce into the redirect again
  useEffect(() => {
    if (data && route.view === "queue" && route.arg && data.kev.entries.some((k) => k.cve === route.arg)) {
      window.location.replace(`#/kev/${route.arg}`);
    }
  }, [data, route.view, route.arg]);

  useEffect(() => {
    const label = VIEWS.find(([id]) => id === route.view)?.[1] ?? "";
    document.title = `CTI Console · ${label}`;
  }, [route.view]);

  if (error) {
    return (
      <div className="panel error" role="alert">
        <h2>Dashboard data unavailable</h2>
        <p className="muted">{error}</p>
        <pre className="mono note">cti export --date &lt;snapshot date&gt;{"\n"}cti serve</pre>
      </div>
    );
  }
  if (!data) {
    return <p className="empty">Loading export…</p>;
  }

  const views: Record<View, () => ReactElement> = {
    overview: () => <Overview data={data} />,
    kev: () => <KnownExploited data={data} focus={route.arg} />,
    queue: () => <RiskQueue data={data} focus={route.arg} />,
    threats: () => <Threats data={data} focus={route.name} />,
    landscape: () => <RiskLandscape data={data} />,
    weakness: () => <WeaknessGraph data={data} />,
    attack: () => <AttackGraph data={data} />,
    indicators: () => <Indicators data={data} />,
    evaluation: () => <Evaluation data={data} />,
    guide: () => <Guide data={data} focus={route.name} />,
  };
  return (
    <Shell view={route.view} snapshot={data.meta.snapshot_date} synthetic={data.meta.git.commit === "fixture"}>
      {views[route.view]()}
    </Shell>
  );
}
