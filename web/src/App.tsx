import { useEffect, useState, type ReactElement } from "react";
import { DataError, loadAll } from "./data";
import type { Data } from "./types";
import { Shell, VIEWS, type View } from "./components/ui";
import { Overview } from "./views/Overview";
import { RiskQueue } from "./views/RiskQueue";
import { RiskLandscape } from "./views/RiskLandscape";
import { WeaknessGraph } from "./views/WeaknessGraph";
import { AttackGraph } from "./views/AttackGraph";
import { Indicators } from "./views/Indicators";
import { Evaluation } from "./views/Evaluation";
import { Threats } from "./views/Threats";

/** Hash routes: #/<view>[/<CVE>] (no server rewrites needed under `cti serve`). */
function parseHash(): { view: View; arg: string | null } {
  const [, view = "", arg = ""] = window.location.hash.split("/");
  const known = VIEWS.some(([id]) => id === view);
  return { view: known ? (view as View) : "overview", arg: CVE_ID.test(arg) ? arg : null };
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
      setRoute(parseHash());
      window.scrollTo(0, 0);
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  useEffect(() => {
    loadAll()
      .then(setData)
      .catch((e: unknown) => setError(e instanceof DataError ? e.message : "could not load the export"));
  }, []);

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
    queue: () => <RiskQueue data={data} focus={route.arg} />,
    threats: () => <Threats data={data} />,
    landscape: () => <RiskLandscape data={data} />,
    weakness: () => <WeaknessGraph data={data} />,
    attack: () => <AttackGraph data={data} />,
    indicators: () => <Indicators data={data} />,
    evaluation: () => <Evaluation data={data} />,
  };
  return (
    <Shell view={route.view} snapshot={data.meta.snapshot_date} synthetic={data.meta.git.commit === "fixture"}>
      {views[route.view]()}
    </Shell>
  );
}
