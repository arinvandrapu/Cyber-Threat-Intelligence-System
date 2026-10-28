import type { Data } from "./types";

const FILES = {
  meta: "meta.json",
  risk: "risk.json",
  iocs: "iocs.json",
  graphs: "graphs.json",
  evals: "eval.json",
} as const;

export class DataError extends Error {}

async function load(name: string): Promise<unknown> {
  let res: Response;
  try {
    res = await fetch(`/data/${name}`, { cache: "no-store", credentials: "omit" });
  } catch {
    throw new DataError(`could not reach /data/${name}; is \`cti serve\` running?`);
  }
  if (!res.ok) {
    throw new DataError(`/data/${name}: HTTP ${res.status}; run \`cti export\` first`);
  }
  if (!(res.headers.get("Content-Type") ?? "").startsWith("application/json")) {
    throw new DataError(`/data/${name} is not JSON`);
  }
  return res.json();
}

/** Every export file, with a light structural check (the export validated them in full). */
export async function loadAll(): Promise<Data> {
  const entries = await Promise.all(
    Object.entries(FILES).map(async ([key, file]) => [key, await load(file)] as const),
  );
  const data = Object.fromEntries(entries) as unknown as Data;
  if (data.meta?.schema_version !== 1) {
    throw new DataError("export schema version is not 1; rebuild the dashboard or re-export");
  }
  if (!Array.isArray(data.risk?.rows) || !Array.isArray(data.iocs?.indicators)) {
    throw new DataError("export files are incomplete; re-run `cti export`");
  }
  return data;
}
