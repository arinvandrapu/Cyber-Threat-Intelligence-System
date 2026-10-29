import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

const EXPORT_FILES = new Set(["meta.json", "risk.json", "iocs.json", "graphs.json", "eval.json", "threats.json"]);

/**
 * Dev only: serve /data/<file>.json from CTI_EXPORT_DIR (a `cti export` folder), or the
 * synthetic fixture. Production never uses this: `cti serve` maps /data/ to the export.
 */
function devData(): Plugin {
  const dir = resolve(process.env.CTI_EXPORT_DIR ?? "fixtures");
  return {
    name: "cti-dev-data",
    apply: "serve",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const name = req.url?.startsWith("/data/") ? req.url.slice(6).split("?")[0] : null;
        if (!name || !EXPORT_FILES.has(name)) return next();
        const file = resolve(dir, name);
        if (!existsSync(file)) {
          res.statusCode = 404;
          return res.end("not found");
        }
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        res.end(readFileSync(file));
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), devData()],
  server: { host: "127.0.0.1", port: 5173, strictPort: true },
  preview: { host: "127.0.0.1" },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    assetsInlineLimit: 0, // no data: URIs; every asset is a file the allowlist serves
    modulePreload: { polyfill: false }, // modern browsers only; nothing inline
    sourcemap: false,
  },
});
