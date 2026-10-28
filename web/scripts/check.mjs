// Static checks on the built dashboard and its source (`npm run check`, after `npm run build`).
// The CSP `cti serve` sends forbids inline script and style and any remote origin; these checks
// catch a build that would break under it, or source that would weaken it, before it ships.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, extname } from "node:path";

const DIST = "dist";
const SRC = "src";

function files(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? files(path) : [path];
  });
}

// URLs that appear in the bundle as identifiers or message text, never fetched:
// XML/SVG/MathML namespace URIs and React's production error-decoder link.
const ALLOWED_URLS = [
  /^http:\/\/www\.w3\.org\/(1999\/xlink|2000\/svg|XML\/1998\/namespace|1998\/Math\/MathML)$/,
  /^https:\/\/react\.dev\/errors\/$/,
];

test("index.html has no inline script, style or event handler", () => {
  const html = readFileSync(join(DIST, "index.html"), "utf8");
  for (const tag of html.match(/<script\b[^>]*>[\s\S]*?<\/script>/g) ?? []) {
    assert.match(tag, /\ssrc="\/assets\/[^"]+\.js"/, `inline script: ${tag.slice(0, 80)}`);
    assert.match(tag, /><\/script>$/, "script tag with a body");
  }
  assert.doesNotMatch(html, /<style\b/i, "inline <style>");
  assert.doesNotMatch(html, /\sstyle=/i, "inline style attribute");
  assert.doesNotMatch(html, /\son[a-z]+=/i, "inline event handler");
});

test("every asset is a local file the allowlist can serve", () => {
  const types = new Set([".js", ".css", ".html", ".svg", ".png", ".ico", ".woff2"]);
  for (const path of files(DIST)) {
    assert.ok(types.has(extname(path)), `unexpected asset type: ${path}`);
    assert.ok(!path.split("/").some((p) => p.startsWith(".")), `dotfile in dist: ${path}`);
  }
});

test("the build references no remote origin", () => {
  for (const path of files(DIST)) {
    const text = readFileSync(path, "utf8");
    for (const url of text.match(/(?:https?|wss?):\/\/[^\s"'`)<>\\]+/g) ?? []) {
      assert.ok(ALLOWED_URLS.some((re) => re.test(url)), `${path}: ${url}`);
    }
    assert.doesNotMatch(text, /\/\/fonts\.googleapis|\/\/cdn\./, `${path}: CDN reference`);
    assert.doesNotMatch(text, /["'`]\/\/[a-z0-9-]+\.[a-z]/i, `${path}: protocol-relative URL`);
  }
});

test("source never writes raw HTML or evaluates strings", () => {
  for (const path of files(SRC)) {
    const text = readFileSync(path, "utf8");
    const banned = [
      "dangerouslySetInnerHTML", "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
      "new Function", "eval(", '["eval"]', "srcdoc", "xlinkHref", "setAttribute(\"style",
    ];
    for (const word of banned) assert.ok(!text.includes(word), `${path} uses ${word}`);
    assert.doesNotMatch(text, /set(Timeout|Interval)\(\s*["'`]/, `${path}: string timer`);
    // data is rendered as text; the only links are in-app hash routes
    assert.doesNotMatch(text, /(href|src)=\{[^}]*(value|description|label|url)\b/, `${path}: data used as a URL`);
  }
});
