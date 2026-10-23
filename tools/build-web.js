#!/usr/bin/env node
'use strict';
/**
 * Builds the in-browser version of VibeGuard: one self-contained HTML page that
 * runs the whole scanner client-side (no server, code never leaves the browser).
 *
 *   node tools/build-web.js
 *
 * Outputs:
 *   dist/vibeguard-web.html   page body for hosts that add their own <html> skeleton (claude.ai artifacts)
 *   docs/index.html           full HTML document for GitHub Pages (Settings → Pages → /docs)
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const BUILTINS = new Set(['fs', 'path', 'zlib', 'child_process', 'os', 'crypto']);
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

// ---------- tiny CommonJS bundler ----------
const modules = new Map(); // id -> { code, deps: {spec: id} }
function resolve(fromId, spec) {
  if (BUILTINS.has(spec)) return `builtin:${spec}`;
  if (!spec.startsWith('.')) return null; // packages only appear inside strings/templates in the engine
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(fromId), spec));
  for (const cand of [base, base + '.js', base + '.json', base + '/index.js']) {
    if (fs.existsSync(path.join(ROOT, cand)) && fs.statSync(path.join(ROOT, cand)).isFile()) return cand;
  }
  return null; // a require() inside a string or template (e.g. demo project code), not a real dependency
}
function add(id) {
  if (modules.has(id) || id.startsWith('builtin:')) return;
  let code = read(id);
  if (id.endsWith('.json')) code = `module.exports = ${code};`;
  const deps = {};
  modules.set(id, { code, deps });
  const re = /require\(\s*['"]([^'"]+)['"]\s*\)/g;
  let m;
  while ((m = re.exec(code))) {
    const target = resolve(id, m[1]);
    if (!target) continue;
    deps[m[1]] = target;
    add(target);
  }
}

const ENTRY = 'web/__entry.js';
modules.set(ENTRY, {
  code: `
    const scanner = require('../server/lib/scanner.js');
    module.exports = {
      scanProject: scanner.scanProject,
      report: require('../server/lib/report.js'),
      CATEGORIES: require('../server/lib/categories.js').CATEGORIES,
      buildDemo: require('../server/lib/demo.js').buildDemo,
      listEntries: require('../server/lib/zip.js').listEntries,
      zipDirectory: require('../server/lib/zip.js').zipDirectory,
    };`,
  deps: {},
});
for (const spec of ['../server/lib/scanner.js', '../server/lib/report.js', '../server/lib/categories.js', '../server/lib/demo.js', '../server/lib/zip.js']) {
  const id = resolve(ENTRY, spec);
  modules.get(ENTRY).deps[spec] = id;
  add(id);
}

const defs = [...modules.entries()].map(([id, { code, deps }]) =>
  `${JSON.stringify(id)}: [function (require, module, exports) {\n${code}\n}, ${JSON.stringify(deps)}]`).join(',\n');

const engine = `(function () {
'use strict';
var S = window.VG_SHIMS;
var defs = {
${defs}
};
var cache = {};
function load(id) {
  if (id.indexOf('builtin:') === 0) return S[id.slice(8)];
  if (cache[id]) return cache[id].exports;
  var def = defs[id];
  if (!def) throw new Error('VibeGuard bundle: missing module ' + id);
  var module = { exports: {} };
  cache[id] = module;
  def[0](function (spec) {
    var target = def[1][spec];
    if (!target) throw new Error('VibeGuard bundle: ' + spec + ' is not available in the browser');
    return load(target);
  }, module, module.exports);
  return module.exports;
}
window.VGEngine = load(${JSON.stringify(ENTRY)});
})();`;

// ---------- assemble the page ----------
const html = read('public/index.html');
const body = html.slice(html.indexOf('<body>') + 6, html.lastIndexOf('</body>')).trim();
const css = read('public/styles.css');
const iconSvg = read('public/icon.svg').trim();
const icon = `data:image/svg+xml;base64,${Buffer.from(iconSvg).toString('base64')}`;
const safeScript = (s) => s.replace(/<\/script/gi, '<\\/script').replace(/<!--/g, '<\\!--');
const scripts = [read('web/shims.js'), engine, read('web/local-api.js'), read('public/app.js')]
  .map((s) => `<script>\n${safeScript(s)}\n</script>`).join('\n');
const pageBody = body.replace('<a href="https://github.com/tejashalo/security-fix-project" rel="noopener">', '<a href="https://github.com/tejashalo/security-fix-project" target="_blank" rel="noopener">');

const head = `<title>VibeGuard</title>
<meta name="claude:viewport-fit-sides" content="cover">
<meta name="description" content="Find and fix leaked API keys, open admin routes, missing auth, XSS, CORS and more in vibe-coded websites and apps — right in your browser.">
<link rel="icon" href="${icon}">
<style>
${css}
</style>`;

fs.mkdirSync(path.join(ROOT, 'dist'), { recursive: true });
const fragment = `${head}\n${pageBody}\n${scripts}\n`;
fs.writeFileSync(path.join(ROOT, 'dist/vibeguard-web.html'), fragment);
const full = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#14213d">
${head}
</head>
<body>
${pageBody}
${scripts}
</body>
</html>
`;
fs.mkdirSync(path.join(ROOT, 'docs'), { recursive: true });
fs.writeFileSync(path.join(ROOT, 'docs/index.html'), full);
console.log(`Built ${modules.size} modules → dist/vibeguard-web.html (${(fragment.length / 1024).toFixed(0)} KB) and docs/index.html`);
