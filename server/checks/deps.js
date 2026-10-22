'use strict';
const semver = require('../lib/semver');
const { mapLimit, fetchJSON, levenshtein, escapeRe, posix } = require('../lib/util');
const { safeJSON } = require('../lib/detect');
const POP = require('../lib/popular');

const NPM_REGISTRY = (process.env.VIBEGUARD_NPM_REGISTRY || 'https://registry.npmjs.org').replace(/\/$/, '');
const PYPI = (process.env.VIBEGUARD_PYPI || 'https://pypi.org').replace(/\/$/, '');
const IMPLICIT = /^(@types\/|eslint|@eslint|prettier|typescript$|ts-node|tsx$|@typescript-eslint|tailwindcss|postcss|autoprefixer|@tailwindcss|babel|@babel|webpack|vite$|@vitejs|rollup|esbuild|jest|vitest|@vitest|@testing-library|husky|lint-staged|nodemon|concurrently|cross-env|next$|react-scripts|react-dom$|sharp$|pg-hstore|pg$|mysql2?$|sqlite3$|tedious|mariadb|better-sqlite3|@prisma\/client|prisma$|expo|@expo|react-native|@react-native|electron|dotenv-cli|serve$|vercel|netlify-cli|wrangler|sass$|less$|stylus|postcss-|@next\/|turbo$|nx$|@nx|lerna|patch-package|@commitlint|semantic-release|gh-pages|@capacitor|@ionic|cordova|.*-loader$|@svgr|@sveltejs|svelte$|@astrojs|astro$|nuxt$|@nuxt|@vue\/|@angular|tslib$|zone\.js$|rxjs$|core-js$|regenerator-runtime$|@swc|swc|babel-plugin|@playwright|playwright$|cypress$|start-server-and-test|wait-on|npm-run-all|run-p|kill-port|@vercel|@netlify|firebase-tools$|supabase$|@supabase\/cli)/;
const SEV_MAP = { critical: 'critical', high: 'high', moderate: 'medium', medium: 'medium', low: 'low', info: 'info' };

function npmUrl(name) { return `${NPM_REGISTRY}/${name.startsWith('@') ? '@' + encodeURIComponent(name.slice(1)) : encodeURIComponent(name)}`; }

function lockVersions(p, dir) {
  const out = {};
  const lock = safeJSON(p.read(dir ? `${dir}/package-lock.json` : 'package-lock.json') || '');
  if (lock && lock.packages) for (const [k, v] of Object.entries(lock.packages)) { if (k.startsWith('node_modules/') && !k.slice(13).includes('node_modules/') && v.version) out[k.slice(13)] = v.version; }
  else if (lock && lock.dependencies) for (const [k, v] of Object.entries(lock.dependencies)) if (v.version) out[k] = v.version;
  return out;
}

function writePkg(ctx, file, original, json) {
  const indent = (/\n(\s+)"/.exec(original) || [, '  '])[1];
  ctx.p.write(file, JSON.stringify(json, null, indent.includes('\t') ? '\t' : indent.length) + '\n');
}

module.exports = {
  id: 'deps',
  title: 'Checking dependencies (vulnerable, outdated, fake, unused)',
  async run(ctx, progress) {
    const { p, det } = ctx;
    const online = ctx.opts.online !== false;
    let anyPkg = false, offline = !online, networkFailures = 0;
    const popular = new Set(POP.NPM);

    for (const pkg of det.pkgs) {
      const dir = pkg.dir === '.' ? '' : pkg.dir;
      const original = p.read(pkg.file);
      const json = safeJSON(original);
      if (!json) continue;
      const entries = [];
      for (const sec of ['dependencies', 'devDependencies']) for (const [name, range] of Object.entries(json[sec] || {})) entries.push({ name, range: String(range), sec });
      if (!entries.length) continue;
      anyPkg = true;
      const locks = lockVersions(p, dir);
      let changed = false;

      // ---- registry metadata ----
      const meta = new Map();
      if (online && !offline) {
        progress && progress(`Looking up ${entries.length} npm packages`);
        const res = await mapLimit(entries.slice(0, 250), 8, async (e) => {
          if (/^(file:|link:|workspace:|git|github:|https?:|npm:)/.test(e.range)) return null;
          try { return { e, r: await fetchJSON(npmUrl(e.name), { headers: { accept: 'application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8' } }) }; }
          catch { networkFailures++; return null; }
        });
        if (networkFailures && !res.some((x) => x && x.r && x.r.status)) offline = true;
        for (const x of res) if (x && x.r) meta.set(x.e.name, x.r);
      }

      // ---- fake (hallucinated) and malicious placeholder packages ----
      for (const e of entries) {
        const m = meta.get(e.name);
        if (m && m.status === 404 && e.name.startsWith('@')) {
          ctx.add({ category: 'supply', severity: 'medium', file: pkg.file, snippet: `"${e.name}": "${e.range}"`, title: `Scoped package "${e.name}" is not on the public npm registry`, why: 'Fine if it comes from a private registry. If not, it may be an AI-invented name — and anyone could register it.', fix: 'Confirm where this package comes from; remove it if it does not exist.' });
          continue;
        }
        if (m && m.status === 404) {
          const fd = ctx.add({ category: 'supply', severity: 'critical', file: pkg.file, snippet: `"${e.name}": "${e.range}"`, title: `Package "${e.name}" does not exist on npm`, why: 'AI assistants sometimes invent package names. Attackers register these "hallucinated" names with malware ("slopsquatting"), so the next install could run their code.', fix: `Remove it and find the real package that provides this feature.` });
          delete json[e.sec][e.name]; changed = true;
          ctx.markFixed(fd, { before: `"${e.name}": "${e.range}"`, after: '(removed)', summary: 'Removed the non-existent package from package.json.' });
          e.removed = true;
          continue;
        }
        const latest = m && m.data && m.data['dist-tags'] && m.data['dist-tags'].latest;
        if (latest && /security/.test(latest)) {
          const fd = ctx.add({ category: 'supply', severity: 'critical', file: pkg.file, snippet: `"${e.name}": "${e.range}"`, title: `"${e.name}" was removed by npm for being malicious`, why: 'npm replaces malware with a "security holding" package. If you installed an older version, your machine may be compromised.', fix: 'Remove it, delete node_modules, reinstall, and rotate any secrets on machines that installed it.' });
          delete json[e.sec][e.name]; changed = true; e.removed = true;
          ctx.markFixed(fd, { before: `"${e.name}": "${e.range}"`, after: '(removed)', summary: 'Removed from package.json.' });
          continue;
        }
        // typo-squat look-alikes
        if (!popular.has(e.name) && e.name.length >= 4 && !e.name.startsWith('@types/')) {
          const close = POP.NPM.find((n) => n !== e.name && levenshtein(n, e.name) === 1 && !e.name.startsWith(n + '-') && !n.startsWith(e.name + '-'));
          if (close && !(m && m.data && Object.keys(m.data.versions || {}).length > 30)) {
            ctx.add({ category: 'supply', severity: 'high', file: pkg.file, snippet: `"${e.name}": "${e.range}"`, title: `"${e.name}" looks like a typo of "${close}"`, why: 'Typo-squatted packages imitate popular names to sneak malware into projects.', fix: `Double-check the name. If you meant "${close}", replace it.` });
          }
        }
      }

      // ---- vulnerabilities via npm bulk advisory endpoint ----
      const current = {};
      for (const e of entries) {
        if (e.removed) continue;
        const v = locks[e.name] || (semver.validRange(e.range) ? semver.minVersion(e.range) : null);
        if (v && semver.parse(v)) current[e.name] = v;
      }
      let advisories = {};
      if (online && !offline && Object.keys(current).length) {
        progress && progress('Checking known vulnerabilities');
        try {
          const body = JSON.stringify(Object.fromEntries(Object.entries(current).map(([n, v]) => [n, [v]])));
          const r = await fetchJSON(`${NPM_REGISTRY}/-/npm/v1/security/advisories/bulk`, { method: 'POST', body, headers: { 'content-type': 'application/json' }, timeout: 15000 });
          if (r.data) advisories = r.data;
        } catch { offline = true; }
      }
      const updates = [], majors = [], vulnFixed = [];
      for (const e of entries) {
        if (e.removed) continue;
        const cur = current[e.name];
        const m = meta.get(e.name);
        const versions = m && m.data && m.data.versions ? Object.keys(m.data.versions).filter((v) => semver.parse(v) && !semver.parse(v).pre.length) : [];
        const advs = (advisories[e.name] || []).filter((a) => cur && semver.satisfies(cur, a.vulnerable_versions || '<0.0.0'));
        if (advs.length) {
          const worst = advs.map((a) => SEV_MAP[a.severity] || 'medium').sort((a, b) => ['critical', 'high', 'medium', 'low', 'info'].indexOf(a) - ['critical', 'high', 'medium', 'low', 'info'].indexOf(b))[0];
          const safe = versions.filter((v) => semver.compare(v, cur) > 0 && !advs.some((a) => semver.satisfies(v, a.vulnerable_versions)))
            .sort(semver.compare);
          const sameMajor = safe.filter((v) => semver.parse(v).major === semver.parse(cur).major);
          const target = sameMajor.length ? sameMajor[sameMajor.length - 1] : safe[0];
          const fd = ctx.add({
            category: 'deps', severity: worst, file: pkg.file, snippet: `"${e.name}": "${e.range}" (installed ${cur})`,
            title: `${e.name}@${cur} has ${advs.length} known vulnerabilit${advs.length > 1 ? 'ies' : 'y'}`,
            why: advs.slice(0, 3).map((a) => `${a.title}${a.url ? ` (${a.url})` : ''}`).join('; '),
            fix: target ? `Upgrade to ${target}${semver.parse(target).major !== semver.parse(cur).major ? ' (major version — check the changelog)' : ''}.` : 'No fixed version yet — consider replacing the package.',
          });
          if (target && semver.parse(target).major === semver.parse(cur).major) {
            const nr = semver.rewriteRange(e.range, target);
            json[e.sec][e.name] = nr; changed = true;
            ctx.markFixed(fd, { before: `"${e.name}": "${e.range}"`, after: `"${e.name}": "${nr}"`, summary: `Upgraded to ${target} (same major version, no breaking changes expected).` });
            vulnFixed.push(e.name);
          }
          continue;
        }
        if (!versions.length || !cur) continue;
        const bestSame = semver.maxSatisfying(versions, `^${cur}`.replace(/^\^0\./, '~0.'));
        if (bestSame && semver.compare(bestSame, cur) > 0) {
          const nr = semver.rewriteRange(e.range, bestSame);
          if (nr !== e.range) { updates.push({ name: e.name, from: e.range, to: nr }); json[e.sec][e.name] = nr; changed = true; }
        }
        const latest = m.data['dist-tags'] && m.data['dist-tags'].latest;
        if (latest && semver.parse(latest) && semver.parse(latest).major > semver.parse(cur).major) majors.push(`${e.name} ${cur} → ${latest}`);
        const dep = m.data.versions[cur] && m.data.versions[cur].deprecated;
        if (dep) ctx.add({ category: 'deps', severity: 'medium', file: pkg.file, snippet: `"${e.name}": "${e.range}"`, title: `${e.name}@${cur} is deprecated`, why: String(dep).slice(0, 200), fix: 'Move to the recommended replacement.' });
      }
      if (updates.length) {
        const fd = ctx.add({ category: 'deps', severity: 'low', file: pkg.file, title: `${updates.length} package(s) had newer patch/minor versions`, snippet: updates.slice(0, 6).map((u) => `${u.name} ${u.from}→${u.to}`).join(', '), why: 'Patch and minor releases include bug and security fixes without breaking changes (semver).', fix: 'Update within the same major version.' });
        ctx.markFixed(fd, { before: updates.slice(0, 8).map((u) => `"${u.name}": "${u.from}"`).join('\n'), after: updates.slice(0, 8).map((u) => `"${u.name}": "${u.to}"`).join('\n'), summary: `Updated ${updates.length} package range(s) within their current major versions.` });
      }
      if (majors.length) ctx.add({ category: 'deps', severity: 'info', file: pkg.file, title: `${majors.length} package(s) have a new major version`, snippet: majors.slice(0, 8).join(', '), why: 'Major versions can contain breaking changes, so VibeGuard does not upgrade them automatically.', fix: 'Upgrade one at a time and test: `npm install <name>@latest`.' });

      // ---- unused packages ----
      if (!json.workspaces) {
        const corpus = p.codeFiles((x) => (dir ? x.startsWith(dir + '/') : true) && posix.basename(x) !== 'package.json')
          .map((f) => p.read(f.path) || '').join('\n');
        const scripts = JSON.stringify(json.scripts || {}) + JSON.stringify(json.jest || {}) + JSON.stringify(json.eslintConfig || {}) + JSON.stringify(json.babel || {}) + JSON.stringify(json.prettier || '') + JSON.stringify(json.browserslist || '');
        const peers = new Set();
        for (const e of entries) {
          const m = meta.get(e.name);
          const v = current[e.name] && m && m.data && m.data.versions && m.data.versions[current[e.name]];
          if (v) Object.keys({ ...(v.peerDependencies || {}), ...(v.dependencies || {}) }).forEach((x) => peers.add(x));
        }
        const unusedDeps = [], unusedDev = [];
        for (const e of entries) {
          if (e.removed || IMPLICIT.test(e.name) || peers.has(e.name)) continue;
          const nameRe = new RegExp(`['"\`(]${escapeRe(e.name)}(?:/[^'"\`)]*)?['"\`)]`);
          if (nameRe.test(corpus)) continue;
          const m = meta.get(e.name);
          const v = m && m.data && current[e.name] && m.data.versions && m.data.versions[current[e.name]];
          const bins = [e.name.replace(/^@[^/]+\//, ''), ...(v && v.bin ? Object.keys(v.bin) : [])];
          if (bins.some((b) => new RegExp(`(^|[^\\w-])${escapeRe(b)}([^\\w-]|$)`).test(scripts))) continue;
          if (corpus.includes(e.name)) continue; // mentioned somewhere (config strings, comments) — be conservative
          (e.sec === 'dependencies' ? unusedDeps : unusedDev).push(e);
        }
        const confident = meta.size > 0; // with registry data we also know bins & peers
        for (const e of unusedDeps) {
          const fd = ctx.add({ category: 'unused', severity: 'low', file: pkg.file, snippet: `"${e.name}": "${e.range}"`, title: `"${e.name}" is installed but never used`, why: 'Every extra package is more code that can be compromised, more updates to track and a bigger, slower deploy.', fix: `npm uninstall ${e.name}` });
          if (confident) {
            delete json.dependencies[e.name]; changed = true;
            ctx.markFixed(fd, { before: `"${e.name}": "${e.range}"`, after: '(removed)', summary: 'Removed from dependencies (no import, require, script or config reference found). Re-add it if something breaks.' });
          }
        }
        if (unusedDev.length) ctx.add({ category: 'unused', severity: 'info', file: pkg.file, title: `${unusedDev.length} dev dependenc${unusedDev.length > 1 ? 'ies' : 'y'} may be unused`, snippet: unusedDev.slice(0, 10).map((e) => e.name).join(', '), why: 'Dev tools are often used only through config files, so VibeGuard leaves these for you to confirm.', fix: `If you don't use them: npm uninstall ${unusedDev.slice(0, 5).map((e) => e.name).join(' ')}` });
        ctx.checked('unused');
      }
      if (changed) {
        writePkg(ctx, pkg.file, original, json);
        ctx.note(`package.json was updated in ${dir || 'the project root'} — run \`npm install\` there to refresh package-lock.json, then test the app.`);
      }
      if (!fsHasLock(p, dir)) ctx.add({ category: 'supply', severity: 'low', file: pkg.file, title: 'No lockfile committed', why: 'Without package-lock.json (or yarn/pnpm lock), every install can pull different — possibly compromised — versions.', fix: 'Run npm install and commit package-lock.json. Use `npm ci` in CI/deploys.' });
    }

    // ---------- Python ----------
    for (const req of p.byName('requirements.txt')) {
      const content = p.read(req) || '';
      anyPkg = true;
      const lines = content.split('\n');
      const pkgs = [];
      let pos = 0;
      for (const line of lines) {
        const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(==|>=|~=|<=|>|<)?\s*([0-9][\w.]*)?/.exec(line);
        if (m && !line.trim().startsWith('#') && !line.trim().startsWith('-')) pkgs.push({ name: m[1], op: m[3], ver: m[4], line, pos });
        pos += line.length + 1;
      }
      const popularPy = new Set(POP.PYPI);
      const edits = [];
      if (online && !offline) {
        progress && progress(`Looking up ${pkgs.length} Python packages`);
        await mapLimit(pkgs.slice(0, 150), 6, async (pk) => {
          try {
            const r = await fetchJSON(`${PYPI}/pypi/${encodeURIComponent(pk.name)}/json`);
            if (r.status === 404) {
              const fd = ctx.add({ category: 'supply', severity: 'critical', file: req, snippet: pk.line, title: `Python package "${pk.name}" does not exist on PyPI`, why: 'Likely an AI-hallucinated name — attackers register these with malware.', fix: 'Remove it and find the real package.' });
              edits.push({ index: pk.pos, old: pk.line, new: `# removed by VibeGuard (not on PyPI): ${pk.line}`, finding: fd, summary: 'Commented out the non-existent package.' });
              return;
            }
            if (pk.ver && pk.op === '==') {
              const rv = await fetchJSON(`${PYPI}/pypi/${encodeURIComponent(pk.name)}/${encodeURIComponent(pk.ver)}/json`);
              const vulns = (rv.data && rv.data.vulnerabilities) || [];
              if (vulns.length) {
                const fixedIn = vulns.flatMap((v) => v.fixed_in || []).filter((v) => pyCompare(v, pk.ver) > 0).sort(pyCompare);
                const target = fixedIn.length ? fixedIn[fixedIn.length - 1] : null;
                const fd = ctx.add({ category: 'deps', severity: 'high', file: req, snippet: pk.line, title: `${pk.name}==${pk.ver} has ${vulns.length} known vulnerabilit${vulns.length > 1 ? 'ies' : 'y'}`, why: vulns.slice(0, 3).map((v) => v.id + (v.aliases && v.aliases[0] ? ` / ${v.aliases[0]}` : '')).join(', '), fix: target ? `Upgrade to ${target}.` : 'Upgrade to the latest version.' });
                if (target) edits.push({ index: pk.pos, old: pk.line, new: pk.line.replace(`==${pk.ver}`, `==${target}`).replace(/==\s+/, '=='), finding: fd, summary: `Pinned to ${target}, which fixes the known vulnerabilities.` });
              }
            }
          } catch { networkFailures++; }
        });
      }
      for (const pk of pkgs) {
        const low = pk.name.toLowerCase();
        if (popularPy.has(low)) continue;
        const close = POP.PYPI.find((n) => levenshtein(n, low) === 1 && !low.startsWith(n + '-'));
        if (close) ctx.add({ category: 'supply', severity: 'high', file: req, snippet: pk.line, title: `"${pk.name}" looks like a typo of "${close}"`, why: 'Typo-squatted Python packages are a common malware vector.', fix: `Check the name; did you mean "${close}"?` });
      }
      const unpinned = pkgs.filter((pk) => !pk.op);
      if (unpinned.length) ctx.add({ category: 'supply', severity: 'low', file: req, title: `${unpinned.length} Python package(s) are not version-pinned`, snippet: unpinned.slice(0, 8).map((x) => x.name).join(', '), why: 'Unpinned dependencies can change underneath you and pull in a compromised release.', fix: 'Pin versions (pip freeze > requirements.txt or use pip-tools/uv lock).' });
      ctx.applyEdits(req, edits);
    }
    if (p.byName('pubspec.yaml').length || p.byName('build.gradle').length || p.byName('Podfile').length) anyPkg = true;

    if (!anyPkg) { ctx.na('deps', 'No package manifest (package.json / requirements.txt) found.'); ctx.na('unused', 'No package manifest found.'); ctx.na('supply', 'No package manifest found.'); return; }
    ctx.checked('deps'); ctx.checked('supply');
    if (!ctx.status.has('unused')) ctx.checked('unused');
    if (offline || networkFailures) {
      ctx.depsOffline = true;
      ctx.add({ category: 'deps', severity: 'info', file: null, title: 'Live vulnerability lookup was not available', why: online ? 'The npm/PyPI registries could not be reached from the scanner, so outdated/vulnerable/fake package checks were skipped or partial.' : 'You turned off online checks.', fix: 'Run `npm audit` (and `pip-audit` for Python) locally, or re-scan with online checks on.' });
    }
  },
};

function fsHasLock(p, dir) {
  return ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'bun.lock'].some((n) => p.exists(dir ? `${dir}/${n}` : n));
}

function pyCompare(a, b) {
  const pa = String(a).split(/[.+-]/).map((x) => (/^\d+$/.test(x) ? +x : x));
  const pb = String(b).split(/[.+-]/).map((x) => (/^\d+$/.test(x) ? +x : x));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0, y = pb[i] ?? 0;
    if (x === y) continue;
    if (typeof x === 'number' && typeof y === 'number') return x - y;
    return String(x) < String(y) ? -1 : 1;
  }
  return 0;
}
