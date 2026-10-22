'use strict';
const { posix, lineIndexer, lineText, clip, randomSecret, relImport, escapeRe, matchParen } = require('./util');
const T = require('./templates');

const CLIENT_DIR_RE = /(^|\/)(public|static|client|frontend|web|www|components|src\/components|src\/pages|src\/views|views|src\/app\/components|assets|lib\/screens|lib\/widgets|android|ios|app\/src\/main)\//;
const SERVER_DIR_RE = /(^|\/)(server|backend|api|functions|netlify\/functions|supabase\/functions|routes|controllers|middleware|middlewares|services|models|scripts|lambda|workers?)\//;

class Context {
  constructor(project, det, opts) {
    this.p = project;
    this.det = det;
    this.opts = { mode: 'web', autoFix: true, online: true, ...opts };
    this.findings = [];
    this.status = new Map(); // category -> { state: 'checked' | 'na', note }
    this.secretValues = new Set();
    this.notes = []; // project-level manual steps
    this.generated = []; // { file, why }
    this.errors = [];
    this.securityModule = null;
    this._lineIdx = new Map();
  }

  /** Paths/rules listed in .vibeguardignore, or lines marked `vibeguard-ignore`, are skipped. */
  isIgnored(f) {
    if (this._ignore === undefined) {
      const lines = (this.p.read('.vibeguardignore') || '').split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
      this._ignore = lines.map((l) => {
        if (l.startsWith('rule:')) return { rule: l.slice(5).trim() };
        const pat = l.replace(/^\//, '');
        const re = new RegExp('^' + pat.split('**').map((part) => part.split('*').map(escapeRe).join('[^/]*')).join('.*') + (pat.endsWith('/') ? '.*' : '(/.*)?') + '$');
        return { re };
      });
    }
    if (f.file && this._ignore.some((i) => i.re && i.re.test(f.file))) return true;
    if (this._ignore.some((i) => i.rule && (i.rule === f.category || i.rule === f.title))) return true;
    if (f.snippet && /vibeguard-ignore/.test(f.snippet)) return true;
    return false;
  }

  // ----- findings -----
  add(f) {
    const finding = {
      id: `VG-${String(this.findings.length + 1).padStart(3, '0')}`,
      severity: 'medium', fixed: false, fixable: false, line: null, snippet: '',
      ...f,
    };
    if (this.isIgnored(finding)) { finding.ignored = true; this.ignoredCount = (this.ignoredCount || 0) + 1; return finding; }
    if (finding.snippet) finding.snippet = clip(finding.snippet, 220);
    this.findings.push(finding);
    this.checked(finding.category);
    return finding;
  }

  /** Convenience: create a finding located at `index` in `file`. */
  at(file, index, f) {
    const content = this.p.read(file) || '';
    return this.add({ file, line: this.lineOf(file, content, index), snippet: lineText(content, index), ...f });
  }

  lineOf(file, content, index) {
    const key = file + ':' + content.length;
    let fn = this._lineIdx.get(key);
    if (!fn) { fn = lineIndexer(content); this._lineIdx.set(key, fn); }
    return fn(index);
  }

  checked(cat, note) { if (!this.status.has(cat) || this.status.get(cat).state === 'na') this.status.set(cat, { state: 'checked', note }); }
  na(cat, note) { if (!this.status.has(cat)) this.status.set(cat, { state: 'na', note }); }
  note(text) { if (!this.notes.includes(text)) this.notes.push(text); }

  get fixing() { return true; } // fixes are always computed in memory; flushed only when autoFix is on

  /**
   * Apply text edits to a file. edits: [{ index, old, new, finding }]
   * Applied from the end so indexes stay valid. Marks findings fixed with before/after.
   */
  applyEdits(file, edits) {
    if (!edits.length) return 0;
    let content = this.p.read(file);
    if (content == null) return 0;
    const sorted = [...edits].sort((a, b) => b.index - a.index);
    let lastStart = Infinity;
    let applied = 0;
    for (const e of sorted) {
      if (e.finding && e.finding.ignored) continue; // user asked to ignore this one
      if (e.index + e.old.length > lastStart) continue; // overlapping edit — skip
      if (content.substr(e.index, e.old.length) !== e.old) continue;
      const ls = content.lastIndexOf('\n', e.index - 1) + 1;
      let le = content.indexOf('\n', e.index + e.old.length);
      if (le === -1) le = content.length;
      const before = content.slice(ls, le);
      const after = before.slice(0, e.index - ls) + e.new + before.slice(e.index - ls + e.old.length);
      content = content.slice(0, e.index) + e.new + content.slice(e.index + e.old.length);
      lastStart = e.index;
      applied++;
      if (e.finding) this.markFixed(e.finding, { before, after, summary: e.summary });
    }
    if (applied) this.p.write(file, content);
    return applied;
  }

  markFixed(finding, { before, after, summary } = {}) {
    finding.fixed = true;
    finding.fixable = true;
    if (summary) finding.fixSummary = summary;
    if (before !== undefined || after !== undefined) finding.diff = { before: clip(before ?? '', 400), after: clip(after ?? '', 600) };
  }

  /** Insert text after the line containing `index`. */
  insertAfterLine(file, index, text, finding, summary) {
    const content = this.p.read(file);
    let le = content.indexOf('\n', index);
    if (le === -1) { le = content.length; text = '\n' + text.replace(/\n$/, ''); }
    else le += 1;
    return this.applyEdits(file, [{ index: le, old: '', new: text, finding, summary }]);
  }

  createFile(file, content, why) {
    if (this.p.exists(file)) return false;
    this.p.write(file, content);
    this.generated.push({ file, why });
    return true;
  }

  // ----- classification helpers -----
  pkgDirOf(file) {
    let dir = posix.dirname(file);
    while (dir && dir !== '.') {
      if (this.p.exists(`${dir}/package.json`) || this.p.exists(`${dir}/requirements.txt`) || this.p.exists(`${dir}/pyproject.toml`)) return dir;
      dir = posix.dirname(dir);
    }
    return '';
  }

  join(dir, name) { return dir && dir !== '.' ? `${dir}/${name}` : name; }

  pkgOf(file) {
    const dir = this.pkgDirOf(file);
    return this.det.pkgs.find((k) => (k.dir === '.' ? '' : k.dir) === dir) || null;
  }

  isClient(file) {
    const content = this.p.read(file) || '';
    if (/\.(jsx|tsx|vue|svelte|html?|dart|swift|kt|java|m|mm|astro)$/.test(file) && !/(^|\/)(server|backend|api)\//.test(file)) {
      if (/\.(kt|java)$/.test(file) && !/(^|\/)(android|app\/src)\//.test(file)) return false;
      if (/\.(jsx|tsx)$/.test(file) && /(^|\/)(pages\/api|app\/api)\//.test(file)) return false;
      if (/\.(jsx|tsx|astro)$/.test(file) && this.det.has('next') && /(^|\/)app\//.test(file) && !/^['"]use client['"]/m.test(content)) return false;
      return true;
    }
    if (/^\s*['"]use client['"]/.test(content)) return true;
    if (/^\s*['"]use server['"]/.test(content)) return false;
    if (/(^|\/)(pages\/api|app\/api|api)\//.test(file) || /(^|\/)route\.(js|ts)$/.test(file)) return false;
    if (SERVER_DIR_RE.test(file)) return false;
    if (/\.(py|rb|php|go|sql)$/.test(file)) return false;
    if (this.det.isApp && /\.(js|ts)$/.test(file) && !SERVER_DIR_RE.test(file)) {
      const pkg = this.pkgOf(file);
      const d = pkg ? { ...pkg.json.dependencies, ...pkg.json.devDependencies } : {};
      if (d['react-native'] || d.expo || d['@capacitor/core']) return true;
    }
    if (CLIENT_DIR_RE.test(file)) return true;
    if (/\b(document\.|window\.|localStorage|useState\(|useEffect\(|import\.meta\.env\.VITE_)/.test(content)) return true;
    const pkg = this.pkgOf(file);
    if (pkg) {
      const d = { ...pkg.json.dependencies, ...pkg.json.devDependencies };
      const isFrontendPkg = (d.react || d.vue || d.svelte || d['@angular/core'] || d.vite) && !(d.express || d.fastify || d.koa || d.hono || d.next || d['@nestjs/core'] || d.nuxt);
      if (isFrontendPkg) return true;
    }
    return false;
  }

  moduleKind(file) {
    if (/\.(ts|mts|tsx)$/.test(file)) return 'ts';
    if (/\.mjs$/.test(file)) return 'esm';
    if (/\.cjs$/.test(file)) return 'cjs';
    const content = this.p.read(file) || '';
    const pkg = this.pkgOf(file);
    if (pkg && pkg.json.type === 'module') return 'esm';
    if (/^\s*import\s[^;]*\bfrom\s+['"]|^\s*export\s+(default|const|function|async|\{)/m.test(content)) return 'esm';
    return 'cjs';
  }

  // ----- project files -----
  /** Ensure root .gitignore contains lines. Returns array of lines added. */
  ensureGitignore(lines, dir = '') {
    const file = this.join(dir, '.gitignore');
    const existing = this.p.read(file) || '';
    const have = new Set(existing.split(/\r?\n/).map((l) => l.trim()));
    const covers = (l) => {
      if (have.has(l) || have.has('/' + l)) return true;
      if (l === '.env' && [...have].some((h) => /^\/?(\.env\*?|\*\.env|\.env\.\*)$/.test(h))) return true;
      if (l === 'node_modules/' && (have.has('node_modules') || have.has('/node_modules') || have.has('/node_modules/'))) return true;
      return false;
    };
    const missing = lines.filter((l) => l.startsWith('#') ? false : !covers(l));
    if (!missing.length) return [];
    const header = lines.find((l) => l.startsWith('#'));
    const block = (existing && !existing.endsWith('\n') ? '\n' : '') + (existing ? '\n' : '') + (header ? header + '\n' : '') + missing.join('\n') + '\n';
    if (!this.p.exists(file)) this.generated.push({ file, why: 'Keeps secrets, keys, databases and logs out of git.' });
    this.p.write(file, existing + block);
    return missing;
  }

  gitignoreCovers(name, dir = '') {
    const g = this.p.read(this.join(dir, '.gitignore')) || this.p.read('.gitignore') || '';
    const lines = g.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
    return lines.some((l) => {
      const pat = l.replace(/^\//, '').replace(/\/$/, '');
      const re = new RegExp('^' + pat.split('*').map(escapeRe).join('.*') + '$');
      return re.test(name) || re.test(posix.basename(name));
    });
  }

  /** Add/ensure KEY=value in .env (and KEY= in .env.example) for the package that owns `nearFile`. */
  envSet(name, value, nearFile = '') {
    const dir = this.pkgDirOf(nearFile);
    const envFile = this.join(dir, '.env');
    const cur = this.p.read(envFile) || '';
    if (!new RegExp(`^\\s*${escapeRe(name)}\\s*=`, 'm').test(cur)) {
      const needsQuote = /[\s#"'$]/.test(value);
      const v = needsQuote ? JSON.stringify(value) : value;
      this.p.write(envFile, cur + (cur && !cur.endsWith('\n') ? '\n' : '') + `${name}=${v}\n`);
    }
    this.envExampleAdd([name], nearFile);
    this.ensureGitignore(T.GITIGNORE_BLOCK);
    return envFile;
  }

  envExampleAdd(names, nearFile = '') {
    const dir = this.pkgDirOf(nearFile);
    const file = this.join(dir, '.env.example');
    const cur = this.p.read(file) || '';
    const missing = names.filter((n) => !new RegExp(`^\\s*#?\\s*${escapeRe(n)}\\s*=`, 'm').test(cur));
    if (!missing.length) return [];
    const head = cur ? '' : '# Copy this file to .env and fill in real values. Never commit .env.\n';
    this.p.write(file, cur + (cur && !cur.endsWith('\n') ? '\n' : '') + head + missing.map((n) => `${n}=`).join('\n') + '\n');
    if (!cur) this.generated.push({ file, why: 'Documents every environment variable your app needs (without values).' });
    return missing;
  }

  /** Ensure the JS/TS file loads .env before anything else (only when the framework doesn't already). */
  ensureEnvLoaded(file) {
    const d = this.det;
    if (d.hasAny('next', 'nuxt', '@sveltejs/kit', 'vite', 'astro', 'expo', '@remix-run/node')) return;
    const entry = (d.expressEntries[0] && d.expressEntries[0].file) || file;
    const content = this.p.read(entry) || '';
    if (/dotenv|loadEnvFile|--env-file/.test(content)) return;
    const pkg = this.pkgOf(entry);
    const scripts = pkg ? JSON.stringify(pkg.json.scripts || {}) : '';
    if (/--env-file|dotenv/.test(scripts)) return;
    const line = this.moduleKind(entry) === 'cjs'
      ? "try { process.loadEnvFile(); } catch { /* .env is optional; needs Node 20.12+ (or use the dotenv package) */ }\n"
      : "try { process.loadEnvFile(); } catch { /* .env is optional; needs Node 20.12+ (or use the dotenv package) */ }\n";
    const at = this.veryTopIndex(content);
    this.applyEdits(entry, [{ index: at, old: '', new: line }]);
    this.note(`VibeGuard added \`process.loadEnvFile()\` to ${entry} so values in .env are loaded (Node 20.12+). On older Node, install dotenv and add \`require('dotenv').config()\`.`);
  }

  ensurePythonEnvLoaded(file) {
    const content = this.p.read(file) || '';
    if (/load_dotenv|from dotenv/.test(content)) return;
    const block = 'try:\n    from dotenv import load_dotenv\n    load_dotenv()\nexcept ImportError:  # pip install python-dotenv\n    pass\n';
    this.applyEdits(file, [{ index: this.pyTopInsertIndex(content), old: '', new: block }]);
    const req = this.join(this.pkgDirOf(file), 'requirements.txt');
    const r = this.p.read(req);
    if (r != null && !/python-dotenv/i.test(r)) this.p.write(req, r + (r.endsWith('\n') ? '' : '\n') + 'python-dotenv\n');
  }

  ensurePythonImport(file, stmt) {
    const content = this.p.read(file) || '';
    const re = new RegExp('^' + escapeRe(stmt) + '\\s*$', 'm');
    if (re.test(content)) return;
    if (stmt === 'import os' && /^import os\b|^import [^\n]*\bos\b/m.test(content)) return;
    this.applyEdits(file, [{ index: this.pyTopInsertIndex(content), old: '', new: stmt + '\n' }]);
  }

  pyTopInsertIndex(content) {
    const lines = content.split('\n');
    let idx = 0, pos = 0, inDoc = false;
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      const t = l.trim();
      const lineEnd = pos + l.length + 1;
      if (i === 0 && t.startsWith('#!')) { idx = lineEnd; pos = lineEnd; continue; }
      if (inDoc) { if (t.includes('"""') || t.includes("'''")) { inDoc = false; idx = lineEnd; } pos = lineEnd; continue; }
      if (/^("""|''')/.test(t) && idx === pos) { if (!(t.length > 3 && (t.endsWith('"""') || t.endsWith("'''")))) inDoc = true; idx = lineEnd; pos = lineEnd; continue; }
      if (/^#.*coding[:=]/.test(t) || /^from __future__ import/.test(t)) { idx = lineEnd; pos = lineEnd; continue; }
      break;
    }
    return Math.min(idx, content.length);
  }

  /** Index after a shebang / 'use strict' directive — the earliest safe place for code. */
  veryTopIndex(content) {
    let idx = 0;
    const re = /^(#![^\n]*\n|\s*['"]use (strict|client|server)['"];?[^\n]*\n)/;
    let m;
    while ((m = re.exec(content.slice(idx)))) idx += m[0].length;
    return idx;
  }

  /** Index right after the leading import/require block of a JS/TS file. */
  topInsertIndex(content) {
    const lines = content.split('\n');
    let pos = 0, best = 0, inImport = false;
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      const t = l.trim();
      const end = pos + l.length + 1;
      if (inImport) { if (/\bfrom\s+['"][^'"]+['"]|['"];?\s*$/.test(t)) { inImport = false; best = end; } pos = end; continue; }
      if (i === 0 && t.startsWith('#!')) { best = end; pos = end; continue; }
      if (/^['"]use (strict|client|server)['"];?$/.test(t) || /^try \{ process\.loadEnvFile\(\)/.test(t)) { best = end; pos = end; continue; }
      if (t === '' || t.startsWith('//') || t.startsWith('/*') || t.startsWith('*')) { pos = end; continue; }
      if (/^import\s/.test(t)) {
        if (/\bfrom\s+['"][^'"]+['"]|^import\s+['"][^'"]+['"]/.test(t)) best = end; else inImport = true;
        pos = end; continue;
      }
      if (/^(const|let|var)\s+[\w${}\s,:]+=\s*require\(/.test(t) || /^require\(/.test(t)) { best = end; pos = end; continue; }
      break;
    }
    return Math.min(best, content.length);
  }

  /** Create (once) the Express security module next to the first Express entry. */
  ensureSecurityModule() {
    if (this.securityModule) return this.securityModule;
    const entry = this.det.expressEntries[0];
    if (!entry) return null;
    const kind = this.moduleKind(entry.file);
    const dir = posix.dirname(entry.file);
    const ext = kind === 'ts' ? '.ts' : /\.mjs$/.test(entry.file) ? '.mjs' : /\.cjs$/.test(entry.file) ? '.cjs' : '.js';
    const file = this.join(dir === '.' ? '' : dir, 'vibeguard-security' + ext);
    if (!this.p.exists(file)) {
      this.createFile(file, T.expressSecurityModule(kind), 'Zero-dependency Express middleware: security headers, rate limits, CORS allow-list, admin guard.');
    }
    this.securityModule = { file, kind };
    return this.securityModule;
  }

  /** Make sure `file` imports `names` from the security module. */
  ensureSecurityImport(file, names) {
    const mod = this.ensureSecurityModule();
    if (!mod) return false;
    let content = this.p.read(file) || '';
    const kind = this.moduleKind(file);
    const usesJsExt = /from\s+['"]\.{1,2}\/[^'"]+\.js['"]/.test(content);
    let spec = relImport(file, mod.file, { keepExt: kind === 'esm' && mod.kind !== 'ts' });
    if (mod.kind === 'ts' && usesJsExt) spec = relImport(file, mod.file).replace(/$/, '.js');
    if (kind === 'cjs' && /\.cjs$/.test(mod.file)) spec = relImport(file, mod.file, { keepExt: true });
    const specRe = new RegExp(`(import\\s*\\{([^}]*)\\}\\s*from\\s*['"]${escapeRe(spec)}['"]|const\\s*\\{([^}]*)\\}\\s*=\\s*require\\(\\s*['"]${escapeRe(spec)}['"]\\s*\\))`);
    const m = specRe.exec(content);
    if (m) {
      const current = (m[2] || m[3] || '').split(',').map((s) => s.trim()).filter(Boolean);
      const missing = names.filter((n) => !current.includes(n));
      if (!missing.length) return true;
      const list = [...current, ...missing].join(', ');
      const replacement = m[0].replace(/\{[^}]*\}/, `{ ${list} }`);
      return this.applyEdits(file, [{ index: m.index, old: m[0], new: replacement }]) > 0;
    }
    const stmt = kind === 'cjs'
      ? `const { ${names.join(', ')} } = require('${spec}'); // added by VibeGuard\n`
      : `import { ${names.join(', ')} } from '${spec}'; // added by VibeGuard\n`;
    content = this.p.read(file) || '';
    return this.applyEdits(file, [{ index: this.topInsertIndex(content), old: '', new: stmt }]) > 0;
  }

  /** End index (exclusive, after newline) of the statement starting at `index` (balances parens). */
  statementEnd(content, index) {
    const open = content.indexOf('(', index);
    let end = open >= 0 ? matchParen(content, open) : -1;
    if (end < 0) end = index;
    let nl = content.indexOf('\n', end);
    if (nl === -1) nl = content.length; else nl += 1;
    return nl;
  }

  newSecret() { return randomSecret(32); }
}

module.exports = { Context };
