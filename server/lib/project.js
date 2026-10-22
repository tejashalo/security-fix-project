'use strict';
/**
 * In-memory view of an extracted project. All reads/writes go through here so
 * fixes can be tracked, diffed, and either flushed to disk or discarded.
 */
const fs = require('fs');
const path = require('path');
const { posix } = require('./util');

const TEXT_EXTS = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.mts', '.cts', '.tsx', '.vue', '.svelte', '.astro', '.html', '.htm', '.ejs', '.hbs', '.handlebars', '.pug', '.njk', '.twig', '.css', '.scss', '.sass', '.less', '.json', '.jsonc', '.json5', '.yml', '.yaml', '.toml', '.ini', '.cfg', '.conf', '.env', '.py', '.rb', '.php', '.go', '.java', '.kt', '.kts', '.swift', '.m', '.mm', '.h', '.dart', '.gradle', '.xml', '.plist', '.properties', '.sql', '.prisma', '.graphql', '.gql', '.md', '.mdx', '.txt', '.sh', '.bash', '.zsh', '.ps1', '.rules', '.tf', '.tfvars', '.dockerfile', '.lock', '.example', '.sample', '.template', '.local', '.development', '.production', '.staging', '.map', '.log', '.bak', '.old', '.orig', '.swp']);
const TEXT_NAMES = new Set(['dockerfile', 'procfile', 'makefile', '.gitignore', '.dockerignore', '.npmrc', '.env', 'gemfile', 'podfile', '_headers', '_redirects', '.htaccess', '.babelrc', '.eslintrc', '.prettierrc', 'firestore.rules', 'storage.rules', 'database.rules.json', 'vercel.json', 'netlify.toml', 'cname']);

// Content of these is not scanned for code issues (still listed for exposure checks).
const SKIP_CONTENT_DIRS = new Set(['node_modules', '.git', '.next', '.nuxt', '.output', '.svelte-kit', '.vercel', '.netlify', 'coverage', '__pycache__', '.venv', 'venv', '.gradle', 'Pods', '.dart_tool', '.expo', 'vendor', '.turbo', '.cache', '.idea', 'DerivedData', '.parcel-cache', '.angular', 'dist', 'build', 'out', '_vibeguard_quarantine', '.vibeguard']);
const LOCK_FILES = new Set(['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'poetry.lock', 'Pipfile.lock', 'Podfile.lock', 'pubspec.lock', 'Gemfile.lock', 'composer.lock', 'Cargo.lock', 'go.sum']);

function isTextFile(rel) {
  const base = posix.basename(rel).toLowerCase();
  if (TEXT_NAMES.has(base) || base.startsWith('.env') || base.startsWith('dockerfile')) return true;
  return TEXT_EXTS.has(posix.extname(base));
}

class Project {
  constructor(root) {
    this.root = root;
    this.files = [];
    this.fileSet = new Set();
    this.dirs = [];
    this._cache = new Map();
    this.original = new Map(); // rel -> original content for changed files (null for created)
    this.changed = new Set();
    this.created = new Set();
    this.moves = []; // { from, to }
    this.hasGit = fs.existsSync(path.join(root, '.git', 'HEAD'));
  }

  static load(root) {
    const p = new Project(root);
    p._walk('');
    p.files.sort((a, b) => a.path.localeCompare(b.path));
    return p;
  }

  _walk(rel) {
    const abs = path.join(this.root, rel);
    let ents;
    try { ents = fs.readdirSync(abs, { withFileTypes: true }); } catch { return; }
    for (const ent of ents) {
      if (ent.isSymbolicLink()) continue;
      const r = rel ? `${rel}/${ent.name}` : ent.name;
      if (ent.isDirectory()) {
        if (ent.name === 'node_modules' || r === '.git') continue;
        this.dirs.push(r);
        this._walk(r);
      } else if (ent.isFile()) {
        let size = 0;
        try { size = fs.statSync(path.join(abs, ent.name)).size; } catch { /* ignore */ }
        const parts = r.split('/');
        const skipped = parts.slice(0, -1).some((d) => SKIP_CONTENT_DIRS.has(d));
        this._addFile({ path: r, size, text: isTextFile(r), skipped, lock: LOCK_FILES.has(ent.name) });
      }
    }
  }

  _addFile(f) { this.files.push(f); this.fileSet.add(f.path); }

  exists(rel) { return this.fileSet.has(rel); }
  dirExists(rel) { return this.dirs.includes(rel); }

  read(rel) {
    if (this._cache.has(rel)) return this._cache.get(rel);
    if (!this.fileSet.has(rel)) return null;
    let s;
    try {
      const buf = fs.readFileSync(path.join(this.root, rel));
      if (buf.length > 3 * 1024 * 1024 || buf.includes(0)) s = null;
      else s = buf.toString('utf8');
    } catch { s = null; }
    this._cache.set(rel, s);
    return s;
  }

  write(rel, content) {
    const exists = this.fileSet.has(rel);
    if (!this.original.has(rel)) this.original.set(rel, exists ? this.read(rel) : null);
    if (!exists) {
      this._addFile({ path: rel, size: Buffer.byteLength(content), text: true, skipped: false, lock: false });
      this.created.add(rel);
    }
    this._cache.set(rel, content);
    this.changed.add(rel);
  }

  move(from, to) {
    if (!this.fileSet.has(from)) return false;
    this.moves.push({ from, to });
    return true;
  }

  /** Files whose content should be scanned for code issues. */
  codeFiles(filter) {
    return this.files.filter((f) => f.text && !f.skipped && !f.lock && f.size < 1.5 * 1024 * 1024 && (!filter || filter(f.path)));
  }

  byExt(...exts) {
    const set = new Set(exts);
    return this.codeFiles((p) => set.has(posix.extname(p).toLowerCase())).map((f) => f.path);
  }

  byName(name) { return this.files.filter((f) => posix.basename(f.path) === name && !f.skipped).map((f) => f.path); }

  flush() {
    for (const rel of this.changed) {
      const abs = path.join(this.root, rel);
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      fs.writeFileSync(abs, this._cache.get(rel));
    }
    for (const { from, to } of this.moves) {
      const a = path.join(this.root, from), b = path.join(this.root, to);
      fs.mkdirSync(path.dirname(b), { recursive: true });
      try { fs.renameSync(a, b); } catch { /* ignore */ }
    }
  }
}

module.exports = { Project, isTextFile, LOCK_FILES };
