'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { scanProject } = require('../server/lib/scanner');
const { buildDemo } = require('../server/lib/demo');
const { project, read, tmp, j } = require('./helpers');

const scan = (root, opts = {}) => scanProject(root, { mode: 'web', autoFix: true, online: false, ...opts });
const has = (r, re, extra = () => true) => r.findings.some((f) => re.test(f.title) && extra(f));
const nodeCheck = (file) => spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
const pyAvailable = spawnSync('python3', ['--version']).status === 0;

test('web demo: finds the main problem classes and fixes produce valid JS', async () => {
  const root = buildDemo(path.join(tmp(), 'demo'), 'web');
  const r = await scan(root);
  for (const re of [/OpenAI API key hardcoded/, /admin/i, /SQL query/, /MD5/, /CORS|cors\(\)/, /rate limiting/i, /security headers/i, /innerHTML/, /git history/, /lodash/, /IDOR/, /mass assignment/, /JWT is issued without an expiry/]) {
    assert.ok(has(r, re), `expected a finding matching ${re}`);
  }
  for (const f of ['server/index.js', 'server/vibeguard-security.js', 'server/db.js', 'public/app.js']) {
    const res = nodeCheck(path.join(root, f));
    assert.equal(res.status, 0, `${f} must stay valid JS: ${res.stderr}`);
  }
  const idx = read(root, 'server/index.js');
  assert.match(idx, /process\.env\.OPENAI_API_KEY/);
  assert.match(idx, /applyVibeGuard\(app\)/);
  assert.match(idx, /cors\(vibeguardCorsOptions\)/);
  assert.match(idx, /'\/admin', vibeguardRequireAdmin, adminRoutes/);
  assert.ok(idx.indexOf('loadEnvFile') < idx.indexOf("require('./vibeguard-security')"), 'env must load before modules that read it');
  assert.doesNotMatch(idx, new RegExp(j('sk-', 'proj-')), 'secret removed from code');
  assert.match(read(root, '.gitignore'), /^\.env$/m);
  assert.ok(fs.existsSync(path.join(root, '_vibeguard_quarantine/public/backup.sql')));
  // secrets never leak into the report
  const json = JSON.stringify(r);
  assert.ok(!json.includes(j('sk-', 'proj-', 'Vg7dEmoKeyNotReal')), 'report must redact secrets');
  assert.ok(r.score.after >= r.score.before);
});

test('the user\'s security module works at runtime (headers, rate limit, admin guard)', async () => {
  const root = buildDemo(path.join(tmp(), 'demo'), 'web', { withGit: false });
  await scan(root);
  const mod = require(path.join(root, 'server/vibeguard-security.js'));
  const headers = {};
  const res = { setHeader: (k, v) => { headers[k] = v; }, removeHeader() {}, status(c) { this.code = c; return this; }, json(b) { this.body = b; return this; } };
  let nexted = 0;
  mod.vibeguardSecurityHeaders()({ headers: {} }, res, () => nexted++);
  assert.equal(headers['X-Frame-Options'], 'DENY');
  assert.ok(headers['Content-Security-Policy-Report-Only']);
  const limit = mod.vibeguardRateLimit({ max: 2 });
  for (let i = 0; i < 3; i++) limit({ ip: '1.2.3.4' }, res, () => nexted++);
  assert.equal(res.code, 429);
  const r2 = { ...res, code: null, status(c) { this.code = c; return this; } };
  mod.vibeguardRequireAdmin({ user: { role: 'user' } }, r2, () => nexted++);
  assert.equal(r2.code, 403);
  const before = nexted;
  mod.vibeguardRequireAdmin({ user: { role: 'admin' } }, r2, () => nexted++);
  assert.equal(nexted, before + 1);
});

test('app demo: mobile checks run and manifest/plist are fixed', async () => {
  const root = buildDemo(path.join(tmp(), 'demo'), 'app');
  const r = await scan(root, { mode: 'app' });
  assert.ok(has(r, /debuggable/, (f) => f.fixed));
  assert.ok(has(r, /App Transport Security/, (f) => f.fixed));
  assert.ok(has(r, /dangerouslyAllowBrowser/));
  assert.ok(has(r, /AsyncStorage/));
  assert.ok(has(r, /Row Level Security is OFF/));
  assert.ok(has(r, /EXPO_PUBLIC_SUPABASE_SERVICE_ROLE_KEY/));
  assert.match(read(root, 'android/app/src/main/AndroidManifest.xml'), /android:debuggable="false"/);
  assert.equal(r.categories.find((c) => c.id === 'mobile').status, 'action');
});

test('report-only mode changes nothing on disk', async () => {
  const root = buildDemo(path.join(tmp(), 'demo'), 'web', { withGit: false });
  const before = read(root, 'server/index.js');
  const r = await scan(root, { autoFix: false });
  assert.equal(read(root, 'server/index.js'), before);
  assert.equal(r.counts.fixed, 0);
  assert.ok(r.counts.fixable > 0);
  assert.ok(r.proposedChanges.length > 0);
});

test('Next.js: security middleware created, admin API flagged, public secret env flagged', async () => {
  const root = project({
    'package.json': JSON.stringify({ dependencies: { next: '14.2.0', react: '18.2.0' } }),
    'tsconfig.json': '{}',
    'app/page.tsx': 'export default function Page() { return <div>Hi</div>; }',
    'app/api/admin/users/route.ts': 'export async function DELETE(req: Request) { await db.user.deleteMany(); return Response.json({ ok: true }); }',
    'app/api/notes/route.ts': 'export async function POST(req: Request) { const b = await req.json(); await db.note.create({ data: b }); return Response.json({}); }',
    'lib/ai.ts': 'const key = process.env.NEXT_PUBLIC_OPENAI_API_KEY;',
    'next.config.js': 'module.exports = { productionBrowserSourceMaps: true };',
  });
  const r = await scan(root);
  assert.ok(fs.existsSync(path.join(root, 'middleware.ts')));
  assert.ok(has(r, /admin API/));
  assert.ok(has(r, /changes data without checking the user/));
  assert.ok(has(r, /NEXT_PUBLIC_OPENAI_API_KEY/, (f) => f.severity === 'critical'));
  assert.match(read(root, 'next.config.js'), /productionBrowserSourceMaps: false/);
});

test('Python: Flask debug, secrets, headers and uploads fixed with valid syntax', { skip: !pyAvailable }, async () => {
  const root = project({
    'requirements.txt': 'flask==2.0.0\nflask-cors\n',
    'app.py': `from flask import Flask, request\nfrom flask_cors import CORS\nimport yaml\n\napp = Flask(__name__)\nCORS(app)\nSECRET_KEY = "${j('a8f5f167f44f4964', 'e6c998dee827110c')}"\n\n@app.route("/upload", methods=["POST"])\ndef upload():\n    f = request.files["file"]\n    f.save(os.path.join("uploads", f.filename))\n    cfg = yaml.load(request.data)\n    return "ok"\n\nif __name__ == "__main__":\n    app.run(debug=True)\n`,
  });
  const r = await scan(root);
  const src = read(root, 'app.py');
  assert.match(src, /os\.environ\.get\("SECRET_KEY"\)/);
  assert.match(src, /secure_filename\(f\.filename\)/);
  assert.match(src, /yaml\.safe_load/);
  assert.match(src, /FLASK_DEBUG/);
  assert.match(src, /_vibeguard_security_headers/);
  assert.match(src, /CORS\(app, origins=/);
  const c = spawnSync('python3', ['-m', 'py_compile', path.join(root, 'app.py')], { encoding: 'utf8' });
  assert.equal(c.status, 0, c.stderr);
  assert.ok(has(r, /debug=True/, (f) => f.fixed));
});

test('Firebase rules and Supabase-only projects', async () => {
  const root = project({
    'package.json': JSON.stringify({ dependencies: { firebase: '^10.0.0', react: '^18.0.0', vite: '^5.0.0' } }),
    'firestore.rules': "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /{document=**} {\n      allow read, write: if true;\n    }\n  }\n}\n",
    'src/App.jsx': 'export default function App() { return <p>hi</p>; }',
  });
  const r = await scan(root);
  assert.match(read(root, 'firestore.rules'), /request\.auth != null/);
  assert.ok(has(r, /Firebase rules allow everyone/, (f) => f.fixed));
  assert.equal(r.categories.find((c) => c.id === 'ratelimit').status, 'na');
});

test('clean project scores well and reports passes', async () => {
  const root = project({
    'package.json': JSON.stringify({ dependencies: { express: '^4.21.0', helmet: '^7.0.0', 'express-rate-limit': '^7.0.0', zod: '^3.0.0' } }),
    'package-lock.json': '{}',
    '.gitignore': 'node_modules\n.env\n',
    '.env.example': 'PORT=\n',
    'index.js': "const express = require('express');\nconst helmet = require('helmet');\nconst rateLimit = require('express-rate-limit');\nconst { z } = require('zod');\nconst app = express();\napp.use(helmet());\napp.use(rateLimit({ windowMs: 60000, max: 100 }));\napp.use(express.json({ limit: '100kb' }));\napp.get('/health', (req, res) => res.json({ ok: true }));\napp.listen(process.env.PORT);\n",
  });
  const r = await scan(root);
  assert.ok(r.score.after >= 85, `score was ${r.score.after}: ${r.findings.map((f) => f.title).join(' | ')}`);
  assert.equal(r.categories.find((c) => c.id === 'headers').status, 'passed');
});

test('dependency checks with a mocked registry: fake package removed, vulnerable one upgraded', async () => {
  const realFetch = global.fetch;
  const versions = (list) => Object.fromEntries(list.map((v) => [v, {}]));
  global.fetch = async (url, opts = {}) => {
    const u = String(url);
    const reply = (status, body) => ({ ok: status < 400, status, json: async () => body });
    if (u.endsWith('/-/npm/v1/security/advisories/bulk')) {
      const body = JSON.parse(opts.body);
      return reply(200, body.lodash ? { lodash: [{ title: 'Prototype Pollution', severity: 'high', vulnerable_versions: '<4.17.21', url: 'https://example.test/adv' }] } : {});
    }
    if (u.includes('totally-made-up-ai-pkg')) return reply(404, {});
    if (u.includes('lodash')) return reply(200, { 'dist-tags': { latest: '4.17.21' }, versions: versions(['4.17.15', '4.17.20', '4.17.21']) });
    if (u.includes('express')) return reply(200, { 'dist-tags': { latest: '5.1.0' }, versions: versions(['4.17.1', '4.21.2', '5.1.0']) });
    return reply(404, {});
  };
  try {
    const root = project({
      'package.json': JSON.stringify({ dependencies: { express: '^4.17.1', lodash: '^4.17.15', 'totally-made-up-ai-pkg': '^1.0.0' } }, null, 2),
      'index.js': "const express = require('express'); const _ = require('lodash'); require('totally-made-up-ai-pkg');",
    });
    const r = await scanProject(root, { mode: 'web', autoFix: true, online: true });
    const pkg = JSON.parse(read(root, 'package.json'));
    assert.equal(pkg.dependencies['totally-made-up-ai-pkg'], undefined);
    assert.equal(pkg.dependencies.lodash, '^4.17.21');
    assert.equal(pkg.dependencies.express, '^4.21.2');
    assert.ok(has(r, /does not exist on npm/, (f) => f.fixed));
    assert.ok(has(r, /lodash@4\.17\.15 has 1 known vulnerability/, (f) => f.fixed));
    assert.ok(has(r, /new major version/));
  } finally { global.fetch = realFetch; }
});
