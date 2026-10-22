'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createZip } = require('../server/lib/zip');

process.env.VIBEGUARD_TMP = require('./helpers').tmp('vg-srv-');
const { server } = require('../server/index');

let base;
test.before(() => new Promise((r) => server.listen(0, '127.0.0.1', () => { base = `http://127.0.0.1:${server.address().port}`; r(); })));
test.after(() => new Promise((r) => server.close(r)));

async function waitDone(id) {
  for (let i = 0; i < 100; i++) {
    const d = await (await fetch(`${base}/api/jobs/${id}`)).json();
    if (d.status === 'done' || d.status === 'error') return d;
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error('timeout');
}

test('serves the app with strict security headers', async () => {
  const res = await fetch(`${base}/`);
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-security-policy'), /script-src 'self'/);
  assert.equal(res.headers.get('x-frame-options'), 'DENY');
  assert.equal(res.headers.get('x-powered-by'), null);
  assert.equal((await fetch(`${base}/app`)).status, 200);
});

test('static path traversal is blocked', async () => {
  const res = await fetch(`${base}/..%2fpackage.json`);
  assert.ok([403, 404].includes(res.status));
});

test('upload → scan → download', async () => {
  const zip = createZip([
    { name: 'site/index.js', data: Buffer.from("const express = require('express');\nconst app = express();\napp.post('/api/items', (req, res) => res.json(req.body));\napp.listen(3000);\n") },
    { name: 'site/package.json', data: Buffer.from(JSON.stringify({ dependencies: { express: '^4.21.0' } })) },
  ]);
  const fd = new FormData();
  fd.append('mode', 'web');
  fd.append('online', 'false');
  fd.append('project', new Blob([zip], { type: 'application/zip' }), 'site.zip');
  const res = await fetch(`${base}/api/scan`, { method: 'POST', body: fd });
  assert.equal(res.status, 202);
  const { id } = await res.json();
  const job = await waitDone(id);
  assert.equal(job.status, 'done', job.error);
  assert.ok(job.result.findings.length > 0);
  const dl = await fetch(`${base}/api/jobs/${id}/fixed.zip`);
  assert.equal(dl.status, 200);
  assert.match(dl.headers.get('content-disposition'), /attachment; filename="site-vibeguard-fixed.zip"/);
  const html = await fetch(`${base}/api/jobs/${id}/report.html`);
  assert.match(html.headers.get('content-security-policy'), /default-src 'none'/);
  const del = await fetch(`${base}/api/jobs/${id}`, { method: 'DELETE' });
  assert.equal(del.status, 200);
  assert.equal((await fetch(`${base}/api/jobs/${id}`)).status, 404);
});

test('rejects non-zip uploads, bad GitHub URLs and cross-site posts', async () => {
  const fd = new FormData();
  fd.append('project', new Blob([Buffer.from('not a zip at all')]), 'x.zip');
  assert.equal((await fetch(`${base}/api/scan`, { method: 'POST', body: fd })).status, 400);
  const bad = await fetch(`${base}/api/scan-github`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: 'http://169.254.169.254/latest' }) });
  assert.equal(bad.status, 400);
  const xs = await fetch(`${base}/api/demo`, { method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://evil.example' }, body: '{}' });
  assert.equal(xs.status, 403);
});

test('demo scan in app mode', async () => {
  const res = await fetch(`${base}/api/demo`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ mode: 'app', online: false }) });
  const { id } = await res.json();
  const job = await waitDone(id);
  assert.equal(job.status, 'done');
  assert.equal(job.result.meta.mode, 'app');
  assert.ok(job.result.categories.some((c) => c.id === 'mobile'));
});

test('unknown job ids return 404', async () => {
  assert.equal((await fetch(`${base}/api/jobs/${'0'.repeat(32)}`)).status, 404);
  assert.equal((await fetch(`${base}/api/jobs/not-an-id`)).status, 404);
});
