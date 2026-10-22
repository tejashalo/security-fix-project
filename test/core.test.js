'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { createZip, safeExtract, listEntries } = require('../server/lib/zip');
const semver = require('../server/lib/semver');
const { parseMultipart } = require('../server/multipart');
const { unifiedDiff } = require('../server/lib/diff');
const { findSecrets } = require('../server/lib/patterns');
const { isPlaceholder, shannon, splitArgs } = require('../server/lib/util');
const { tmp, j } = require('./helpers');

test('zip round-trip', () => {
  const buf = createZip([{ name: 'proj/a.txt', data: Buffer.from('hello') }, { name: 'proj/sub/b.js', data: Buffer.from('x'.repeat(5000)) }]);
  const dest = tmp();
  const { root, stats } = safeExtract(buf, dest);
  assert.equal(path.basename(root), 'proj');
  assert.equal(stats.files, 2);
  assert.equal(fs.readFileSync(path.join(root, 'sub/b.js'), 'utf8'), 'x'.repeat(5000));
});

test('zip-slip paths are rejected', () => {
  const buf = createZip([{ name: '../../evil.txt', data: Buffer.from('pwned') }]);
  assert.throws(() => safeExtract(buf, tmp()), /zip-slip/);
  const abs = createZip([{ name: '/etc/evil.txt', data: Buffer.from('pwned') }]);
  assert.throws(() => safeExtract(abs, tmp()), /zip-slip/);
});

test('zip bombs are stopped by the per-file limit', () => {
  const buf = createZip([{ name: 'big.txt', data: Buffer.alloc(3 * 1024 * 1024, 65) }]);
  const { stats } = (() => { try { return safeExtract(buf, tmp(), { maxFileBytes: 1024 * 1024 }); } catch (e) { return { stats: { error: e.message } }; } })();
  assert.ok(stats.skippedLarge === 1 || /too large|bomb|did not contain/.test(stats.error || ''));
});

test('symlink entries are skipped and node_modules ignored', () => {
  const buf = createZip([{ name: 'link', data: Buffer.from('/etc/passwd') }, { name: 'node_modules/x/index.js', data: Buffer.from('1') }, { name: 'a.js', data: Buffer.from('1') }]);
  // mark first entry as a symlink in the central directory (unix mode 0120777)
  const entries = listEntries(buf);
  assert.equal(entries.length, 3);
  const eocd = buf.length - 22;
  const cdOffset = buf.readUInt32LE(eocd + 16);
  buf.writeUInt32LE((0o120777 << 16) >>> 0, cdOffset + 38);
  const { stats } = safeExtract(buf, tmp());
  assert.equal(stats.skippedSymlinks, 1);
  assert.equal(stats.skippedDeps, 1);
  assert.equal(stats.files, 1);
});

test('semver basics', () => {
  assert.ok(semver.satisfies('1.2.3', '^1.0.0'));
  assert.ok(!semver.satisfies('2.0.0', '^1.0.0'));
  assert.ok(semver.satisfies('0.2.5', '^0.2.1'));
  assert.ok(!semver.satisfies('0.3.0', '^0.2.1'));
  assert.ok(semver.satisfies('4.17.20', '<4.17.21'));
  assert.ok(semver.satisfies('1.5.0', '>=1.0.0 <1.6.0 || >=2.0.0 <2.1.0'));
  assert.ok(!semver.satisfies('1.0.0-beta.1', '^1.0.0'));
  assert.equal(semver.minVersion('^4.17.1'), '4.17.1');
  assert.equal(semver.minVersion('~1.2'), '1.2.0');
  assert.equal(semver.maxSatisfying(['1.0.0', '1.4.2', '2.0.0'], '^1.0.0'), '1.4.2');
  assert.equal(semver.rewriteRange('^1.2.0', '1.4.0'), '^1.4.0');
  assert.equal(semver.rewriteRange('1.2.0', '1.4.0'), '1.4.0');
});

test('multipart parsing', () => {
  const b = 'XyZ';
  const body = Buffer.concat([
    Buffer.from(`--${b}\r\nContent-Disposition: form-data; name="mode"\r\n\r\napp\r\n`),
    Buffer.from(`--${b}\r\nContent-Disposition: form-data; name="project"; filename="p.zip"\r\nContent-Type: application/zip\r\n\r\n`),
    Buffer.from([1, 2, 3, 13, 10, 4]),
    Buffer.from(`\r\n--${b}--\r\n`),
  ]);
  const parts = parseMultipart(body, b);
  assert.equal(parts.length, 2);
  assert.equal(parts[0].data.toString(), 'app');
  assert.equal(parts[1].filename, 'p.zip');
  assert.deepEqual([...parts[1].data], [1, 2, 3, 13, 10, 4]);
});

test('unified diff marks changes', () => {
  const d = unifiedDiff('a\nb\nc\n', 'a\nB\nc\n', 'f.txt');
  assert.match(d, /-b\n\+B/);
});

test('secret patterns', () => {
  const text = `const a = "${j('sk-proj-', 'abcdefghijklmnopqrstuvwxyz0123456789ABCD')}";\nconst k = '${j('AKIA', 'ABCDEFGHIJKLMNOP')}';\nconst password = "changeme";\nconst apiKey = "${j('Zx9', 'qL2mN8pR4tV6wY1b')}";`;
  const hits = findSecrets(text, { isPlaceholder, shannon });
  const ids = hits.map((h) => h.pattern.id);
  assert.ok(ids.includes('openai'));
  assert.ok(ids.includes('aws-access'));
  assert.ok(ids.includes('generic'));
  assert.ok(!hits.some((h) => h.value === 'changeme'), 'placeholders are ignored');
});

test('supabase anon vs service_role keys are told apart', () => {
  const mk = (role) => `eyJhbGciOiJIUzI1NiJ9.${Buffer.from(JSON.stringify({ role, iss: 'supabase' })).toString('base64url')}.abcdefghijklmnop`;
  const anon = findSecrets(`x = "${mk('anon')}"`, {});
  const svc = findSecrets(`x = "${mk('service_role')}"`, {});
  assert.ok(anon[0].pattern.supabaseAnon);
  assert.ok(svc[0].pattern.serviceRole);
  assert.equal(svc[0].pattern.severity, 'critical');
});

test('splitArgs respects nesting and strings', () => {
  assert.deepEqual(splitArgs("{ a: 1, b: 2 }, 'x,y', fn(1, 2)").map((s) => s.trim()), ['{ a: 1, b: 2 }', "'x,y'", 'fn(1, 2)']);
});
