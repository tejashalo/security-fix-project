'use strict';
/**
 * VibeGuard web server — zero dependencies (Node's built-in http only).
 * It practises what it preaches: strict CSP, security headers, rate limits,
 * body size limits, unguessable job ids, automatic deletion of uploads.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const jobs = require('./jobs');
const { parseMultipart } = require('./multipart');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const MAX_UPLOAD = Number(process.env.MAX_UPLOAD_MB || 50) * 1024 * 1024;
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const pkg = require('../package.json');
const { CATEGORIES } = require('./lib/categories');

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json', '.webmanifest': 'application/manifest+json', '.txt': 'text/plain; charset=utf-8', '.woff2': 'font/woff2' };

const APP_CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self'; worker-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'; upgrade-insecure-requests";
const REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

function securityHeaders(req, res, csp = APP_CSP) {
  res.setHeader('Content-Security-Policy', csp);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  if (req.socket.encrypted || (TRUST_PROXY && req.headers['x-forwarded-proto'] === 'https')) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}

// ---------- rate limiting ----------
function limiter(windowMs, max) {
  const hits = new Map();
  setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (v.reset <= now) hits.delete(k); }, windowMs).unref();
  return (ip) => {
    const now = Date.now();
    let e = hits.get(ip);
    if (!e || e.reset <= now) { e = { n: 0, reset: now + windowMs }; hits.set(ip, e); }
    e.n++;
    return { ok: e.n <= max, retry: Math.ceil((e.reset - now) / 1000) };
  };
}
const generalLimit = limiter(15 * 60 * 1000, Number(process.env.RATE_LIMIT_MAX || 600));
const scanLimit = limiter(60 * 60 * 1000, Number(process.env.SCAN_RATE_LIMIT || 20));

function clientIp(req) {
  if (TRUST_PROXY && req.headers['x-forwarded-for']) return String(req.headers['x-forwarded-for']).split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

// ---------- helpers ----------
function send(res, status, body, type = 'application/json; charset=utf-8', extra = {}) {
  const data = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', ...extra });
  res.end(data);
}
const json = (res, status, obj) => send(res, status, obj);
const fail = (res, status, message) => json(res, status, { error: message });

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const len = Number(req.headers['content-length'] || 0);
    if (len > limit) { const e = new Error('too large'); e.status = 413; return reject(e); }
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { const e = new Error('too large'); e.status = 413; req.destroy(); reject(e); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function readJSON(req) {
  if (!/^application\/json/.test(req.headers['content-type'] || '')) { const e = new Error('Expected JSON'); e.status = 415; throw e; }
  const buf = await readBody(req, 16 * 1024);
  try { return JSON.parse(buf.toString('utf8') || '{}'); } catch { const e = new Error('Invalid JSON'); e.status = 400; throw e; }
}

function scanOptions(src) {
  const mode = src.mode === 'app' ? 'app' : 'web';
  const flag = (v, d) => (v === undefined || v === null || v === '' ? d : v === true || v === 'true' || v === '1' || v === 'on');
  return { mode, autoFix: flag(src.autoFix, true), online: flag(src.online, true) };
}

// Same-origin check for state-changing requests (CSRF defence for our own API).
function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true; // non-browser clients (curl, CLI)
  try { return new URL(origin).host === req.headers.host; } catch { return false; }
}

function serveStatic(req, res, urlPath) {
  let rel = decodeURIComponent(urlPath);
  if (rel === '/' || rel === '') rel = '/index.html';
  if (rel.includes('\0')) return fail(res, 400, 'Bad path');
  const abs = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!abs.startsWith(PUBLIC_DIR + path.sep)) return fail(res, 403, 'Forbidden');
  fs.stat(abs, (err, st) => {
    if (err || !st.isFile()) {
      // SPA fallback for /app and /website sections
      if (/^\/(app|website|web|about|privacy)\/?$/.test(urlPath)) return serveStatic(req, res, '/index.html');
      return fail(res, 404, 'Not found');
    }
    const ext = path.extname(abs);
    const cache = ext === '.html' || abs.endsWith('sw.js') ? 'no-cache' : 'public, max-age=3600';
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream', 'Cache-Control': cache, 'Content-Length': st.size });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(abs).pipe(res);
  });
}

// ---------- routes ----------
async function handle(req, res) {
  const url = new URL(req.url, 'http://local');
  const p = url.pathname;
  const ip = clientIp(req);
  securityHeaders(req, res);

  const g = generalLimit(ip);
  if (!g.ok) { res.setHeader('Retry-After', String(g.retry)); return fail(res, 429, 'Too many requests. Please slow down.'); }

  if (!p.startsWith('/api/')) {
    if (req.method !== 'GET' && req.method !== 'HEAD') return fail(res, 405, 'Method not allowed');
    return serveStatic(req, res, p);
  }

  if (req.method === 'GET' && p === '/api/health') return json(res, 200, { ok: true, version: pkg.version });
  if (req.method === 'GET' && p === '/api/checks') return send(res, 200, JSON.stringify(CATEGORIES), 'application/json; charset=utf-8', { 'Cache-Control': 'public, max-age=3600' });

  if (req.method === 'POST' && (p === '/api/scan' || p === '/api/scan-github' || p === '/api/demo')) {
    if (!sameOrigin(req)) return fail(res, 403, 'Cross-site request blocked.');
    const s = scanLimit(ip);
    if (!s.ok) { res.setHeader('Retry-After', String(s.retry)); return fail(res, 429, `Scan limit reached. Try again in ${Math.ceil(s.retry / 60)} minutes.`); }

    if (p === '/api/scan') {
      const ct = req.headers['content-type'] || '';
      const bm = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(ct);
      if (!/^multipart\/form-data/i.test(ct) || !bm) return fail(res, 415, 'Upload a ZIP file as multipart/form-data.');
      const body = await readBody(req, MAX_UPLOAD + 64 * 1024);
      const parts = parseMultipart(body, bm[1] || bm[2]);
      const file = parts.find((x) => x.name === 'project' && x.filename);
      if (!file) return fail(res, 400, 'No file received. Choose a .zip of your project.');
      if (file.data.length > MAX_UPLOAD) return fail(res, 413, `ZIP is larger than ${MAX_UPLOAD / 1024 / 1024} MB. Remove node_modules and build folders.`);
      if (file.data.length < 22 || file.data.readUInt32LE(0) !== 0x04034b50) return fail(res, 400, 'That file is not a ZIP archive.');
      const fields = Object.fromEntries(parts.filter((x) => !x.filename).map((x) => [x.name, x.data.toString('utf8').slice(0, 20)]));
      const job = jobs.startUpload(file.data, { ...scanOptions(fields), filename: String(file.filename).replace(/[^\w.\- ]/g, '').slice(0, 80) });
      return json(res, 202, { id: job.id });
    }
    const body = await readJSON(req);
    if (p === '/api/scan-github') {
      const m = /^https:\/\/github\.com\/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9._-]{1,100}?)(?:\.git)?\/?$/.exec(String(body.url || '').trim());
      if (!m || m[2] === '.' || m[2] === '..') return fail(res, 400, 'Enter a public GitHub repository URL like https://github.com/owner/repo');
      const job = jobs.startGithub(m[1], m[2], scanOptions(body));
      return json(res, 202, { id: job.id });
    }
    const job = jobs.startDemo(scanOptions(body));
    return json(res, 202, { id: job.id });
  }

  const jm = /^\/api\/jobs\/([a-f0-9]{32})(?:\/(fixed\.zip|report\.html|report\.md|report\.json))?$/.exec(p);
  if (jm) {
    const job = jobs.get(jm[1]);
    if (!job) return fail(res, 404, 'Scan not found or expired. Results are deleted after 30 minutes.');
    if (req.method === 'DELETE' && !jm[2]) {
      if (!sameOrigin(req)) return fail(res, 403, 'Cross-site request blocked.');
      jobs.remove(job.id);
      return json(res, 200, { deleted: true });
    }
    if (req.method !== 'GET') return fail(res, 405, 'Method not allowed');
    if (!jm[2]) return json(res, 200, jobs.publicView(job));
    if (job.status !== 'done') return fail(res, 409, 'Scan is not finished yet.');
    const file = path.join(job.dir, jm[2]);
    if (!fs.existsSync(file)) return fail(res, 404, 'File not available.');
    const base = (job.result.meta.source || 'project').replace(/[^\w.-]+/g, '-').replace(/\.zip$/i, '').slice(0, 40);
    const names = { 'fixed.zip': `${base}-vibeguard-fixed.zip`, 'report.html': `${base}-security-report.html`, 'report.md': `${base}-security-report.md`, 'report.json': `${base}-security-report.json` };
    const types = { 'fixed.zip': 'application/zip', 'report.html': 'text/html; charset=utf-8', 'report.md': 'text/markdown; charset=utf-8', 'report.json': 'application/json; charset=utf-8' };
    const inline = url.searchParams.get('view') === '1' && jm[2] === 'report.html';
    if (jm[2] === 'report.html') res.setHeader('Content-Security-Policy', REPORT_CSP);
    return send(res, 200, fs.readFileSync(file), types[jm[2]], { 'Content-Disposition': `${inline ? 'inline' : 'attachment'}; filename="${names[jm[2]]}"` });
  }
  return fail(res, 404, 'Not found');
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((err) => {
    const status = err && err.status ? err.status : 500;
    if (status >= 500) console.error(err);
    if (!res.headersSent) fail(res, status, err && (err.userFacing || status < 500) ? (status === 413 ? 'Upload is too large.' : err.message) : 'Internal server error');
    else res.end();
  });
});
server.requestTimeout = 120000;
server.headersTimeout = 20000;
server.keepAliveTimeout = 5000;

if (require.main === module) {
  server.listen(PORT, HOST, () => console.log(`VibeGuard running on http://localhost:${PORT}`));
}

module.exports = { server };
