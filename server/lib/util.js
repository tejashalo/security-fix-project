'use strict';
const crypto = require('crypto');
const path = require('path');

const posix = path.posix;

function lineIndexer(content) {
  const starts = [0];
  for (let i = 0; i < content.length; i++) if (content.charCodeAt(i) === 10) starts.push(i + 1);
  return (idx) => {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= idx) lo = mid; else hi = mid - 1;
    }
    return lo + 1;
  };
}

function lineText(content, index) {
  const s = content.lastIndexOf('\n', index - 1) + 1;
  let e = content.indexOf('\n', index);
  if (e === -1) e = content.length;
  return content.slice(s, e);
}

function clip(s, max = 180) {
  s = String(s || '').replace(/\t/g, '  ').trim();
  return s.length > max ? s.slice(0, max) + '…' : s;
}

function shannon(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let e = 0;
  for (const k in freq) { const p = freq[k] / str.length; e -= p * Math.log2(p); }
  return e;
}

const PLACEHOLDER_RE = /^(?:your|my|xx+|\*+|\.{3}|changeme|change[_-]?me|replace|placeholder|example|sample|dummy|fake|todo|tbd|none|null|undefined|insert|enter|put|redacted|<.*>|\[.*\]|\{\{.*\}\}|\$\{.*\}|%\w+%|process\.env|os\.environ|import\.meta|env\(|test(?:ing)?$|password$|secret$|pass$|admin$|root$|user$)/i;
function isPlaceholder(v) {
  if (!v) return true;
  const s = String(v).trim();
  if (s.length < 6) return true;
  if (PLACEHOLDER_RE.test(s)) return true;
  if (/your[_-]|_here\b|-here\b|xxxx|0000000|1234567|abcdef(?:gh)?$|lorem|foo|bar\b|example\.com/i.test(s)) return true;
  if (/^\$\w+$|^\$\{|^%\(|^\{\w+\}$/.test(s)) return true;
  return false;
}

function redact(secret) {
  const s = String(secret);
  if (s.length <= 10) return '•'.repeat(6);
  return `${s.slice(0, 4)}…${s.slice(-2)}`;
}

function envName(raw) {
  let s = String(raw || '').replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/[^A-Za-z0-9]+/g, '_').replace(/^_+|_+$/g, '').toUpperCase();
  if (!s) s = 'SECRET';
  if (/^\d/.test(s)) s = '_' + s;
  return s;
}

function randomSecret(bytes = 32) { return crypto.randomBytes(bytes).toString('hex'); }

function relImport(fromFile, toFile, { keepExt = false } = {}) {
  let rel = posix.relative(posix.dirname(fromFile), toFile);
  if (!keepExt) rel = rel.replace(/\.(js|ts|mjs|cjs)$/, '');
  if (!rel.startsWith('.')) rel = './' + rel;
  return rel;
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function escapeRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

/** Find index of the closing paren matching the "(" at openIdx. Skips strings roughly. */
function matchParen(content, openIdx) {
  let depth = 0, q = null;
  for (let i = openIdx; i < content.length && i < openIdx + 20000; i++) {
    const c = content[i];
    if (q) { if (c === '\\') { i++; continue; } if (c === q) q = null; continue; }
    if (c === '"' || c === "'" || c === '`') { q = c; continue; }
    if (c === '(') depth++;
    else if (c === ')') { depth--; if (depth === 0) return i; }
  }
  return -1;
}

/** Split a call's argument text on top-level commas. */
function splitArgs(text) {
  const out = [];
  let depth = 0, q = null, cur = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (q) { cur += ch; if (ch === '\\') { cur += text[++i] || ''; continue; } if (ch === q) q = null; continue; }
    if (ch === '"' || ch === "'" || ch === '`') { q = ch; cur += ch; continue; }
    if ('([{'.includes(ch)) depth++;
    if (')]}'.includes(ch)) depth--;
    if (ch === ',' && depth === 0) { out.push(cur); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

function levenshtein(a, b) {
  if (Math.abs(a.length - b.length) > 2) return 3;
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + 1);
    }
  }
  return dp[a.length][b.length];
}

async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) { const k = i++; try { out[k] = await fn(items[k], k); } catch (e) { out[k] = { error: e }; } }
  });
  await Promise.all(workers);
  return out;
}

async function fetchJSON(url, { timeout = 8000, method = 'GET', body, headers = {} } = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(url, { method, body, headers: { 'user-agent': 'vibeguard-scanner', ...headers }, signal: ctrl.signal });
    if (res.status === 404) return { status: 404, data: null };
    if (!res.ok) return { status: res.status, data: null };
    return { status: res.status, data: await res.json() };
  } finally { clearTimeout(t); }
}

module.exports = { lineIndexer, lineText, clip, shannon, isPlaceholder, redact, envName, randomSecret, relImport, escapeHtml, escapeRe, matchParen, splitArgs, levenshtein, mapLimit, fetchJSON, posix };
