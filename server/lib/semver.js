'use strict';
/** Small, dependency-free subset of semver: parse, compare, satisfies, maxSatisfying, minVersion. */

const VER_RE = /^\s*v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?\s*$/;

function parse(v) {
  if (typeof v !== 'string') return null;
  const m = VER_RE.exec(v);
  if (!m) return null;
  return { major: +m[1], minor: +m[2], patch: +m[3], pre: m[4] ? m[4].split('.') : [], raw: v.trim().replace(/^v/, '') };
}

function cmpPre(a, b) {
  if (!a.length && !b.length) return 0;
  if (!a.length) return 1;
  if (!b.length) return -1;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (a[i] === undefined) return -1;
    if (b[i] === undefined) return 1;
    const an = /^\d+$/.test(a[i]), bn = /^\d+$/.test(b[i]);
    if (an && bn) { const d = +a[i] - +b[i]; if (d) return d > 0 ? 1 : -1; }
    else if (an) return -1;
    else if (bn) return 1;
    else if (a[i] !== b[i]) return a[i] > b[i] ? 1 : -1;
  }
  return 0;
}

function compare(a, b) {
  const A = typeof a === 'string' ? parse(a) : a;
  const B = typeof b === 'string' ? parse(b) : b;
  if (!A || !B) return 0;
  for (const k of ['major', 'minor', 'patch']) if (A[k] !== B[k]) return A[k] > B[k] ? 1 : -1;
  return cmpPre(A.pre, B.pre);
}

// Partial version like "1", "1.2", "1.x", "*"
function parsePartial(s) {
  s = s.trim().replace(/^v/, '').replace(/^=/, '');
  if (s === '' || s === '*' || /^[xX]$/.test(s)) return { major: null };
  const m = /^(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$/.exec(s);
  if (!m) return undefined;
  const n = (x) => (x === undefined || /^[xX*]$/.test(x) ? null : +x);
  return { major: n(m[1]), minor: n(m[2]), patch: n(m[3]), pre: m[4] ? m[4].split('.') : [] };
}

const V = (a, b, c, pre = []) => ({ major: a, minor: b, patch: c, pre });

// Returns array of comparator sets; each comparator: { op, v }
function parseRange(range) {
  if (range == null) return null;
  range = String(range).trim();
  if (range === '' || range === '*' || range === 'latest' || range === 'x') return [[]];
  const sets = [];
  for (let part of range.split('||')) {
    part = part.trim();
    const comps = [];
    const hy = /^(\S+)\s+-\s+(\S+)$/.exec(part);
    if (hy) {
      const lo = parsePartial(hy[1]), hi = parsePartial(hy[2]);
      if (!lo || !hi) return null;
      comps.push({ op: '>=', v: V(lo.major || 0, lo.minor || 0, lo.patch || 0, lo.pre || []) });
      if (hi.major !== null) {
        if (hi.minor === null) comps.push({ op: '<', v: V(hi.major + 1, 0, 0) });
        else if (hi.patch === null) comps.push({ op: '<', v: V(hi.major, hi.minor + 1, 0) });
        else comps.push({ op: '<=', v: V(hi.major, hi.minor, hi.patch, hi.pre) });
      }
      sets.push(comps);
      continue;
    }
    const tokens = part.replace(/(>=|<=|>|<|=|\^|~>?)\s+/g, '$1').split(/\s+/).filter(Boolean);
    for (const tok of tokens) {
      const m = /^(>=|<=|>|<|=|\^|~>?)?(.*)$/.exec(tok);
      const op = m[1] || '';
      const p = parsePartial(m[2]);
      if (p === undefined) return null;
      if (p.major === null) { if (op === '<' || op === '>') comps.push({ op: '<', v: V(0, 0, 0) }); continue; }
      const maj = p.major, min = p.minor, pat = p.patch;
      const full = V(maj, min || 0, pat || 0, p.pre || []);
      if (op === '^') {
        comps.push({ op: '>=', v: full });
        if (maj > 0 || min === null) comps.push({ op: '<', v: V(maj + 1, 0, 0) });
        else if (min > 0 || pat === null) comps.push({ op: '<', v: V(0, min + 1, 0) });
        else comps.push({ op: '<', v: V(0, 0, pat + 1) });
      } else if (op === '~' || op === '~>') {
        comps.push({ op: '>=', v: full });
        if (min === null) comps.push({ op: '<', v: V(maj + 1, 0, 0) });
        else comps.push({ op: '<', v: V(maj, min + 1, 0) });
      } else if (op === '' || op === '=') {
        if (min === null) { comps.push({ op: '>=', v: V(maj, 0, 0) }, { op: '<', v: V(maj + 1, 0, 0) }); }
        else if (pat === null) { comps.push({ op: '>=', v: V(maj, min, 0) }, { op: '<', v: V(maj, min + 1, 0) }); }
        else comps.push({ op: '=', v: full });
      } else if (op === '>') {
        if (min === null) comps.push({ op: '>=', v: V(maj + 1, 0, 0) });
        else if (pat === null) comps.push({ op: '>=', v: V(maj, min + 1, 0) });
        else comps.push({ op: '>', v: full });
      } else if (op === '<=') {
        if (min === null) comps.push({ op: '<', v: V(maj + 1, 0, 0) });
        else if (pat === null) comps.push({ op: '<', v: V(maj, min + 1, 0) });
        else comps.push({ op: '<=', v: full });
      } else {
        comps.push({ op, v: full });
      }
    }
    sets.push(comps);
  }
  return sets;
}

function testComp(v, c) {
  const d = compare(v, c.v);
  switch (c.op) {
    case '>=': return d >= 0;
    case '<=': return d <= 0;
    case '>': return d > 0;
    case '<': return d < 0;
    case '=': return d === 0;
    default: return false;
  }
}

function satisfies(version, range, { includePrerelease = false } = {}) {
  const v = typeof version === 'string' ? parse(version) : version;
  const sets = parseRange(range);
  if (!v || !sets) return false;
  return sets.some((comps) => {
    if (!comps.every((c) => testComp(v, c))) return false;
    if (v.pre.length && !includePrerelease) {
      // prerelease only matches if a comparator shares the same [major,minor,patch] and has a prerelease
      return comps.some((c) => c.v.pre.length && c.v.major === v.major && c.v.minor === v.minor && c.v.patch === v.patch);
    }
    return true;
  });
}

function validRange(range) { return parseRange(range) !== null; }

function maxSatisfying(versions, range) {
  let best = null;
  for (const s of versions) {
    if (!satisfies(s, range)) continue;
    if (!best || compare(s, best) > 0) best = s;
  }
  return best;
}

function minVersion(range) {
  const sets = parseRange(range);
  if (!sets) return null;
  let best = null;
  for (const comps of sets) {
    let lo = V(0, 0, 0);
    for (const c of comps) {
      if (c.op === '>=' || c.op === '=') { if (compare(c.v, lo) > 0) lo = c.v; }
      else if (c.op === '>') { const n = V(c.v.major, c.v.minor, c.v.patch + 1); if (compare(n, lo) > 0) lo = n; }
    }
    if (!best || compare(lo, best) < 0) best = lo;
  }
  if (!best) return null;
  return `${best.major}.${best.minor}.${best.patch}${best.pre && best.pre.length ? '-' + best.pre.join('.') : ''}`;
}

/** Keeps the user's range style (^, ~, exact) while pointing at a new version. */
function rewriteRange(oldRange, newVersion) {
  const m = /^\s*(\^|~|>=|=)?/.exec(oldRange || '');
  const prefix = m && m[1] ? (m[1] === '>=' ? '^' : m[1] === '=' ? '' : m[1]) : '';
  return prefix + newVersion;
}

module.exports = { parse, compare, satisfies, maxSatisfying, minVersion, validRange, rewriteRange };
