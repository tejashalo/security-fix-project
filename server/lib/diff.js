'use strict';
/** Minimal unified diff (LCS-based) for showing what VibeGuard changed. */

function lcsTable(a, b) {
  const n = a.length, m = b.length;
  const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  return dp;
}

function unifiedDiff(oldText, newText, file, context = 3) {
  const a = (oldText ?? '').split('\n');
  const b = (newText ?? '').split('\n');
  // trim common prefix/suffix to keep the table small
  let pre = 0;
  while (pre < a.length && pre < b.length && a[pre] === b[pre]) pre++;
  let suf = 0;
  while (suf < a.length - pre && suf < b.length - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++;
  const A = a.slice(pre, a.length - suf), B = b.slice(pre, b.length - suf);
  if (A.length * B.length > 4e6) return `--- a/${file}\n+++ b/${file}\n@@ (file too large to diff inline) @@\n`;
  const dp = lcsTable(A, B);
  const ops = [];
  let i = 0, j = 0;
  while (i < A.length || j < B.length) {
    if (i < A.length && j < B.length && A[i] === B[j]) { ops.push([' ', A[i]]); i++; j++; }
    else if (j < B.length && (i >= A.length || dp[i][j + 1] > dp[i + 1][j])) { ops.push(['+', B[j]]); j++; }
    else { ops.push(['-', A[i]]); i++; }
  }
  const full = [...a.slice(0, pre).map((l) => [' ', l]), ...ops, ...a.slice(a.length - suf).map((l) => [' ', l])];
  // build hunks
  const out = [`--- ${oldText == null ? '/dev/null' : 'a/' + file}`, `+++ b/${file}`];
  let k = 0, oldLn = 1, newLn = 1;
  const lineNums = full.map((op) => { const r = [oldLn, newLn]; if (op[0] !== '+') oldLn++; if (op[0] !== '-') newLn++; return r; });
  while (k < full.length) {
    if (full[k][0] === ' ') { k++; continue; }
    let start = Math.max(0, k - context);
    let end = k;
    while (end < full.length) {
      if (full[end][0] !== ' ') { end++; continue; }
      let run = 0;
      while (end + run < full.length && full[end + run][0] === ' ') run++;
      if (end + run >= full.length || run > context * 2) { end = Math.min(full.length, end + context); break; }
      end += run;
    }
    const hunk = full.slice(start, end);
    const oS = lineNums[start][0], nS = lineNums[start][1];
    const oC = hunk.filter((h) => h[0] !== '+').length, nC = hunk.filter((h) => h[0] !== '-').length;
    out.push(`@@ -${oldText == null ? 0 : oS},${oC} +${nS},${nC} @@`);
    for (const [op, l] of hunk) out.push(op + l);
    k = end;
  }
  return out.join('\n') + '\n';
}

module.exports = { unifiedDiff };
