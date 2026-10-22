'use strict';
const { escapeHtml: h } = require('./util');

const STATUS_LABEL = { fixed: 'Fixed', action: 'Needs you', passed: 'Passed', na: 'Not applicable', skipped: 'Skipped (offline)' };
const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };

function markdown(r) {
  const L = [];
  L.push(`# VibeGuard Security Report`);
  L.push('');
  L.push(`Scanned ${new Date(r.meta.scannedAt).toUTCString()} · ${r.meta.mode === 'app' ? 'App' : 'Website'} project · ${r.meta.fileCount} files · ${r.meta.frameworks.join(', ') || 'no framework detected'}`);
  L.push('');
  L.push(`**Security score:** ${r.score.before} (${r.score.gradeBefore}) → **${r.score.after} (${r.score.gradeAfter})**`);
  L.push('');
  L.push(`- Issues found: **${r.counts.total}**`);
  L.push(`- Fixed automatically: **${r.counts.fixed}**`);
  L.push(`- Still need your attention: **${r.counts.open}** (${Object.entries(r.counts.bySeverity).filter(([, n]) => n).map(([s, n]) => `${n} ${s}`).join(', ') || 'none'})`);
  L.push('');
  L.push('## What was checked');
  L.push('');
  L.push('| Check | Result | Details |');
  L.push('|---|---|---|');
  for (const c of r.categories) L.push(`| ${c.title}${c.requested ? '' : ' *(extra)*'} | ${STATUS_LABEL[c.status]} | ${c.status === 'na' || c.status === 'skipped' ? c.note : `${c.fixed} fixed, ${c.open} open`} |`);
  L.push('');
  const fixed = r.findings.filter((f) => f.fixed);
  if (fixed.length) {
    L.push('## ✅ What VibeGuard fixed');
    L.push('');
    for (const f of fixed) L.push(`- **${f.title}** — \`${f.file || 'project'}${f.line ? ':' + f.line : ''}\`. ${f.fixSummary || ''}`);
    L.push('');
  }
  const open = r.findings.filter((f) => !f.fixed);
  if (open.length) {
    L.push('## ⚠️ What you still need to do');
    L.push('');
    for (const f of open) {
      L.push(`### [${SEV_LABEL[f.severity]}] ${f.title}`);
      if (f.file) L.push(`\`${f.file}${f.line ? ':' + f.line : ''}\``);
      if (f.snippet) L.push('```\n' + f.snippet + '\n```');
      L.push(`**Why:** ${f.why}`);
      L.push('');
      L.push(`**Fix:** ${f.fix}`);
      L.push('');
    }
  }
  if (r.notes.length) {
    L.push('## Before you deploy');
    L.push('');
    for (const n of r.notes) L.push(`- ${n}`);
    L.push('');
  }
  if (r.changes.length) {
    L.push('## Files changed');
    L.push('');
    for (const c of r.changes) L.push(`- \`${c.file}\` — ${c.type}${c.to ? ` → \`${c.to}\`` : ''}${c.why ? ` (${c.why})` : ''}`);
    L.push('');
  }
  if (r.allPrompt) {
    L.push('## Prompt for your AI coding tool');
    L.push('');
    L.push('Paste this into Cursor, Lovable, Bolt, Replit, Claude or Copilot to fix the remaining issues:');
    L.push('');
    L.push('```text\n' + r.allPrompt + '\n```');
    L.push('');
  }
  L.push('---');
  L.push('VibeGuard catches common, known security mistakes. It is not a guarantee that an app cannot be hacked — get a professional review before handling payments or sensitive data at scale.');
  return L.join('\n') + '\n';
}

function html(r) {
  const sevColor = { critical: '#c62828', high: '#e65100', medium: '#b7791f', low: '#2b6cb0', info: '#4a5568' };
  const stColor = { fixed: '#2f855a', action: '#c05621', passed: '#2f855a', na: '#718096', skipped: '#718096' };
  const fRow = (f) => `
    <details class="f ${f.fixed ? 'done' : ''}" ${!f.fixed && /critical|high/.test(f.severity) ? 'open' : ''}>
      <summary><span class="sev" style="background:${sevColor[f.severity]}">${SEV_LABEL[f.severity]}</span> ${f.fixed ? '<span class="ok">FIXED</span> ' : ''}${h(f.title)} <span class="loc">${h(f.file || '')}${f.line ? ':' + f.line : ''}</span></summary>
      ${f.snippet ? `<pre>${h(f.snippet)}</pre>` : ''}
      <p><b>Why it matters:</b> ${h(f.why)}</p>
      <p><b>${f.fixed ? 'What VibeGuard did' : 'How to fix'}:</b> ${h(f.fixed ? f.fixSummary || f.fix : f.fix)}</p>
      ${f.diff ? `<div class="diff"><pre class="del">- ${h(f.diff.before)}</pre><pre class="add">+ ${h(f.diff.after)}</pre></div>` : ''}
      ${f.aiPrompt ? `<p class="small"><b>AI prompt:</b> ${h(f.aiPrompt)}</p>` : ''}
    </details>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VibeGuard Report</title>
<style>
:root{--bg:#f7f7f5;--card:#fff;--ink:#1a202c;--mute:#5a6472;--line:#e3e3df}
@media (prefers-color-scheme:dark){:root{--bg:#121417;--card:#1b1e23;--ink:#eceff3;--mute:#9aa4b2;--line:#2b3038}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:28px 16px 60px}h1{margin:0 0 4px;font-size:26px}h2{margin:34px 0 12px;font-size:19px}
.mute{color:var(--mute)}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;margin:12px 0}
.score{display:flex;gap:22px;flex-wrap:wrap;align-items:center}.big{font-size:44px;font-weight:800}.arrow{font-size:28px;color:var(--mute)}
table{width:100%;border-collapse:collapse;font-size:14px}td,th{padding:8px 6px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
.chip{display:inline-block;padding:2px 9px;border-radius:99px;color:#fff;font-size:12px;font-weight:600;white-space:nowrap}
.sev{display:inline-block;min-width:62px;text-align:center;padding:1px 7px;border-radius:6px;color:#fff;font-size:12px;font-weight:700}
.ok{color:#2f855a;font-weight:700;font-size:12px}.loc{color:var(--mute);font:12px ui-monospace,Menlo,monospace;margin-left:6px}
details.f{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px;margin:8px 0}details.f.done{opacity:.9}
summary{cursor:pointer;font-weight:600}pre{background:rgba(127,127,127,.12);padding:8px 10px;border-radius:8px;overflow:auto;font:12.5px/1.45 ui-monospace,Menlo,monospace;white-space:pre-wrap;word-break:break-word}
.diff pre{margin:4px 0}.del{background:rgba(229,62,62,.12)}.add{background:rgba(56,161,105,.14)}.small{font-size:13px;color:var(--mute)}
ul{padding-left:20px}footer{margin-top:40px;font-size:13px}
</style></head><body><div class="wrap">
<h1>VibeGuard Security Report</h1>
<div class="mute">${r.meta.mode === 'app' ? 'App' : 'Website'} project · ${r.meta.fileCount} files · ${h(r.meta.frameworks.join(', ') || 'no framework detected')} · ${h(new Date(r.meta.scannedAt).toUTCString())}</div>
<div class="card score">
  <div><div class="mute">Before</div><div class="big">${r.score.before}<small> ${r.score.gradeBefore}</small></div></div>
  <div class="arrow">→</div>
  <div><div class="mute">After</div><div class="big">${r.score.after}<small> ${r.score.gradeAfter}</small></div></div>
  <div style="margin-left:auto"><div><b>${r.counts.total}</b> issues found</div><div><b>${r.counts.fixed}</b> fixed automatically</div><div><b>${r.counts.open}</b> need your attention</div></div>
</div>
<h2>Everything that was checked</h2>
<div class="card"><table><tr><th>Check</th><th>Result</th><th>Details</th></tr>
${r.categories.map((c) => `<tr><td>${h(c.title)}${c.requested ? '' : ' <span class="mute">(extra)</span>'}</td><td><span class="chip" style="background:${stColor[c.status]}">${STATUS_LABEL[c.status]}</span></td><td class="mute">${c.status === 'na' || c.status === 'skipped' ? h(c.note) : `${c.fixed} fixed · ${c.open} open`}</td></tr>`).join('')}
</table></div>
${r.findings.some((f) => !f.fixed) ? `<h2>Needs your attention</h2>${r.findings.filter((f) => !f.fixed).map(fRow).join('')}` : ''}
${r.findings.some((f) => f.fixed) ? `<h2>Fixed by VibeGuard</h2>${r.findings.filter((f) => f.fixed).map(fRow).join('')}` : ''}
${r.notes.length ? `<h2>Before you deploy</h2><div class="card"><ul>${r.notes.map((n) => `<li>${h(n)}</li>`).join('')}</ul></div>` : ''}
${r.changes.length ? `<h2>Files changed</h2><div class="card"><ul>${r.changes.map((c) => `<li><code>${h(c.file)}</code> — ${c.type}${c.to ? ` → <code>${h(c.to)}</code>` : ''}</li>`).join('')}</ul></div>` : ''}
${r.allPrompt ? `<h2>Prompt for your AI coding tool</h2><pre>${h(r.allPrompt)}</pre>` : ''}
<footer class="mute">Generated by VibeGuard ${h(r.tool.version)}. VibeGuard catches common, known security mistakes; it is not a guarantee that an app cannot be hacked.</footer>
</div></body></html>`;
}

module.exports = { markdown, html };
