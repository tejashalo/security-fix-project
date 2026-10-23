'use strict';
const { Project } = require('./project');
const { detect } = require('./detect');
const { Context } = require('./context');
const { CATEGORIES, SEVERITY, SEVERITY_ORDER } = require('./categories');
const { unifiedDiff } = require('./diff');
const { redact } = require('./util');
const pkg = require('../../package.json');

const CHECKS = [
  require('../checks/secrets'),
  require('../checks/env'),
  require('../checks/gitHistory'),
  require('../checks/hardening'),
  require('../checks/routes'),
  require('../checks/cors'),
  require('../checks/credentials'),
  require('../checks/xss'),
  require('../checks/injection'),
  require('../checks/database'),
  require('../checks/debug'),
  require('../checks/exposed'),
  require('../checks/ai'),
  require('../checks/deploy'),
  require('../checks/mobile'),
  require('../checks/deps'),
];

// Each category contributes its worst issue plus a little for extra issues (capped),
// so one noisy category can't zero the score on its own.
function scoreFrom(findings) {
  const byCat = new Map();
  for (const f of findings) {
    const w = SEVERITY[f.severity] || 0;
    if (!w) continue;
    const c = byCat.get(f.category) || [];
    c.push(w);
    byCat.set(f.category, c);
  }
  let penalty = 0;
  for (const ws of byCat.values()) {
    ws.sort((a, b) => b - a);
    penalty += Math.min(40, ws[0] + ws.slice(1).reduce((s, w) => s + w * 0.3, 0));
  }
  return Math.max(0, Math.round(100 * Math.exp(-penalty / 200)));
}
function grade(score) { return score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 65 ? 'C' : score >= 45 ? 'D' : 'F'; }

function aiPrompt(f) {
  const where = f.file ? `In \`${f.file}\`${f.line ? ` (around line ${f.line})` : ''}` : 'In this project';
  return `${where}: ${f.title}. Why it matters: ${f.why} Please fix it: ${f.fix} Keep all other behaviour the same, explain what you changed, and do not hardcode any secrets.`;
}

/**
 * Scan (and optionally fix) a project folder.
 * @param {string} root  extracted project folder
 * @param {{mode?: 'web'|'app', autoFix?: boolean, online?: boolean}} opts
 * @param {(step: string, pct: number) => void} [onProgress]
 */
async function scanProject(root, opts = {}, onProgress = () => {}) {
  const started = Date.now();
  onProgress('Reading project files', 2);
  const project = Project.load(root);
  const det = detect(project);
  const ctx = new Context(project, det, opts);
  ctx.initialEnvIgnored = ctx.gitignoreCovers('.env');
  const initialGitignore = project.read('.gitignore') || '';
  ctx.initialIgnored = (file) => { const cur = project.read('.gitignore'); project._cache.set('.gitignore', initialGitignore); const r = ctx.gitignoreCovers(file); project._cache.set('.gitignore', cur); return r; };
  let i = 0;
  for (const check of CHECKS) {
    i++;
    onProgress(check.title, Math.round(5 + (i / CHECKS.length) * 85));
    if (opts.yieldEachStep) await new Promise((r) => setTimeout(r, 0)); // let the browser repaint progress
    try {
      await check.run(ctx, (msg) => onProgress(msg, Math.round(5 + (i / CHECKS.length) * 85)));
    } catch (err) {
      ctx.errors.push({ check: check.id, message: err && err.message });
      if (process.env.VIBEGUARD_DEBUG) console.error(err);
    }
  }
  onProgress('Writing report', 93);

  // Report-only mode: keep the "would fix" info but don't claim it was done.
  if (!ctx.opts.autoFix) {
    for (const f of ctx.findings) if (f.fixed) { f.fixed = false; f.fixable = true; f.proposed = f.diff; }
  }

  // ----- redact secrets everywhere in the output -----
  const secrets = [...ctx.secretValues].filter((s) => s && s.length >= 6).sort((a, b) => b.length - a.length);
  const scrub = (s) => {
    if (typeof s !== 'string' || !secrets.length) return s;
    for (const v of secrets) if (s.includes(v)) s = s.split(v).join(redact(v));
    return s;
  };
  const sevRank = (s) => SEVERITY_ORDER.indexOf(s);
  const findings = ctx.findings
    .map((f) => ({
      ...f,
      title: scrub(f.title), why: scrub(f.why), fix: scrub(f.fix), snippet: scrub(f.snippet),
      diff: f.diff ? { before: scrub(f.diff.before), after: scrub(f.diff.after) } : undefined,
      proposed: f.proposed ? { before: scrub(f.proposed.before), after: scrub(f.proposed.after) } : undefined,
    }))
    .map((f) => ({ ...f, aiPrompt: f.fixed ? null : aiPrompt(f) }))
    .sort((a, b) => (a.fixed - b.fixed) || (sevRank(a.severity) - sevRank(b.severity)));

  const open = findings.filter((f) => !f.fixed && f.severity !== 'info');
  const scoreBefore = scoreFrom(findings.filter((f) => f.severity !== 'info'));
  const scoreAfter = scoreFrom(open);

  const categories = CATEGORIES
    .filter((c) => !c.modes || c.modes.includes(ctx.opts.mode) || det.isApp)
    .map((c) => {
      const fs = findings.filter((f) => f.category === c.id);
      const real = fs.filter((f) => f.severity !== 'info');
      const st = ctx.status.get(c.id);
      const openN = real.filter((f) => !f.fixed).length;
      const fixedN = real.filter((f) => f.fixed).length;
      let status;
      if (openN) status = 'action';
      else if (fixedN) status = 'fixed';
      else if (c.id === 'deps' && ctx.depsOffline) status = 'skipped';
      else if (st && st.state === 'checked') status = 'passed';
      else if (fs.length) status = 'passed';
      else status = 'na';
      const worst = real.filter((f) => !f.fixed).map((f) => f.severity).sort((a, b) => sevRank(a) - sevRank(b))[0] || null;
      const note = status === 'skipped' ? 'Live vulnerability lookup was unavailable — run npm audit / pip-audit locally.' : st ? st.note || '' : 'Not applicable to this project.';
      return { id: c.id, title: c.title, requested: c.requested, blurb: c.blurb, status, note, total: fs.length, fixed: fixedN, open: openN, worst };
    });

  // ----- file changes -----
  const changes = [];
  const SECRET_FILE = /(^|\/)\.env(\.[\w-]+)?$|(^|\/)\.vibeguard\//;
  for (const file of project.changed) {
    const before = project.original.get(file);
    const after = project.read(file);
    if (before === after) continue;
    const created = project.created.has(file);
    const hidden = SECRET_FILE.test(file) && !/\.example$/.test(file);
    changes.push({
      file, type: created ? 'created' : 'modified',
      why: (ctx.generated.find((g) => g.file === file) || {}).why || '',
      diff: hidden ? `--- ${created ? '/dev/null' : 'a/' + file}\n+++ b/${file}\n@@ contents hidden: this file holds secrets @@\n` : scrub(unifiedDiff(before, after, file)),
    });
  }
  for (const m of project.moves) changes.push({ file: m.from, type: 'moved', to: m.to, why: 'Removed from a public folder', diff: '' });
  changes.sort((a, b) => a.file.localeCompare(b.file));

  if (ctx.opts.autoFix) project.flush();

  const bySeverity = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, open.filter((f) => f.severity === s).length]));
  return {
    tool: { name: 'VibeGuard', version: pkg.version },
    meta: {
      scannedAt: new Date().toISOString(),
      durationMs: Date.now() - started,
      mode: ctx.opts.mode,
      suggestedMode: det.suggestedMode,
      autoFix: !!ctx.opts.autoFix,
      online: ctx.opts.online !== false && !ctx.depsOffline,
      frameworks: [...det.frameworks],
      fileCount: project.files.length,
      hasGit: project.hasGit,
      gitCommits: ctx.gitInfo ? ctx.gitInfo.commits : null,
      errors: ctx.errors,
    },
    score: { before: scoreBefore, after: ctx.opts.autoFix ? scoreAfter : scoreBefore, potential: scoreAfter, gradeBefore: grade(scoreBefore), gradeAfter: grade(ctx.opts.autoFix ? scoreAfter : scoreBefore) },
    counts: { ignored: ctx.ignoredCount || 0, total: findings.length, fixed: findings.filter((f) => f.fixed).length, open: open.length, fixable: findings.filter((f) => f.fixable).length, bySeverity },
    categories,
    findings,
    changes: ctx.opts.autoFix ? changes : [],
    proposedChanges: ctx.opts.autoFix ? [] : changes,
    notes: ctx.notes.map(scrub),
    allPrompt: open.length ? `Please fix these security issues in my project, one by one. Don't change unrelated behaviour, don't hardcode secrets, and tell me what you changed:\n\n${open.slice(0, 40).map((f, n) => `${n + 1}. [${f.severity.toUpperCase()}] ${f.file ? f.file + (f.line ? ':' + f.line : '') + ' — ' : ''}${f.title}. Fix: ${f.fix}`).join('\n')}` : '',
  };
}

module.exports = { scanProject, CHECKS };
