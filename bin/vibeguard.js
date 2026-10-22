#!/usr/bin/env node
'use strict';
/**
 * VibeGuard CLI
 *   vibeguard scan [path|project.zip] [options]
 *
 * Never touches your original files unless you pass --in-place.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { scanProject } = require('../server/lib/scanner');
const { safeExtract } = require('../server/lib/zip');
const report = require('../server/lib/report');

const HELP = `VibeGuard — find and fix security holes in vibe-coded projects

Usage:
  vibeguard scan [path|project.zip] [options]

Options:
  --mode web|app       Project type (default: auto-detect)
  --out <dir>          Where to write the fixed copy (default: <project>-vibeguard-fixed)
  --in-place           Apply fixes directly to your project files
  --no-fix             Report only, change nothing
  --offline            Skip npm/PyPI lookups
  --report <file>      Also write a report (.html, .md or .json)
  --json               Print the full result as JSON
  --ci                 Exit with code 1 if open issues at --fail-on level or worse remain
  --fail-on <level>    critical | high | medium | low (default: high)
  -h, --help           Show this help
`;

function parseArgs(argv) {
  const a = { _: [], fix: true, online: true, failOn: 'high' };
  for (let i = 0; i < argv.length; i++) {
    const x = argv[i];
    if (x === '-h' || x === '--help') a.help = true;
    else if (x === '--mode') a.mode = argv[++i];
    else if (x === '--out') a.out = argv[++i];
    else if (x === '--in-place') a.inPlace = true;
    else if (x === '--no-fix') a.fix = false;
    else if (x === '--offline') a.online = false;
    else if (x === '--report') a.report = argv[++i];
    else if (x === '--json') a.json = true;
    else if (x === '--ci') a.ci = true;
    else if (x === '--fail-on') a.failOn = argv[++i];
    else a._.push(x);
  }
  return a;
}

function copyDir(src, dst) {
  fs.mkdirSync(dst, { recursive: true });
  for (const ent of fs.readdirSync(src, { withFileTypes: true })) {
    if (ent.name === 'node_modules') continue;
    const s = path.join(src, ent.name), d = path.join(dst, ent.name);
    if (ent.isSymbolicLink()) continue;
    if (ent.isDirectory()) copyDir(s, d);
    else if (ent.isFile()) fs.copyFileSync(s, d);
  }
}

const C = process.stdout.isTTY ? { r: '\x1b[31m', y: '\x1b[33m', g: '\x1b[32m', b: '\x1b[1m', d: '\x1b[2m', x: '\x1b[0m' } : { r: '', y: '', g: '', b: '', d: '', x: '' };
const SEV_C = { critical: C.r, high: C.r, medium: C.y, low: C.d, info: C.d };

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || args._[0] !== 'scan') { process.stdout.write(HELP); process.exit(args.help ? 0 : 1); }
  const target = path.resolve(args._[1] || '.');
  if (!fs.existsSync(target)) { console.error(`Not found: ${target}`); process.exit(1); }

  // Always scan a copy: the git sanitizer rewrites .git/config, which must never touch your real repo.
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'vibeguard-cli-'));
  let root = path.join(work, 'src');
  if (fs.statSync(target).isFile()) {
    if (!/\.zip$/i.test(target)) { console.error('Pass a folder or a .zip file.'); process.exit(1); }
    fs.mkdirSync(root);
    root = safeExtract(fs.readFileSync(target), root).root;
  } else copyDir(target, root);

  const mode = args.mode === 'app' || args.mode === 'web' ? args.mode : undefined;
  let lastStep = '';
  const result = await scanProject(root, { mode: mode || 'web', autoFix: args.fix, online: args.online }, (step) => {
    if (process.stderr.isTTY && step !== lastStep) { lastStep = step; process.stderr.write(`\r\x1b[K${C.d}${step}…${C.x}`); }
  });
  if (!mode && result.meta.suggestedMode === 'app') {
    // re-run in app mode on a fresh copy so mobile checks are included
    fs.rmSync(work, { recursive: true, force: true });
    process.argv.push('--mode', 'app');
    return main();
  }
  if (process.stderr.isTTY) process.stderr.write('\r\x1b[K');

  // Write outputs
  let outDir = null;
  if (args.fix) {
    if (args.inPlace && fs.statSync(target).isDirectory()) {
      for (const c of result.changes) {
        if (c.type === 'moved') {
          fs.mkdirSync(path.dirname(path.join(target, c.to)), { recursive: true });
          fs.renameSync(path.join(target, c.file), path.join(target, c.to));
        } else {
          fs.mkdirSync(path.dirname(path.join(target, c.file)), { recursive: true });
          fs.copyFileSync(path.join(root, c.file), path.join(target, c.file));
        }
      }
      outDir = target;
    } else {
      outDir = path.resolve(args.out || `${target.replace(/\.zip$/i, '')}-vibeguard-fixed`);
      if (fs.existsSync(outDir) && fs.readdirSync(outDir).length) { console.error(`Output folder ${outDir} is not empty. Use --out to choose another.`); process.exit(1); }
      fs.rmSync(path.join(root, '.git'), { recursive: true, force: true });
      copyDir(root, outDir);
    }
    fs.writeFileSync(path.join(outDir, 'VIBEGUARD_REPORT.md'), report.markdown(result));
  }
  if (args.report) {
    const ext = path.extname(args.report).toLowerCase();
    fs.writeFileSync(args.report, ext === '.json' ? JSON.stringify(result, null, 2) : ext === '.md' ? report.markdown(result) : report.html(result));
  }
  fs.rmSync(work, { recursive: true, force: true });

  if (args.json) { process.stdout.write(JSON.stringify(result, null, 2) + '\n'); }
  else {
    console.log(`\n${C.b}VibeGuard${C.x} — ${result.meta.mode === 'app' ? 'app' : 'website'} scan of ${result.meta.fileCount} files (${result.meta.frameworks.join(', ') || 'no framework detected'})`);
    console.log(`Score ${result.score.before} (${result.score.gradeBefore}) → ${C.b}${result.score.after} (${result.score.gradeAfter})${C.x}   ${result.counts.total} issues · ${C.g}${result.counts.fixed} fixed${C.x} · ${result.counts.open} need you\n`);
    for (const f of result.findings.filter((x) => !x.fixed && x.severity !== 'info')) {
      console.log(`  ${SEV_C[f.severity]}${f.severity.toUpperCase().padEnd(8)}${C.x} ${f.title} ${C.d}${f.file ? f.file + (f.line ? ':' + f.line : '') : ''}${C.x}`);
    }
    if (result.counts.fixed) {
      console.log(`\n${C.g}Fixed:${C.x}`);
      for (const f of result.findings.filter((x) => x.fixed)) console.log(`  ${C.g}✔${C.x} ${f.title} ${C.d}${f.file || ''}${C.x}`);
    }
    if (outDir) console.log(`\n${args.inPlace ? 'Fixes applied to' : 'Fixed copy written to'} ${outDir} (see VIBEGUARD_REPORT.md)`);
    if (args.report) console.log(`Report written to ${path.resolve(args.report)}`);
  }
  if (args.ci) {
    const order = ['critical', 'high', 'medium', 'low'];
    const limit = order.indexOf(args.failOn) === -1 ? 1 : order.indexOf(args.failOn);
    const bad = result.findings.filter((f) => (!f.fixed || !args.inPlace) && order.indexOf(f.severity) !== -1 && order.indexOf(f.severity) <= limit);
    if (bad.length) { console.error(`\n${bad.length} open issue(s) at "${args.failOn}" or worse.`); process.exit(1); }
  }
}

main().catch((err) => { console.error(err && err.message ? err.message : err); process.exit(1); });
