'use strict';
/**
 * In-memory job queue. Each scan gets an unguessable id, its own temp folder,
 * and is deleted automatically after JOB_TTL_MINUTES (default 30).
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { safeExtract, zipDirectory } = require('./lib/zip');
const { scanProject } = require('./lib/scanner');
const { buildDemo } = require('./lib/demo');
const git = require('./lib/git');
const report = require('./lib/report');

const TTL_MS = Number(process.env.JOB_TTL_MINUTES || 30) * 60 * 1000;
const MAX_CONCURRENT = Number(process.env.MAX_CONCURRENT_SCANS || 2);
const MAX_QUEUE = Number(process.env.MAX_QUEUED_SCANS || 20);
const BASE = path.join(process.env.VIBEGUARD_TMP || os.tmpdir(), 'vibeguard-jobs');
fs.mkdirSync(BASE, { recursive: true, mode: 0o700 });

const jobs = new Map();
const queue = [];
let running = 0;

function newJob(kind, options) {
  if (queue.length >= MAX_QUEUE) { const e = new Error('The scanner is busy. Please try again in a minute.'); e.status = 503; e.userFacing = true; throw e; }
  const id = crypto.randomBytes(16).toString('hex');
  const dir = path.join(BASE, id);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const job = { id, kind, dir, status: 'queued', progress: 0, step: 'Waiting in queue', createdAt: Date.now(), options, result: null, error: null };
  jobs.set(id, job);
  return job;
}

function enqueue(job, prepare) {
  queue.push({ job, prepare });
  pump();
}

function pump() {
  while (running < MAX_CONCURRENT && queue.length) {
    const { job, prepare } = queue.shift();
    running++;
    run(job, prepare).finally(() => { running--; pump(); });
  }
}

async function run(job, prepare) {
  job.status = 'running';
  try {
    const srcRoot = await prepare(job);
    const { mode, autoFix, online } = job.options;
    const result = await scanProject(srcRoot, { mode, autoFix, online }, (step, pct) => { job.step = step; job.progress = pct; });
    result.meta.source = job.kind === 'github' ? job.options.repo : job.kind === 'demo' ? 'demo project' : job.options.filename || 'upload.zip';
    job.progress = 96;
    job.step = 'Packaging your fixed project';
    const md = report.markdown(result);
    fs.writeFileSync(path.join(job.dir, 'report.md'), md);
    fs.writeFileSync(path.join(job.dir, 'report.html'), report.html(result));
    fs.writeFileSync(path.join(job.dir, 'report.json'), JSON.stringify(result, null, 2));
    if (autoFix) {
      fs.writeFileSync(path.join(srcRoot, 'VIBEGUARD_REPORT.md'), md);
      const zip = zipDirectory(srcRoot, { exclude: /(^|\/)(\.git|node_modules)(\/|$)/ });
      fs.writeFileSync(path.join(job.dir, 'fixed.zip'), zip);
      job.hasZip = true;
    }
    // Source files are no longer needed — delete them right away.
    fs.rmSync(path.join(job.dir, 'src'), { recursive: true, force: true });
    fs.rmSync(path.join(job.dir, 'upload.zip'), { force: true });
    job.result = result;
    job.status = 'done';
    job.progress = 100;
    job.step = 'Done';
  } catch (err) {
    job.status = 'error';
    job.error = err && err.userFacing ? err.message : 'Something went wrong while scanning this project.';
    if (!err || !err.userFacing) console.error(`[job ${job.id}]`, err);
    fs.rmSync(path.join(job.dir, 'src'), { recursive: true, force: true });
    fs.rmSync(path.join(job.dir, 'upload.zip'), { force: true });
  }
}

function startUpload(buffer, options) {
  const job = newJob('upload', options);
  enqueue(job, async (j) => {
    j.step = 'Unpacking ZIP safely';
    const src = path.join(j.dir, 'src');
    fs.mkdirSync(src);
    const { root, stats } = safeExtract(buffer, src);
    j.extractStats = stats;
    return root;
  });
  return job;
}

function startGithub(owner, repo, options) {
  const job = newJob('github', { ...options, repo: `${owner}/${repo}` });
  enqueue(job, async (j) => {
    j.step = `Cloning ${owner}/${repo}`;
    const src = path.join(j.dir, 'src');
    await git.cloneGithub(owner, repo, src);
    fs.rmSync(path.join(src, 'node_modules'), { recursive: true, force: true });
    return src;
  });
  return job;
}

function startDemo(options) {
  const job = newJob('demo', options);
  enqueue(job, async (j) => {
    j.step = 'Creating a deliberately vulnerable demo project';
    return buildDemo(path.join(j.dir, 'src'), options.mode);
  });
  return job;
}

function get(id) { return /^[a-f0-9]{32}$/.test(id) ? jobs.get(id) : undefined; }

function remove(id) {
  const job = get(id);
  if (!job) return false;
  fs.rmSync(job.dir, { recursive: true, force: true });
  jobs.delete(id);
  return true;
}

function publicView(job) {
  return {
    id: job.id, status: job.status, progress: job.progress, step: job.step, error: job.error,
    expiresAt: new Date(job.createdAt + TTL_MS).toISOString(),
    hasZip: !!job.hasZip, extractStats: job.extractStats || null,
    result: job.status === 'done' ? job.result : null,
  };
}

const sweeper = setInterval(() => {
  const now = Date.now();
  for (const job of jobs.values()) if (now - job.createdAt > TTL_MS && job.status !== 'running') remove(job.id);
  // remove orphaned folders from previous runs
  try {
    for (const name of fs.readdirSync(BASE)) {
      if (jobs.has(name)) continue;
      const p = path.join(BASE, name);
      const st = fs.statSync(p);
      if (now - st.mtimeMs > TTL_MS) fs.rmSync(p, { recursive: true, force: true });
    }
  } catch { /* ignore */ }
}, 60 * 1000);
sweeper.unref();

module.exports = { startUpload, startGithub, startDemo, get, remove, publicView, TTL_MS };
