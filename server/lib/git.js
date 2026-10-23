'use strict';
/**
 * Safe git runner for UNTRUSTED repositories. Before any git command we:
 *  - overwrite .git/config (could define diff drivers, fsmonitor, pagers that run commands)
 *  - delete hooks, alternates and commondir (could point outside the sandbox)
 *  - pass --no-ext-diff/--no-textconv and isolate HOME / system config.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync, spawn } = require('child_process');

const SAFE_ENV_BASE = {
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_TERMINAL_PROMPT: '0',
  GIT_PAGER: 'cat',
  PAGER: 'cat',
  GIT_OPTIONAL_LOCKS: '0',
};

let isolatedHome = null;
function safeEnv() {
  if (!isolatedHome) isolatedHome = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-githome-'));
  const env = { PATH: process.env.PATH, HOME: isolatedHome, XDG_CONFIG_HOME: isolatedHome, ...SAFE_ENV_BASE };
  for (const k of ['HTTPS_PROXY', 'https_proxy', 'NO_PROXY', 'no_proxy', 'SSL_CERT_FILE', 'GIT_SSL_CAINFO']) if (process.env[k]) env[k] = process.env[k];
  return env;
}

const sanitized = new Set();
function sanitizeRepo(root) {
  const gd = path.join(root, '.git');
  try {
    if (!fs.statSync(gd).isDirectory() || !fs.existsSync(path.join(gd, 'HEAD'))) return false;
  } catch { return false; }
  if (sanitized.has(gd)) return true;
  fs.writeFileSync(path.join(gd, 'config'), '[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n');
  for (const rel of ['hooks', 'objects/info/alternates', 'objects/info/http-alternates', 'commondir', 'info/attributes']) {
    fs.rmSync(path.join(gd, rel), { recursive: true, force: true });
  }
  sanitized.add(gd);
  return true;
}

const BASE_ARGS = ['-c', 'safe.directory=*', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-c', 'core.quotepath=off', '--no-pager'];

function run(root, args, { timeout = 60000, maxBuffer = 64 * 1024 * 1024 } = {}) {
  if (!sanitizeRepo(root)) return { ok: false, out: '' };
  const r = spawnSync('git', [...BASE_ARGS, ...args], { cwd: root, env: safeEnv(), timeout, maxBuffer, encoding: 'utf8' });
  return { ok: r.status === 0, out: r.stdout || '', err: r.stderr || '' };
}

let gitAvailable = null;
/** True when a working `git` binary exists (false in the browser build or without git installed). */
function available() {
  if (gitAvailable === null) {
    try { gitAvailable = spawnSync('git', ['--version'], { env: safeEnv(), timeout: 10000 }).status === 0; } catch { gitAvailable = false; }
  }
  return gitAvailable;
}

function trackedFiles(root) {
  const r = run(root, ['ls-files', '-z']);
  return r.ok ? r.out.split('\0').filter(Boolean) : [];
}

function everCommittedFiles(root) {
  const r = run(root, ['log', '--all', '--name-only', '--diff-filter=A', '--format=']);
  return r.ok ? [...new Set(r.out.split('\n').map((s) => s.trim()).filter(Boolean))] : [];
}

/** Streams `git log -p` and yields added lines with commit info. */
function historyAddedLines(root, { maxCommits = 1000 } = {}) {
  const r = run(root, ['log', '--all', '-p', '--no-ext-diff', '--no-textconv', '--no-color', '-U0', `--max-count=${maxCommits}`, '--format=__VG__%H%x09%ad%x09%s', '--date=short'], { timeout: 90000, maxBuffer: 200 * 1024 * 1024 });
  if (!r.ok && !r.out) return [];
  const out = [];
  let commit = null, file = null;
  for (const line of r.out.split('\n')) {
    if (line.startsWith('__VG__')) {
      const [hash, date, ...msg] = line.slice(6).split('\t');
      commit = { hash, date, message: msg.join('\t') };
      continue;
    }
    if (line.startsWith('+++ ')) { file = line.slice(4).replace(/^b\//, ''); continue; }
    if (line.startsWith('+') && !line.startsWith('+++') && commit && file && line.length < 5000) out.push({ commit, file, text: line.slice(1) });
  }
  return out;
}

function commitCount(root) {
  const r = run(root, ['rev-list', '--all', '--count']);
  return r.ok ? parseInt(r.out.trim(), 10) || 0 : 0;
}

/** Clone a PUBLIC GitHub repo (owner/repo validated by caller). */
function cloneGithub(owner, repo, dest, { timeout = 120000 } = {}) {
  return new Promise((resolve, reject) => {
    const url = `https://github.com/${owner}/${repo}.git`;
    const child = spawn('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'protocol.file.allow=never', '-c', 'protocol.ext.allow=never', 'clone', '--quiet', '--no-recurse-submodules', '--single-branch', url, dest], { env: safeEnv(), stdio: ['ignore', 'ignore', 'pipe'] });
    let err = '';
    child.stderr.on('data', (d) => { err += d; if (err.length > 4000) err = err.slice(-4000); });
    const t = setTimeout(() => { child.kill('SIGKILL'); reject(Object.assign(new Error('Cloning took too long (repository too large?).'), { userFacing: true })); }, timeout);
    child.on('close', (code) => {
      clearTimeout(t);
      if (code === 0) resolve();
      else reject(Object.assign(new Error(/not found|could not read Username/i.test(err) ? 'Repository not found or not public.' : 'Could not clone that repository.'), { userFacing: true }));
    });
  });
}

module.exports = { available, run, trackedFiles, everCommittedFiles, historyAddedLines, commitCount, cloneGithub, sanitizeRepo };
