/* Runs VibeGuard entirely in the browser: answers the page's /api/* calls
 * with the bundled engine, so no server is needed and code never leaves the device. */
(function () {
  'use strict';
  const E = window.VGEngine;
  const { fs, path } = window.VG_SHIMS;
  const jobs = new Map();
  const MAX_ZIP = 60 * 1024 * 1024;
  const MAX_FILE = 25 * 1024 * 1024;
  const MAX_TOTAL = 300 * 1024 * 1024;
  const MAX_ENTRIES = 20000;
  const SKIP = /(^|\/)(node_modules|__MACOSX|\.git|\.venv|venv|Pods|\.gradle|\.dart_tool|\.next\/cache)(\/|$)/;

  const userError = (msg) => Object.assign(new Error(msg), { userFacing: true });
  const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  const newId = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), (x) => x.toString(16).padStart(2, '0')).join('');

  async function inflateRaw(bytes, max, name) {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
    const reader = stream.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > max) { reader.cancel(); throw userError(`File "${name}" expands beyond the size limit (possible zip bomb).`); }
      chunks.push(value);
    }
    const out = Buffer.alloc(total);
    let o = 0;
    for (const c of chunks) { out.set(c, o); o += c.length; }
    return out;
  }

  /** Safe in-memory unzip: blocks zip-slip, symlinks, bombs; skips node_modules and .git. */
  async function extract(buf, dest, job) {
    const entries = E.listEntries(buf);
    if (entries.length > MAX_ENTRIES) throw userError(`ZIP has ${entries.length} entries; the limit is ${MAX_ENTRIES}. Remove node_modules/build folders and try again.`);
    let total = 0, count = 0, n = 0;
    for (const e of entries) {
      n++;
      if (n % 200 === 0) { job.step = `Unpacking ZIP (${n}/${entries.length})`; await new Promise((r) => setTimeout(r, 0)); }
      if (e.isDirectory || SKIP.test(e.name) || e.isSymlink || e.encrypted) continue;
      if (!e.name || e.name.includes('\0')) throw userError('ZIP contains an invalid file name.');
      const target = path.resolve(dest, e.name);
      if (!target.startsWith(dest + '/')) throw userError(`Blocked unsafe path in ZIP: "${e.name}" (zip-slip attempt).`);
      if (e.size > MAX_FILE) continue;
      const lo = e.localOffset;
      if (lo + 30 > buf.length || buf.readUInt32LE(lo) !== 0x04034b50) throw userError('Corrupted ZIP archive (bad local header).');
      const start = lo + 30 + buf.readUInt16LE(lo + 26) + buf.readUInt16LE(lo + 28);
      const raw = buf.subarray(start, start + e.compSize);
      let data;
      if (e.method === 0) data = Buffer.from(raw);
      else if (e.method === 8) data = await inflateRaw(raw, Math.min(MAX_FILE, MAX_TOTAL - total) + 1, e.name);
      else throw userError(`Unsupported compression in "${e.name}". Re-create the ZIP with standard settings.`);
      if (data.length > MAX_FILE) continue;
      total += data.length;
      if (total > MAX_TOTAL) throw userError('ZIP expands to more than the allowed total size.');
      fs.writeFileSync(target, data);
      count++;
    }
    if (!count) throw userError('The ZIP did not contain any project files.');
    let root = dest;
    for (let i = 0; i < 3; i++) {
      const items = fs.readdirSync(root).filter((x) => x !== '__MACOSX' && x !== '.DS_Store');
      if (items.length === 1 && fs.statSync(path.join(root, items[0])).isDirectory()) root = path.join(root, items[0]);
      else break;
    }
    return root;
  }

  async function run(job, prepare) {
    job.status = 'running';
    try {
      await new Promise((r) => setTimeout(r, 30));
      const root = await prepare(job);
      const { mode, autoFix } = job.options;
      const result = await E.scanProject(root, { mode, autoFix, online: false, yieldEachStep: true }, (step, pct) => { job.step = step; job.progress = pct; });
      result.meta.source = job.options.filename || 'demo project';
      job.step = 'Packaging your fixed project';
      job.files = {
        'report.md': E.report.markdown(result),
        'report.html': E.report.html(result),
        'report.json': JSON.stringify(result, null, 2),
      };
      if (autoFix) {
        fs.writeFileSync(path.join(root, 'VIBEGUARD_REPORT.md'), job.files['report.md']);
        job.files['fixed.zip'] = E.zipDirectory(root, { exclude: /(^|\/)(\.git|node_modules)(\/|$)/ });
        job.hasZip = true;
      }
      fs.rmSync(job.dir);
      job.result = result;
      job.status = 'done';
      job.progress = 100;
      job.step = 'Done';
    } catch (err) {
      fs.rmSync(job.dir);
      job.status = 'error';
      job.error = err && err.userFacing ? err.message : 'Something went wrong while scanning this project.';
      console.error(err);
    }
  }

  function start(options, prepare) {
    const id = newId();
    const job = { id, dir: `/jobs/${id}`, status: 'queued', progress: 1, step: 'Starting', options, result: null, error: null, createdAt: Date.now() };
    jobs.set(id, job);
    run(job, prepare);
    return id;
  }

  function view(job) {
    return { id: job.id, status: job.status, progress: job.progress, step: job.step, error: job.error, hasZip: !!job.hasZip, expiresAt: null, result: job.status === 'done' ? job.result : null };
  }

  const opts = (o) => ({ mode: o.mode === 'app' ? 'app' : 'web', autoFix: !(o.autoFix === false || o.autoFix === 'false') });

  async function handle(url, init) {
    const method = (init && init.method) || 'GET';
    const p = new URL(url, location.href).pathname.replace(/^.*?(\/api\/)/, '/api/');
    if (p === '/api/checks') return json(200, E.CATEGORIES);
    if (p === '/api/health') return json(200, { ok: true, local: true });
    if (p === '/api/demo' && method === 'POST') {
      const o = opts(JSON.parse((init && init.body) || '{}'));
      return json(202, { id: start(o, async (job) => { job.step = 'Creating a deliberately vulnerable demo project'; return E.buildDemo(`${job.dir}/src`, o.mode); }) });
    }
    if (p === '/api/scan' && method === 'POST') {
      const fd = init.body;
      const file = fd.get('project');
      if (!file || !file.size) return json(400, { error: 'No file received. Choose a .zip of your project.' });
      if (file.size > MAX_ZIP) return json(413, { error: `ZIP is larger than ${MAX_ZIP / 1024 / 1024} MB. Remove node_modules and build folders.` });
      const buf = Buffer.from(await file.arrayBuffer());
      if (buf.length < 22 || buf.readUInt32LE(0) !== 0x04034b50) return json(400, { error: 'That file is not a ZIP archive.' });
      const o = { ...opts({ mode: fd.get('mode'), autoFix: fd.get('autoFix') }), filename: String(file.name || 'upload.zip').slice(0, 80) };
      return json(202, { id: start(o, async (job) => { job.step = 'Unpacking ZIP safely'; return extract(buf, `${job.dir}/src`, job); }) });
    }
    if (p === '/api/scan-github') return json(400, { error: 'GitHub scanning needs the downloadable version of VibeGuard. Download the repo as a ZIP and upload it here instead.' });
    const m = /^\/api\/jobs\/([a-f0-9]{32})$/.exec(p);
    if (m) {
      const job = jobs.get(m[1]);
      if (!job) return json(404, { error: 'Scan not found. Results only live in this browser tab — run the scan again.' });
      if (method === 'DELETE') { jobs.delete(job.id); return json(200, { deleted: true }); }
      return json(200, view(job));
    }
    return json(404, { error: 'Not found' });
  }

  const realFetch = window.fetch ? window.fetch.bind(window) : null;
  window.fetch = function (input, init) {
    const url = typeof input === 'string' ? input : input && input.url;
    if (url && /(^|\/)api\//.test(url) && !/^https?:\/\//.test(url)) return handle(url, init);
    return realFetch(input, init);
  };

  const MIME = { 'fixed.zip': 'application/zip', 'report.html': 'text/html', 'report.md': 'text/markdown', 'report.json': 'application/json' };
  window.VG_LOCAL = {
    /** Offer a result file: through the viewer's save dialog inside claude.ai, or a normal download elsewhere. */
    async download(id, name) {
      const job = jobs.get(id);
      if (!job || !job.files || !job.files[name]) throw userError('This file is no longer available. Run the scan again.');
      const base = (job.result.meta.source || 'project').replace(/\.zip$/i, '').replace(/[^\w.-]+/g, '-').slice(0, 40);
      const names = { 'fixed.zip': `${base}-vibeguard-fixed.zip`, 'report.html': `${base}-security-report.html`, 'report.md': `${base}-security-report.md`, 'report.json': `${base}-security-report.json` };
      const blob = new Blob([job.files[name]], { type: MIME[name] });
      const downloads = window.claude && typeof window.claude.use === 'function' ? await window.claude.use('downloads').catch(() => null) : null;
      if (downloads) {
        try { await downloads.save({ filename: names[name], data: blob }); return 'saved'; }
        catch (e) { if (e && e.code === 'declined') return 'declined'; if (!/unavailable|not_granted|capability/.test(e && e.code || '')) throw userError(e.message || 'Could not save the file.'); }
      }
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = names[name];
      document.body.appendChild(a);
      a.click();
      setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 2000);
      return 'saved';
    },
  };
})();
