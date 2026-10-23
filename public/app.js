'use strict';
(() => {
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const store = {
    get(k) { try { return sessionStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { sessionStorage.setItem(k, v); } catch { /* storage unavailable */ } },
    del(k) { try { sessionStorage.removeItem(k); } catch { /* storage unavailable */ } },
  };

  const COPY = {
    web: {
      headline: 'Your vibe-coded website works. Now make sure it isn\'t wide open.',
      lede: 'Upload the project. VibeGuard checks {n} things AI tools usually get wrong — leaked keys, open admin pages, missing logins, XSS, CORS — fixes what it safely can, and hands you back the fixed code with a plain-English report.',
      button: 'Scan my website',
      sub: 'Website scans cover all of these.',
    },
    app: {
      headline: 'Your vibe-coded app runs. Now make sure nobody can unpack your keys.',
      lede: 'Upload your React Native, Expo, Flutter, Capacitor, Android or iOS project — plus its backend if you have one. VibeGuard checks {n} things, including keys inside the app bundle, insecure token storage, debuggable builds and cleartext traffic.',
      button: 'Scan my app',
      sub: 'App scans add mobile checks to the list.',
    },
  };
  const STATUS_TEXT = { fixed: 'Fixed', action: 'Needs you', passed: 'Passed', na: 'N/A', skipped: 'Skipped' };
  const SEV_TEXT = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };

  let mode = location.pathname.startsWith('/app') ? 'app' : 'web';
  let checks = [];
  let source = 'zip';
  let file = null;
  let jobId = null;
  let result = null;
  let filter = 'open';
  let pollTimer = null;

  // ---------- helpers ----------
  function toast(msg) {
    const t = document.createElement('div');
    t.className = 'toast';
    t.setAttribute('role', 'status');
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 2200);
  }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); toast('Copied to clipboard'); }
    catch {
      const ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); toast('Copied to clipboard'); } catch { toast('Copy failed — select the text manually'); }
      ta.remove();
    }
  }
  function show(id) {
    for (const s of ['start', 'progress', 'results']) $('#' + s).hidden = s !== id;
    $('#how').hidden = id !== 'start';
  }
  function visibleChecks() { return checks.filter((c) => !c.modes || c.modes.includes(mode)); }
  function formError(msg) { const e = $('#formError'); e.textContent = msg || ''; e.hidden = !msg; }

  // ---------- mode (Website / App sections) ----------
  function applyMode(m, push) {
    mode = m;
    const c = COPY[m];
    $$('.seg').forEach((a) => (a.dataset.mode === m ? a.setAttribute('aria-current', 'page') : a.removeAttribute('aria-current')));
    $('#headline').textContent = c.headline;
    $('#lede').textContent = c.lede.replace('{n}', visibleChecks().length || 30);
    $('#scanBtn').textContent = c.button;
    $('#tagSub').textContent = c.sub;
    document.title = `VibeGuard — security check for vibe-coded ${m === 'app' ? 'apps' : 'websites'}`;
    renderChecklist($('#checklist'));
    if (push) history.pushState({ mode: m }, '', m === 'app' ? '/app' : '/website');
  }
  $$('.seg').forEach((a) => a.addEventListener('click', (e) => {
    e.preventDefault();
    if (!$('#results').hidden || !$('#progress').hidden) { stopPolling(); show('start'); }
    applyMode(a.dataset.mode, true);
  }));
  window.addEventListener('popstate', () => applyMode(location.pathname.startsWith('/app') ? 'app' : 'web', false));

  function renderChecklist(ol, statuses) {
    ol.textContent = '';
    const list = statuses || visibleChecks().map((c) => ({ ...c, status: null }));
    for (const c of list) {
      const li = document.createElement('li');
      li.dataset.id = c.id;
      if (c.status) li.className = 's-' + c.status;
      const box = document.createElement('span'); box.className = 'box'; box.setAttribute('aria-hidden', 'true');
      const t = document.createElement('span'); t.textContent = c.title;
      if (!c.requested) { const x = document.createElement('span'); x.className = 'extra'; x.textContent = ' · extra'; t.appendChild(x); }
      const st = document.createElement('span'); st.className = 'st';
      if (c.status) {
        st.textContent = STATUS_TEXT[c.status] + (c.status === 'action' && c.open ? ` (${c.open})` : '');
        li.title = c.status === 'na' || c.status === 'skipped' ? c.note : `${c.fixed} fixed, ${c.open} open`;
      }
      li.append(box, t, st);
      ol.appendChild(li);
    }
  }

  // ---------- source tabs ----------
  function setSource(s) {
    source = s;
    $('#tabZip').setAttribute('aria-selected', String(s === 'zip'));
    $('#tabGit').setAttribute('aria-selected', String(s === 'git'));
    $('#srcZip').hidden = s !== 'zip';
    $('#srcGit').hidden = s !== 'git';
    formError('');
  }
  $('#tabZip').addEventListener('click', () => setSource('zip'));
  $('#tabGit').addEventListener('click', () => setSource('git'));

  // ---------- file picking ----------
  const drop = $('#drop');
  function pick(f) {
    if (!f) return;
    if (!/\.zip$/i.test(f.name)) { formError('Please choose a .zip file. On Mac: right-click the folder → Compress. On Windows: right-click → Send to → Compressed folder.'); return; }
    if (f.size > 50 * 1024 * 1024) { formError('That ZIP is over 50 MB. Delete node_modules, dist and build folders, then zip again.'); return; }
    file = f;
    formError('');
    drop.classList.add('has-file');
    $('#dropTitle').textContent = f.name;
    $('#dropHint').textContent = `${(f.size / 1024 / 1024).toFixed(1)} MB · click to choose a different file`;
  }
  $('#file').addEventListener('change', (e) => pick(e.target.files[0]));
  ['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', (e) => pick(e.dataTransfer.files[0]));

  // ---------- start scan ----------
  function options() { return { mode, autoFix: $('#optFix').checked, online: $('#optOnline').checked }; }

  async function start(kind) {
    formError('');
    let res;
    try {
      if (kind === 'demo') {
        res = await fetch('/api/demo', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(options()) });
      } else if (source === 'git') {
        const url = $('#repo').value.trim();
        if (!/^https:\/\/github\.com\/[^/]+\/[^/]+/.test(url)) { formError('Enter a public GitHub URL like https://github.com/you/your-project'); return; }
        res = await fetch('/api/scan-github', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url, ...options() }) });
      } else {
        if (!file) { formError('Choose your project ZIP first — or try the demo project.'); return; }
        const fd = new FormData();
        const o = options();
        fd.append('mode', o.mode); fd.append('autoFix', String(o.autoFix)); fd.append('online', String(o.online));
        fd.append('project', file);
        res = await fetch('/api/scan', { method: 'POST', body: fd });
      }
    } catch {
      formError('Could not reach the scanner. Check your connection and try again.');
      return;
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { formError(data.error || 'The scan could not start.'); return; }
    jobId = data.id;
    store.set('vg-job', jobId + ':' + mode);
    beginProgress();
  }
  $('#scanForm').addEventListener('submit', (e) => { e.preventDefault(); start('upload'); });
  $('#demoBtn').addEventListener('click', () => start('demo'));

  // ---------- progress ----------
  function beginProgress() {
    show('progress');
    $('#progressTitle').textContent = `Inspecting your ${mode === 'app' ? 'app' : 'website'}`;
    setProgress(2, 'Uploading…');
    poll();
  }
  function setProgress(pct, step) {
    $('#barFill').style.width = pct + '%';
    $('#bar').setAttribute('aria-valuenow', String(pct));
    if (step) $('#progressStep').textContent = step;
  }
  function stopPolling() { clearTimeout(pollTimer); pollTimer = null; }
  async function poll() {
    stopPolling();
    let data;
    try {
      const r = await fetch(`/api/jobs/${jobId}`, { cache: 'no-store' });
      data = await r.json();
      if (!r.ok) throw new Error(data.error || 'Scan not found.');
    } catch (err) {
      store.del('vg-job');
      show('start');
      formError(err.message || 'Lost connection to the scan.');
      return;
    }
    setProgress(data.progress, data.step);
    if (data.status === 'done') { result = data.result; renderResults(data); return; }
    if (data.status === 'error') { store.del('vg-job'); show('start'); formError(data.error); return; }
    pollTimer = setTimeout(poll, 700);
  }

  // ---------- results ----------
  function renderResults(job) {
    const r = job.result;
    if (r.meta.mode !== mode) applyMode(r.meta.mode, false);
    show('results');
    const sb = $('#scoreBefore'), sa = $('#scoreAfter');
    sb.className = `score grade-${r.score.gradeBefore}`;
    sa.className = `score after grade-${r.score.gradeAfter}`;
    $('.num', sb).textContent = r.score.before;
    $('.num', sa).textContent = r.score.after;
    $('.lbl', sa).textContent = r.meta.autoFix ? 'after fixes' : 'not fixed yet';

    const crit = r.counts.bySeverity.critical, high = r.counts.bySeverity.high;
    $('#verdictTitle').textContent = r.counts.total === 0
      ? 'No issues found in the checks VibeGuard runs.'
      : r.meta.autoFix
        ? `Found ${r.counts.total} issue${r.counts.total === 1 ? '' : 's'}. Fixed ${r.counts.fixed}.`
        : `Found ${r.counts.total} issue${r.counts.total === 1 ? '' : 's'}. ${r.counts.fixable} can be fixed automatically.`;
    $('#verdictSummary').textContent = r.counts.open
      ? `${r.counts.open} still need${r.counts.open === 1 ? 's' : ''} you${crit + high ? ` — ${crit ? crit + ' critical' : ''}${crit && high ? ' and ' : ''}${high ? high + ' high' : ''} first` : ''}. Each one says why it matters and how to fix it, with a prompt you can paste into your AI tool.`
      : 'Nothing left on the list. Rotate any keys VibeGuard found, then redeploy.';
    const metaBits = [`${r.meta.mode === 'app' ? 'App' : 'Website'} scan`, `${r.meta.fileCount} files`];
    if (r.meta.frameworks.length) metaBits.push(r.meta.frameworks.join(', '));
    if (r.meta.gitCommits) metaBits.push(`${r.meta.gitCommits} commits of history`);
    let meta = metaBits.join(' • ');
    if (r.meta.suggestedMode !== r.meta.mode) meta += r.meta.suggestedMode === 'app' ? ' — this looks like a mobile app; try the App section for mobile checks.' : ' — no mobile project files found; the Website section fits better.';
    $('#verdictMeta').textContent = meta;

    const base = `/api/jobs/${job.id}`;
    $('#dlZip').hidden = !job.hasZip;
    $('#dlZip').href = `${base}/fixed.zip`;
    $('#dlHtml').href = `${base}/report.html`;
    $('#dlMd').href = `${base}/report.md`;
    $('#dlJson').href = `${base}/report.json`;
    $('#copyAll').hidden = !r.allPrompt;

    renderChecklist($('#checklistResults'), r.categories);
    $('#cOpen').textContent = r.findings.filter((f) => !f.fixed).length;
    $('#cFixed').textContent = r.findings.filter((f) => f.fixed).length;
    $('#cAll').textContent = r.findings.length;
    setFilter(r.findings.some((f) => !f.fixed) ? 'open' : 'fixed');

    $('#notesBox').hidden = !r.notes.length;
    const nl = $('#notesList'); nl.textContent = '';
    for (const n of r.notes) { const li = document.createElement('li'); li.textContent = n; nl.appendChild(li); }

    const changes = r.changes.length ? r.changes : r.proposedChanges;
    $('#changesBox').hidden = !changes.length;
    $('#changesBox summary').firstChild.textContent = r.changes.length ? 'Files VibeGuard changed (' : 'Changes VibeGuard would make (';
    $('#changesCount').textContent = changes.length;
    const cl = $('#changesList'); cl.textContent = '';
    for (const c of changes) {
      const h = document.createElement('div'); h.className = 'change-file';
      h.textContent = c.file + ' ';
      const sm = document.createElement('small'); sm.textContent = c.type + (c.to ? ` → ${c.to}` : '') + (c.why ? ` — ${c.why}` : '');
      h.appendChild(sm); cl.appendChild(h);
      if (c.diff) {
        const pre = document.createElement('pre'); pre.className = 'diff';
        for (const line of c.diff.split('\n').slice(0, 400)) {
          const span = document.createElement('span');
          span.className = line.startsWith('+') && !line.startsWith('+++') ? 'a' : line.startsWith('-') && !line.startsWith('---') ? 'd' : line.startsWith('@@') ? 'h' : '';
          span.textContent = line + '\n';
          pre.appendChild(span);
        }
        cl.appendChild(pre);
      }
    }
    window.scrollTo({ top: 0 });
  }

  function setFilter(f) {
    filter = f;
    $$('.filters button').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.filter === f)));
    renderFindings();
  }
  $$('.filters button').forEach((b) => b.addEventListener('click', () => setFilter(b.dataset.filter)));

  function renderFindings() {
    const list = $('#findingList');
    list.textContent = '';
    const items = result.findings.filter((f) => (filter === 'all' ? true : filter === 'fixed' ? f.fixed : !f.fixed));
    if (!items.length) {
      const e = document.createElement('p'); e.className = 'empty';
      e.textContent = filter === 'open' ? 'Nothing needs your attention. Rotate any keys that were found, then deploy.' : filter === 'fixed' ? (result.meta.autoFix ? 'Nothing was changed automatically.' : 'Automatic fixing was off for this scan.') : 'No issues found.';
      list.appendChild(e);
      return;
    }
    const tpl = $('#findingTpl');
    for (const f of items) {
      const node = tpl.content.firstElementChild.cloneNode(true);
      node.dataset.sev = f.severity;
      node.dataset.fixed = String(!!f.fixed);
      if (!f.fixed && /critical|high/.test(f.severity) && filter === 'open') node.open = items.indexOf(f) < 3;
      $('.sev', node).textContent = f.fixed ? 'Fixed' : SEV_TEXT[f.severity];
      $('.f-title', node).textContent = f.title;
      $('.f-loc', node).textContent = f.file ? f.file + (f.line ? ':' + f.line : '') : '';
      if (f.snippet) { const s = $('.f-snippet', node); s.hidden = false; s.textContent = f.snippet; }
      const why = $('.f-why', node); const b1 = document.createElement('b'); b1.textContent = 'Why it matters: '; why.append(b1, f.why);
      const fix = $('.f-fix', node); const b2 = document.createElement('b');
      b2.textContent = f.fixed ? 'What VibeGuard did: ' : 'How to fix: ';
      fix.append(b2, f.fixed ? (f.fixSummary || f.fix) : f.fix);
      const d = f.diff || f.proposed;
      if (d) { const box = $('.f-diff', node); box.hidden = false; $('.del', box).textContent = d.before; $('.add', box).textContent = d.after; }
      if (f.aiPrompt) { const btn = $('.f-copy', node); btn.hidden = false; btn.addEventListener('click', () => copy(f.aiPrompt)); }
      list.appendChild(node);
    }
  }

  $('#copyAll').addEventListener('click', () => result && copy(result.allPrompt));
  $('#newScan').addEventListener('click', () => {
    stopPolling(); store.del('vg-job'); jobId = null; result = null; file = null;
    drop.classList.remove('has-file');
    $('#dropTitle').textContent = 'Drop your project ZIP here';
    $('#dropHint').textContent = 'or click to choose a file · up to 50 MB · leave out node_modules';
    $('#file').value = '';
    show('start');
  });
  $('#deleteData').addEventListener('click', async () => {
    if (!jobId) return;
    if (!confirm('Delete the report and fixed project from the server now? Download anything you need first.')) return;
    const r = await fetch(`/api/jobs/${jobId}`, { method: 'DELETE' }).catch(() => null);
    if (r && r.ok) { toast('Deleted from the server'); $('#newScan').click(); }
    else toast('Could not delete — it will be removed automatically within 30 minutes');
  });

  // ---------- install as an app (PWA) ----------
  let installEvt = null;
  window.addEventListener('beforeinstallprompt', (e) => { e.preventDefault(); installEvt = e; $('#installBtn').hidden = false; });
  $('#installBtn').addEventListener('click', async () => { if (!installEvt) return; installEvt.prompt(); await installEvt.userChoice; installEvt = null; $('#installBtn').hidden = true; });
  // Downloads in the in-browser build go through VG_LOCAL (the viewer's save dialog), not plain links.
  $('#downloads').addEventListener('click', async (e) => {
    const a = e.target.closest('a[data-file]');
    if (!a || !window.VG_LOCAL) return;
    e.preventDefault();
    try {
      const r = await window.VG_LOCAL.download(jobId, a.dataset.file);
      if (r === 'saved') toast('Saved');
    } catch (err) { toast(err.message || 'Could not save the file'); }
  });

  if (window.VG_LOCAL) {
    // In-browser build: no server, so no GitHub cloning, registry lookups or server-side data to delete.
    $('#tabGit').hidden = true;
    $('#optOnline').checked = false;
    $('#optOnline').closest('label').hidden = true;
    $('#deleteData').hidden = true;
    $('.privacy').textContent = 'Runs entirely in your browser: your code is never uploaded anywhere. Results disappear when you close this tab. Package vulnerability lookups and git-history scanning need the downloadable version.';
    $('.tip').textContent = 'Zip your project folder (leave out node_modules) and drop it here.';
  }

  if (!window.VG_LOCAL && 'serviceWorker' in navigator) window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js').catch(() => {}));

  // ---------- boot ----------
  fetch('/api/checks').then((r) => r.json()).then((c) => { checks = c; applyMode(mode, false); }).catch(() => applyMode(mode, false));
  applyMode(mode, false);
  // Resume a scan after a reload, but only within the same section (Website/App).
  const [savedId, savedMode] = (store.get('vg-job') || '').split(':');
  if (!window.VG_LOCAL && /^[a-f0-9]{32}$/.test(savedId || '') && savedMode === mode) { jobId = savedId; show('progress'); poll(); }
})();
