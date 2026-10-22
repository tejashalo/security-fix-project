'use strict';
const { findSecrets } = require('../lib/patterns');
const { isPlaceholder, shannon, envName, redact, posix, lineText } = require('../lib/util');

const ENV_FILE_RE = /(^|\/)\.env(\.[\w-]+)?$/;
const EXAMPLE_RE = /\.(example|sample|template|dist)$/;

module.exports = {
  id: 'secrets',
  title: 'Scanning for hardcoded API keys and secrets',
  async run(ctx) {
    const { p } = ctx;
    ctx.checked('secrets');
    const usedEnvNames = new Map(); // name -> value
    let anonNoted = false;

    for (const f of p.codeFiles()) {
      const file = f.path;
      if (/(^|\/)vibeguard-security\./.test(file)) continue;
      const isEnvFile = ENV_FILE_RE.test(file);
      const isExample = EXAMPLE_RE.test(file);
      if (isEnvFile && !isExample) continue; // handled by env check (expected place for secrets)
      const content = p.read(file);
      if (!content) continue;
      const isDoc = /\.(md|mdx|txt)$/.test(file);
      const hits = findSecrets(content, { generic: !isDoc, isPlaceholder, shannon });
      if (!hits.length) continue;
      const client = ctx.isClient(file);
      const edits = [];
      for (const h of hits) {
        const pat = h.pattern;
        if (pat.supabaseAnon) {
          if (!anonNoted) {
            anonNoted = true;
            ctx.at(file, h.index, {
              category: 'database', severity: 'info', title: 'Supabase anon key found (public by design)',
              why: 'The anon key is meant to be public. Your data is only safe if Row Level Security (RLS) is enabled on every table with correct policies.',
              fix: 'In Supabase → Table Editor, make sure RLS is ON for every table and add policies like `auth.uid() = user_id`.',
            });
          }
          continue;
        }
        ctx.secretValues.add(h.value);
        let severity = pat.severity;
        if (client && severity !== 'critical' && pat.id !== 'google') severity = 'critical';
        if (isExample) severity = 'high';
        if (/(^|\/)(test|tests|__tests__|spec|fixtures?)\//.test(file) && severity === 'critical') severity = 'high';
        const lineSnippet = lineText(content, h.index).split(h.value).join(redact(h.value));
        const finding = ctx.add({
          category: 'secrets', severity, file, line: ctx.lineOf(file, content, h.index), snippet: lineSnippet,
          title: `${pat.id === 'generic' ? pat.name : pat.name + ' hardcoded'}${client ? ' in code that ships to users' : ''}`,
          why: client
            ? `This file runs in the browser or inside the mobile app, so anyone can extract ${redact(h.value)} with DevTools or by unzipping the app. Bots scan for these keys within minutes and run up bills or steal data.`
            : `Secrets in source code end up in git, screenshots, AI chats and shared ZIPs. Anyone who gets the code gets ${pat.name.toLowerCase()} ${redact(h.value)}.`,
          fix: client
            ? `Move the code that uses this key to a backend/serverless function (e.g. /api route) and call that instead. Then rotate (regenerate) the key in the provider dashboard — treat the old one as leaked.${pat.id === 'google' ? ' For Firebase web keys, restrict the key to your domains/apps in Google Cloud Console and rely on Security Rules.' : ''}`
            : `Store it in .env and read it with an environment variable. Then rotate the key in the provider dashboard because it is already exposed.`,
          secretKind: pat.id,
        });
        if (client || pat.multiline || isExample || isDoc) continue;

        // ---- auto-fix: replace literal with env var (server-side JS/TS/Python/compose) ----
        const q = content[h.index - 1];
        const qEnd = content[h.index + h.length];
        const isJs = /\.(m|c)?(js|ts)x?$/.test(file);
        const isPy = /\.py$/.test(file);
        const isCompose = /(^|\/)(docker-)?compose[\w.-]*\.ya?ml$/.test(file);
        let name = pat.env;
        const before = content.slice(content.lastIndexOf('\n', h.index - 1) + 1, h.index - 1);
        const assign = /([A-Za-z_$][\w$]*)["']?\s*(?::|=|:=)\s*$/.exec(before);
        if (assign && (!name || pat.id === 'generic' || pat.id === 'jwt' || pat.id === 'db-url')) {
          const cand = envName(assign[1]);
          if (!/^(KEY|SECRET|TOKEN|PASSWORD|API_KEY|APIKEY|URL|URI|CONNECTION|VALUE|DEFAULT)$/.test(cand) || !name) name = cand;
        }
        if (!name) name = 'SECRET_' + (usedEnvNames.size + 1);
        if (/^(PASSWORD|PASS|PWD|SECRET|TOKEN|KEY|API_KEY|APIKEY|AUTH|AUTH_TOKEN|ACCESS_TOKEN|PRIVATE_KEY|CLIENT_SECRET)$/.test(name)) {
          const base = envName(posix.basename(file).replace(/\.[^.]+$/, ''));
          const prefix = /^(INDEX|APP|MAIN|SERVER|CONFIG|SETTINGS|CONSTANTS|UTILS?|HELPERS?)$/.test(base) ? 'APP' : base.replace(/_?(CONFIG|CLIENT|SERVICE|CONNECTION|CONN)$/, '') || 'APP';
          name = `${prefix}_${name}`;
        }
        let finalName = name, n = 2;
        while (usedEnvNames.has(finalName) && usedEnvNames.get(finalName) !== h.value) finalName = `${name}_${n++}`;
        usedEnvNames.set(finalName, h.value);

        if (isCompose) {
          const lineStart = content.lastIndexOf('\n', h.index - 1) + 1;
          const lineEnd = content.indexOf('\n', h.index) === -1 ? content.length : content.indexOf('\n', h.index);
          const line = content.slice(lineStart, lineEnd);
          const km = /^(\s*-?\s*)([A-Z][A-Z0-9_]*)(\s*[:=]\s*)(["']?)(.+?)\4\s*$/.exec(line);
          if (km && km[5] === h.value) {
            const varName = km[2];
            const newLine = `${km[1]}${varName}${km[3]}\${${varName}}`;
            edits.push({ index: lineStart, old: line, new: newLine, finding, summary: `Replaced with \${${varName}}; real value moved to .env next to the compose file (Docker Compose loads it automatically).` });
            ctx.envSet(varName, h.value, file);
          }
          continue;
        }
        if (!(q && q === qEnd && /["'`]/.test(q))) continue;
        if (q === '`' && /\$\{/.test(h.value)) continue;
        if (isJs) {
          edits.push({ index: h.index - 1, old: q + h.value + q, new: `process.env.${finalName}`, finding, summary: `Replaced with process.env.${finalName}; value moved to .env (git-ignored) and the name added to .env.example.` });
          ctx.envSet(finalName, h.value, file);
          ctx._needsEnvLoad = ctx._needsEnvLoad || [];
          ctx._needsEnvLoad.push(file);
        } else if (isPy) {
          edits.push({ index: h.index - 1, old: q + h.value + q, new: `os.environ.get("${finalName}")`, finding, summary: `Replaced with os.environ.get("${finalName}"); value moved to .env (git-ignored).` });
          ctx.envSet(finalName, h.value, file);
          ctx._needsPyEnv = ctx._needsPyEnv || new Set();
          ctx._needsPyEnv.add(file);
        }
      }
      ctx.applyEdits(file, edits);
    }
    for (const f of new Set(ctx._needsEnvLoad || [])) ctx.ensureEnvLoaded(f);
    for (const f of ctx._needsPyEnv || []) { ctx.ensurePythonImport(f, 'import os'); ctx.ensurePythonEnvLoaded(f); }
    if (ctx.findings.some((x) => x.category === 'secrets')) {
      ctx.note('Rotate (regenerate) every key VibeGuard found. Moving a key to .env stops future leaks, but a key that was ever in code, a ZIP or git history must be treated as compromised.');
    }
  },
};
