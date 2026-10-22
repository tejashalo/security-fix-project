'use strict';
const { lineText, redact, isPlaceholder } = require('../lib/util');
const T = require('../lib/templates');
const git = require('../lib/git');

const ENV_FILE_RE = /(^|\/)\.env(\.[\w-]+)?$/;
const PUBLIC_PREFIX = /^(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_|NUXT_PUBLIC_|GATSBY_|VUE_APP_)/;
const SENSITIVE_NAME = /(SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|PASSWD|DB_|DATABASE|MONGO|POSTGRES|ADMIN|WEBHOOK|OPENAI|ANTHROPIC|CLAUDE|GROQ|GEMINI|MISTRAL|HUGGING|REPLICATE|STRIPE_SECRET|SK_|AWS_SECRET|SENDGRID|RESEND|TWILIO_AUTH|JWT|SIGNING|ENCRYPTION|SMTP_PASS)/;

module.exports = {
  id: 'env',
  title: 'Checking environment variables and .env handling',
  async run(ctx) {
    const { p, det } = ctx;
    ctx.checked('env');
    const envFiles = p.files.filter((f) => ENV_FILE_RE.test(f.path) && !/\.(example|sample|template)$/.test(f.path) && !f.skipped).map((f) => f.path);

    // 1. .gitignore must cover .env
    const coveredEnv = ctx.initialEnvIgnored;
    if (!coveredEnv) {
      const fd = ctx.add({
        category: 'env', severity: envFiles.length ? 'high' : 'medium', file: p.exists('.gitignore') ? '.gitignore' : null,
        title: envFiles.length ? '.env file is not git-ignored' : '.gitignore does not protect .env files',
        why: 'If .env is not in .gitignore, one `git add .` publishes every key to GitHub, where bots scrape them within minutes.',
        fix: 'Add `.env` and `.env.*` (but not `.env.example`) to .gitignore.',
      });
      ctx.ensureGitignore(T.GITIGNORE_BLOCK);
      ctx.markFixed(fd, { before: '(no rule for .env)', after: T.GITIGNORE_BLOCK.slice(1, 7).join('\n') + '\n…', summary: 'Added .env, keys, databases and logs to .gitignore.' });
    }

    // 2. .env tracked by git
    if (p.hasGit) {
      const tracked = git.trackedFiles(p.root).filter((f) => ENV_FILE_RE.test(f) && !/\.(example|sample|template)$/.test(f));
      for (const f of tracked) {
        ctx.add({
          category: 'env', severity: 'critical', file: f,
          title: `${f} is committed to git`,
          why: 'Everyone with access to the repository (or the public, if it is public) can read every secret in this file — including in old commits.',
          fix: `Run \`git rm --cached ${f}\` then commit. Rotate every key that was inside it, and clean history (see the Git history section).`,
        });
      }
    }

    // 3. Collect env var usage
    const used = new Map(); // name -> first {file, index}
    const refRe = /process\.env\.([A-Z][A-Z0-9_]*)|process\.env\[['"]([A-Z][A-Z0-9_]*)['"]\]|import\.meta\.env\.([A-Z][A-Z0-9_]*)|os\.environ(?:\.get)?\(\s*['"]([A-Z][A-Z0-9_]*)['"]|os\.environ\[['"]([A-Z][A-Z0-9_]*)['"]\]|os\.getenv\(\s*['"]([A-Z][A-Z0-9_]*)['"]|Deno\.env\.get\(\s*['"]([A-Z][A-Z0-9_]*)['"]|env\(\s*['"]([A-Z][A-Z0-9_]*)['"]/g;
    for (const f of p.codeFiles((x) => /\.(m|c)?(js|ts)x?$|\.(py|vue|svelte|astro)$/.test(x))) {
      if (ctx.isIgnored({ file: f.path })) continue;
      const content = p.read(f.path) || '';
      let m;
      refRe.lastIndex = 0;
      while ((m = refRe.exec(content))) {
        const name = m.slice(1).find(Boolean);
        if (!used.has(name)) used.set(name, { file: f.path, index: m.index });
      }
    }
    const ignoreNames = new Set(['NODE_ENV', 'MODE', 'DEV', 'PROD', 'SSR', 'BASE_URL', 'CI', 'VERCEL', 'VERCEL_URL', 'VERCEL_ENV', 'NETLIFY', 'HOME', 'PATH', 'PWD']);

    // 4. Public-prefixed secrets (bundled into the browser / app)
    const envValues = new Map();
    for (const ef of envFiles) {
      for (const line of (p.read(ef) || '').split(/\r?\n/)) {
        const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
        if (m) envValues.set(m[1], { value: m[2].replace(/^['"]|['"]$/g, ''), file: ef });
      }
    }
    const allNames = new Set([...used.keys(), ...envValues.keys()]);
    for (const name of allNames) {
      if (!PUBLIC_PREFIX.test(name) || !SENSITIVE_NAME.test(name.replace(PUBLIC_PREFIX, ''))) continue;
      if (/ANON|PUBLISHABLE|PUBLIC_KEY|_PK$|SITE_KEY|MEASUREMENT/.test(name)) continue;
      const where = used.get(name);
      const info = {
        category: 'env', severity: 'critical',
        title: `Secret exposed through public env var ${name}`,
        why: `Variables starting with ${name.match(PUBLIC_PREFIX)[1]} are copied into the JavaScript sent to every visitor (or into the app bundle). Anyone can read ${name} in DevTools.`,
        fix: `Rename it without the public prefix, use it only in server code (API route / server action / backend), and rotate the key.`,
      };
      if (where) ctx.at(where.file, where.index, info);
      else ctx.add({ file: envValues.get(name).file, ...info });
    }

    // 5. Insecure fallbacks:  process.env.JWT_SECRET || 'secret'
    const fbRe = /process\.env\.([A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|PASS|SALT|PEPPER)[A-Z0-9_]*)\s*(\|\||\?\?)\s*(['"`])([^'"`\n]*)\3/g;
    const pyFbRe = /os\.(?:environ\.get|getenv)\(\s*(['"])([A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|PASS|SALT)[A-Z0-9_]*)\1\s*,\s*(['"])([^'"\n]*)\3\s*\)/g;
    for (const f of p.codeFiles((x) => /\.(m|c)?(js|ts)x?$|\.py$/.test(x))) {
      if (ctx.isClient(f.path)) continue;
      const content = p.read(f.path) || '';
      const edits = [];
      let m;
      fbRe.lastIndex = 0;
      while ((m = fbRe.exec(content))) {
        const [whole, name, , , fallback] = m;
        const fd = ctx.at(f.path, m.index, {
          category: 'env', severity: 'critical',
          title: `Guessable fallback for ${name}`,
          why: `If ${name} is ever missing in production, the app silently uses "${redact(fallback)}" — attackers try these defaults first and can then forge sessions/tokens.`,
          fix: `Remove the fallback so the app fails loudly, and set a long random ${name} in .env.`,
        });
        if (fallback) ctx.secretValues.add(fallback);
        edits.push({ index: m.index, old: whole, new: `process.env.${name}`, finding: fd, summary: `Removed the fallback and put a freshly generated random ${name} in .env.` });
        ctx.envSet(name, ctx.newSecret(), f.path);
      }
      pyFbRe.lastIndex = 0;
      while ((m = pyFbRe.exec(content))) {
        const [whole, , name, , fallback] = m;
        if (!fallback) continue;
        const fd = ctx.at(f.path, m.index, {
          category: 'env', severity: 'critical', title: `Guessable fallback for ${name}`,
          why: `If ${name} is missing, the app uses a predictable default that attackers can use to forge sessions or tokens.`,
          fix: `Use os.environ["${name}"] (fails loudly if missing) and set a long random value in .env.`,
        });
        edits.push({ index: m.index, old: whole, new: `os.environ["${name}"]`, finding: fd, summary: `Now required from the environment; random value written to .env.` });
        ctx.envSet(name, ctx.newSecret(), f.path);
      }
      ctx.applyEdits(f.path, edits);
    }

    // 6. Secrets that look real inside .env.example
    for (const f of p.files.filter((x) => /(^|\/)\.env\.(example|sample|template)$/.test(x.path))) {
      const content = p.read(f.path) || '';
      const lines = content.split('\n');
      let pos = 0;
      const edits = [];
      for (const line of lines) {
        const m = /^(\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*)(.+)$/.exec(line);
        if (m && /(SECRET|KEY|TOKEN|PASSWORD|PASS|PRIVATE)/i.test(line.split('=')[0])) {
          const v = m[2].trim().replace(/^['"]|['"]$/g, '');
          if (v.length >= 12 && !isPlaceholder(v) && /[0-9]/.test(v) && /[A-Za-z]/.test(v)) {
            ctx.secretValues.add(v);
            const fd = ctx.add({
              category: 'env', severity: 'high', file: f.path, line: ctx.lineOf(f.path, content, pos), snippet: line.replace(v, redact(v)),
              title: 'Real-looking secret inside an example env file', why: '.env.example is meant to be committed, so any real value inside it is public.',
              fix: 'Replace the value with an empty placeholder and rotate the key.',
            });
            edits.push({ index: pos, old: line, new: m[1].replace(/\s+$/, ''), finding: fd, summary: 'Value removed from the example file.' });
          }
        }
        pos += line.length + 1;
      }
      ctx.applyEdits(f.path, edits);
    }

    // 7. Document used variables in .env.example
    const names = [...used.keys()].filter((n) => !ignoreNames.has(n));
    if (names.length) {
      const byPkg = new Map();
      for (const n of names) {
        const where = used.get(n).file;
        const dir = ctx.pkgDirOf(where);
        if (!byPkg.has(dir)) byPkg.set(dir, { file: where, names: [] });
        byPkg.get(dir).names.push(n);
      }
      for (const [, { file, names: ns }] of byPkg) {
        const examplePath = ctx.join(ctx.pkgDirOf(file), '.env.example');
        const existed = p.exists(examplePath);
        const missing = ctx.envExampleAdd(ns, file);
        if (missing.length) {
          const fd = ctx.add({
            category: 'env', severity: 'low', file: examplePath,
            title: existed ? `.env.example is missing ${missing.length} variable(s)` : 'No .env.example file',
            why: 'Without a documented list of variables, deployments break or people paste real keys into code to "make it work".',
            fix: 'Keep a .env.example with every variable name and no values.',
          });
          ctx.markFixed(fd, { before: existed ? '(incomplete)' : '(missing)', after: missing.slice(0, 8).map((n) => `${n}=`).join('\n') + (missing.length > 8 ? '\n…' : ''), summary: `${existed ? 'Added' : 'Created with'} ${missing.length} variable name(s).` });
        }
      }
    }
    void lineText; void det;
  },
};
