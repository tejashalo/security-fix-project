'use strict';
const T = require('../lib/templates');
const { safeJSON } = require('../lib/detect');

const RATE_LIBS = ['express-rate-limit', 'rate-limiter-flexible', 'express-slow-down', '@upstash/ratelimit', 'express-brute', '@fastify/rate-limit', 'koa-ratelimit', 'hono-rate-limiter'];

module.exports = {
  id: 'hardening',
  title: 'Adding security headers and rate limiting',
  async run(ctx) {
    const { p, det } = ctx;
    const hasHelmet = det.hasAny('helmet', '@fastify/helmet', 'koa-helmet');
    const hasRate = det.hasAny(...RATE_LIBS);
    let headersHandled = false, rateHandled = false;

    // ---------- Express ----------
    const doneFiles = new Set();
    for (const entry of det.expressEntries) {
      if (doneFiles.has(entry.file)) continue;
      doneFiles.add(entry.file);
      const content = p.read(entry.file) || '';
      if (/applyVibeGuard\(/.test(content)) continue;
      const usesHelmet = hasHelmet && /helmet\s*\(/.test(content);
      const usesRate = hasRate && /rateLimit|RateLimiter|slowDown|limiter/i.test(content);
      headersHandled = true; rateHandled = true;
      ctx.checked('headers'); ctx.checked('ratelimit');
      if (usesHelmet && usesRate) continue;
      const findings = [];
      if (!usesHelmet) findings.push(ctx.at(entry.file, entry.index, {
        category: 'headers', severity: 'medium', title: 'No security headers on the Express server',
        why: 'Without headers like Content-Security-Policy, X-Frame-Options and HSTS, browsers will let your site be framed (clickjacking), sniff content types and downgrade to HTTP.',
        fix: 'Add security headers to every response (helmet, or the zero-dependency middleware VibeGuard generates).',
      }));
      if (!usesRate) findings.push(ctx.at(entry.file, entry.index, {
        category: 'ratelimit', severity: 'high', title: 'No rate limiting on the server',
        why: 'Anyone can hammer your login with millions of password guesses, spam sign-ups and forms, or burn through your paid API (AI, email, SMS) credits.',
        fix: 'Limit requests per IP: strict on login/signup/reset, moderate on AI endpoints, generous elsewhere.',
      }));
      const opts = [];
      if (usesHelmet) opts.push('headers: false');
      if (usesRate) opts.push('rateLimit: false');
      if (!ctx.ensureSecurityImport(entry.file, ['applyVibeGuard'])) continue;
      const c2 = p.read(entry.file);
      const re = new RegExp(`(?:const|let|var)\\s+${entry.appVar}\\s*(?::\\s*[\\w.<>]+\\s*)?=\\s*express\\s*\\(`);
      const m = re.exec(c2);
      if (!m) continue;
      const at = ctx.statementEnd(c2, m.index);
      const call = `applyVibeGuard(${entry.appVar}${opts.length ? `, { ${opts.join(', ')} }` : ''}); // VibeGuard: security headers + rate limits\n`;
      ctx.applyEdits(entry.file, [{ index: at, old: '', new: call }]);
      for (const f of findings) ctx.markFixed(f, { before: m[0] + '…);', after: call.trim(), summary: f.category === 'headers'
        ? 'Added security headers (CSP in report-only mode so nothing breaks, X-Frame-Options, nosniff, Referrer-Policy, HSTS on HTTPS) and removed X-Powered-By.'
        : 'Added rate limits: 10 req/15 min on login/signup/reset, 30 on AI endpoints, 300 elsewhere (configurable via env vars).' });
    }
    if (det.expressEntries.length && ctx.securityModule) {
      ctx.note('If the server runs behind a proxy/load balancer (Render, Railway, Heroku, Fly, Nginx), add `app.set(\'trust proxy\', 1)` so rate limiting sees real client IPs.');
      ctx.note('The Content-Security-Policy is added in report-only mode. Check your browser console for CSP reports, adjust, then set VIBEGUARD_CSP_ENFORCE=1 to enforce it.');
    }

    // express.json() without size limit → api
    for (const f of p.codeFiles((x) => /\.(m|c)?(js|ts)$/.test(x))) {
      const content = p.read(f.path) || '';
      const re = /\b(express|bodyParser)\.(json|urlencoded)\(\s*(\{[^)]*\})?\s*\)/g;
      const edits = [];
      let m;
      while ((m = re.exec(content))) {
        if (m[3] && /limit\s*:/.test(m[3])) continue;
        const fd = ctx.at(f.path, m.index, {
          category: 'api', severity: 'low', title: `${m[1]}.${m[2]}() has no body size limit set explicitly`,
          why: 'Huge request bodies can tie up your server (denial of service). Set an explicit, small limit.',
          fix: "Pass `{ limit: '100kb' }` (raise it only for routes that really need more).",
        });
        const inner = m[3] ? m[3].replace(/^\{\s*/, "{ limit: '100kb', ") : "{ limit: '100kb' }";
        edits.push({ index: m.index, old: m[0], new: `${m[1]}.${m[2]}(${inner})`, finding: fd, summary: 'Request bodies capped at 100kb.' });
      }
      ctx.applyEdits(f.path, edits);
    }

    // ---------- Next.js ----------
    for (const pkg of det.nextPkgs) {
      const dir = pkg.dir === '.' ? '' : pkg.dir;
      ctx.checked('headers');
      const cfgFile = ['next.config.js', 'next.config.mjs', 'next.config.ts', 'next.config.cjs'].map((n) => ctx.join(dir, n)).find((f) => p.exists(f));
      const cfg = cfgFile ? p.read(cfgFile) || '' : '';
      const useSrc = p.dirs.includes(ctx.join(dir, 'src/app')) || p.dirs.includes(ctx.join(dir, 'src/pages'));
      const base = ctx.join(dir, useSrc ? 'src' : '');
      const mwFile = ['middleware.ts', 'middleware.js', 'proxy.ts', 'proxy.js'].map((n) => ctx.join(base === '' ? '' : base, n)).find((f) => p.exists(f))
        || ['middleware.ts', 'middleware.js'].map((n) => ctx.join(dir, n)).find((f) => p.exists(f));
      const mw = mwFile ? p.read(mwFile) || '' : '';
      const hasHeaders = /async\s+headers\s*\(|headers\s*:\s*async|headers\s*\(\)\s*\{/.test(cfg) || /X-Frame-Options|Content-Security-Policy|x-frame-options/i.test(mw);
      headersHandled = true;
      if (!hasHeaders) {
        const fd = ctx.add({
          category: 'headers', severity: 'medium', file: cfgFile || ctx.join(dir, 'package.json'),
          title: 'Next.js app sends no security headers',
          why: 'Without CSP, X-Frame-Options and HSTS your pages can be framed for clickjacking and are easier to attack with injected scripts.',
          fix: 'Add headers in next.config `headers()` or in middleware.',
        });
        if (!mwFile) {
          const ts = det.tsProject || p.exists(ctx.join(dir, 'tsconfig.json'));
          const file = ctx.join(base, ts ? 'middleware.ts' : 'middleware.js');
          ctx.createFile(file, T.nextMiddleware(ts), 'Next.js middleware that adds security headers to every response.');
          ctx.markFixed(fd, { before: '(no middleware)', after: `${file} created`, summary: `Created ${file} which adds security headers (CSP in report-only mode).` });
        } else {
          fd.fix = `Your ${mwFile} already exists, so VibeGuard did not overwrite it. Add these headers to the response it returns: ${T.HEADER_LIST.map(([k]) => k).join(', ')}, Strict-Transport-Security and Content-Security-Policy.`;
        }
      }
      // rate limiting for sensitive API routes
      const apiFiles = p.codeFiles((x) => x.startsWith(dir ? dir + '/' : '') && /(^|\/)(pages\/api|app\/api|app\/.*\/route)\b.*\.(js|ts)$|(^|\/)app\/api\/.*route\.(js|ts)$/.test(x)).map((f) => f.path);
      const sensitive = apiFiles.filter((f) => /(login|signin|signup|register|auth|reset|forgot|otp|chat|ai|generate|completion|llm|contact|email|sms|checkout)/i.test(f));
      if (sensitive.length && !hasRate) {
        rateHandled = true;
        ctx.add({
          category: 'ratelimit', severity: 'high', file: sensitive[0],
          title: `${sensitive.length} sensitive API route(s) have no rate limiting`,
          snippet: sensitive.slice(0, 5).join(', '),
          why: 'Serverless functions scale with traffic — and so does your bill. Login, AI and email routes are the first things bots abuse.',
          fix: 'Use @upstash/ratelimit (works on Vercel/serverless) or enable Vercel Firewall rate limiting for these paths. In-memory limits do not work on serverless.',
        });
      } else if (apiFiles.length) { rateHandled = true; ctx.checked('ratelimit'); }
    }

    // ---------- Flask ----------
    for (const app of det.flaskApps) {
      const content = p.read(app.file) || '';
      headersHandled = rateHandled = true;
      ctx.checked('headers'); ctx.checked('ratelimit');
      if (/_vibeguard_security_headers|Talisman\(|flask_limiter|Limiter\(/.test(content)) continue;
      const f1 = ctx.at(app.file, app.index, { category: 'headers', severity: 'medium', title: 'Flask app sends no security headers', why: 'Missing CSP, X-Frame-Options, nosniff and HSTS make XSS and clickjacking easier.', fix: 'Add an after_request hook (or Flask-Talisman).' });
      const f2 = ctx.at(app.file, app.index, { category: 'ratelimit', severity: 'high', title: 'Flask app has no rate limiting', why: 'Login and form endpoints can be brute-forced or spammed without limits.', fix: 'Add rate limiting (Flask-Limiter for production with Redis).' });
      const at = ctx.statementEnd(content, app.index);
      const block = T.flaskBlock(app.appVar);
      ctx.applyEdits(app.file, [{ index: at, old: '', new: block }]);
      ctx.markFixed(f1, { before: `${app.appVar} = Flask(...)`, after: '@app.after_request → security headers', summary: 'Added an after_request hook with security headers.' });
      ctx.markFixed(f2, { before: `${app.appVar} = Flask(...)`, after: '@app.before_request → rate limit', summary: 'Added an in-memory rate limiter (10/15 min on login/signup, 300/15 min elsewhere).' });
    }

    // ---------- FastAPI ----------
    for (const app of det.fastapiApps) {
      const content = p.read(app.file) || '';
      headersHandled = rateHandled = true;
      ctx.checked('headers'); ctx.checked('ratelimit');
      if (/_vibeguard_security|slowapi|Limiter\(/.test(content)) continue;
      const f1 = ctx.at(app.file, app.index, { category: 'headers', severity: 'medium', title: 'FastAPI app sends no security headers', why: 'Missing CSP, X-Frame-Options, nosniff and HSTS.', fix: 'Add an HTTP middleware that sets them.' });
      const f2 = ctx.at(app.file, app.index, { category: 'ratelimit', severity: 'high', title: 'FastAPI app has no rate limiting', why: 'Login and AI endpoints can be brute-forced or used to run up your bill.', fix: 'Add rate limiting (slowapi with Redis for production).' });
      const at = ctx.statementEnd(content, app.index);
      ctx.applyEdits(app.file, [{ index: at, old: '', new: T.fastapiBlock(app.appVar) }]);
      ctx.markFixed(f1, { before: `${app.appVar} = FastAPI(...)`, after: '@app.middleware("http") → security headers', summary: 'Added middleware with security headers.' });
      ctx.markFixed(f2, { before: `${app.appVar} = FastAPI(...)`, after: '@app.middleware("http") → rate limit', summary: 'Added an in-memory rate limiter (10/15 min on auth routes, 300 elsewhere).' });
    }

    // ---------- Django ----------
    for (const file of det.djangoSettings) {
      const content = p.read(file) || '';
      headersHandled = true;
      ctx.checked('headers');
      if (/SECURE_HSTS_SECONDS|SECURE_CONTENT_TYPE_NOSNIFF/.test(content)) continue;
      const fd = ctx.add({ category: 'headers', severity: 'medium', file, title: 'Django production security settings are missing', why: 'HSTS, secure cookies, SSL redirect and nosniff are off by default.', fix: 'Add the SECURE_* settings for production.' });
      ctx.applyEdits(file, [{ index: content.length, old: '', new: T.DJANGO_BLOCK }]);
      ctx.ensurePythonImport(file, 'import os');
      ctx.markFixed(fd, { before: '(not set)', after: 'SECURE_* settings block (production only)', summary: 'Added HSTS, secure cookies, SSL redirect, nosniff and X-Frame-Options settings (active when DEBUG is False).' });
      if (!/django_ratelimit|axes/.test(det.pyReq)) {
        rateHandled = true;
        ctx.add({ category: 'ratelimit', severity: 'high', file, title: 'Django app has no login rate limiting', why: 'Login forms can be brute-forced.', fix: 'Install django-axes (locks out repeated failed logins) or django-ratelimit.' });
      }
    }

    // ---------- Static / SPA hosting ----------
    if (!headersHandled && (det.hasHtml || det.hasAny('vite', 'react-scripts', 'vue', 'svelte', '@angular/core'))) {
      ctx.checked('headers');
      const vercel = p.read('vercel.json');
      const netlifyHeaders = p.read('_headers') || p.read('public/_headers');
      const netlifyToml = p.read('netlify.toml') || '';
      if (vercel != null) {
        const json = safeJSON(vercel);
        if (json && !json.headers) {
          const fd = ctx.add({ category: 'headers', severity: 'medium', file: 'vercel.json', title: 'Vercel deployment sends no security headers', why: 'Missing X-Frame-Options, nosniff, HSTS and Referrer-Policy.', fix: 'Add a headers section to vercel.json.' });
          json.headers = T.vercelHeaders();
          p.write('vercel.json', JSON.stringify(json, null, 2) + '\n');
          ctx.markFixed(fd, { before: '(no "headers")', after: '"headers": [ … security headers … ]', summary: 'Added security headers to vercel.json.' });
        }
      } else if (!netlifyHeaders && !/\[\[headers\]\]/.test(netlifyToml)) {
        const target = p.dirs.includes('public') ? 'public/_headers' : '_headers';
        const fd = ctx.add({ category: 'headers', severity: 'medium', file: null, title: 'Static site has no security headers configured', why: 'Static hosts send no security headers unless you configure them.', fix: 'Add a _headers file (Netlify, Cloudflare Pages) or headers in vercel.json.' });
        ctx.createFile(target, T.staticHeadersFile(), 'Security headers for Netlify / Cloudflare Pages.');
        ctx.markFixed(fd, { before: '(none)', after: `${target} created`, summary: `Created ${target}. On Vercel or other hosts, copy these headers into that host's config.` });
      }
    }
    if (!rateHandled) {
      if (det.hasBackend) ctx.checked('ratelimit');
      else ctx.na('ratelimit', det.frameworks.has('Supabase') || det.frameworks.has('Firebase')
        ? 'No server code. Supabase/Firebase rate-limit their own APIs; review Auth rate limits in their dashboards.'
        : 'No server code found — nothing to rate-limit here.');
    }
    if (!headersHandled && !ctx.status.has('headers')) ctx.na('headers', 'No web server or website files detected.');
  },
};
