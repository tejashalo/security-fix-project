'use strict';

module.exports = {
  id: 'cors',
  title: 'Reviewing CORS settings',
  async run(ctx) {
    const { p, det } = ctx;
    let seen = false;
    const canFix = det.expressEntries.length > 0;

    for (const f of p.codeFiles((x) => /\.(m|c)?(js|ts)$/.test(x) && !/vibeguard-security/.test(x)).map((x) => x.path)) {
      const c = p.read(f) || '';
      if (ctx.isClient(f)) continue;
      const edits = [];
      // cors() with no options → allows every origin
      const re = /\bcors\s*\(\s*(\{[\s\S]*?\})?\s*\)/g;
      let m;
      while ((m = re.exec(c))) {
        if (!/require\(['"]cors['"]\)|from\s+['"]cors['"]/.test(c)) break;
        seen = true;
        const opts = m[1] || '';
        if (/vibeguardCorsOptions/.test(opts)) continue;
        const wildcard = !opts || /origin\s*:\s*(['"`]\*['"`]|true)/.test(opts);
        if (!wildcard) continue;
        const creds = /credentials\s*:\s*true/.test(opts);
        const fd = ctx.at(f, m.index, {
          category: 'cors', severity: creds || /origin\s*:\s*true/.test(opts) ? 'high' : 'medium',
          title: opts ? 'CORS allows every website' : 'cors() with no options allows every website',
          why: creds || /origin\s*:\s*true/.test(opts)
            ? 'Reflecting any origin with credentials lets any website make logged-in requests to your API and read the responses.'
            : 'Any website can call your API from a visitor\'s browser and read the responses.',
          fix: 'Allow only your own front-end origins (set ALLOWED_ORIGINS="https://yourapp.com").',
        });
        if (!canFix) continue;
        const replacement = !opts ? 'cors(vibeguardCorsOptions)' : `cors(${opts.replace(/origin\s*:\s*(['"`]\*['"`]|true)/, 'origin: vibeguardCorsOptions.origin')})`;
        edits.push({ index: m.index, old: m[0], new: replacement, finding: fd, summary: 'CORS now only allows origins listed in ALLOWED_ORIGINS (defaults to localhost for development).' });
      }
      if (edits.length && ctx.applyEdits(f, edits)) {
        ctx.ensureSecurityImport(f, ['vibeguardCorsOptions']);
        ctx.envExampleAdd(['ALLOWED_ORIGINS'], f);
      }
      // manual Access-Control-Allow-Origin: *
      const h = /(setHeader|header|set)\(\s*['"]Access-Control-Allow-Origin['"]\s*,\s*(['"]\*['"]|req\.headers\.origin|req\.get\(['"]origin['"]\))/i.exec(c);
      if (h) {
        seen = true;
        ctx.at(f, h.index, { category: 'cors', severity: /origin/i.test(h[2]) ? 'high' : 'medium', title: h[2].includes('*') ? 'Access-Control-Allow-Origin set to *' : 'CORS reflects any Origin header', why: 'Any website can read responses from this API in a visitor\'s browser.', fix: 'Compare the Origin header against an allow-list before echoing it back.' });
      }
    }
    // Next.js / Vercel headers with *
    for (const f of [...p.byName('next.config.js'), ...p.byName('next.config.mjs'), ...p.byName('next.config.ts'), ...p.byName('vercel.json')]) {
      const c = p.read(f) || '';
      const m = /Access-Control-Allow-Origin['"]\s*,?\s*value\s*:\s*['"]\*['"]|"key"\s*:\s*"Access-Control-Allow-Origin"\s*,\s*"value"\s*:\s*"\*"/.exec(c);
      if (m) { seen = true; ctx.at(f, m.index, { category: 'cors', severity: 'medium', title: 'CORS header set to * in deployment config', why: 'Every website can call your API routes from the browser.', fix: 'Replace * with your own domain.' }); }
    }
    // Python
    for (const f of p.byExt('.py')) {
      const c = p.read(f) || '';
      const edits = [];
      let m = /\bCORS\(\s*(\w+)\s*\)/.exec(c);
      if (m && /flask_cors/.test(c)) {
        seen = true;
        const fd = ctx.at(f, m.index, { category: 'cors', severity: 'medium', title: 'Flask-CORS allows every website', why: 'CORS(app) with no origins allows any site to call your API.', fix: 'Pass origins from an environment variable.' });
        edits.push({ index: m.index, old: m[0], new: `CORS(${m[1]}, origins=os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(","))`, finding: fd, summary: 'Only origins in ALLOWED_ORIGINS are allowed.' });
      }
      const fm = /allow_origins\s*=\s*\[\s*["']\*["']\s*\]/.exec(c);
      if (fm) {
        seen = true;
        const creds = /allow_credentials\s*=\s*True/.test(c);
        const fd = ctx.at(f, fm.index, { category: 'cors', severity: creds ? 'high' : 'medium', title: 'FastAPI CORS allows every website', why: creds ? 'Wildcard origins with credentials expose logged-in users.' : 'Any website can call your API.', fix: 'Use an explicit list of origins.' });
        edits.push({ index: fm.index, old: fm[0], new: 'allow_origins=os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(",")', finding: fd, summary: 'Origins now come from ALLOWED_ORIGINS.' });
      }
      const dj = /CORS_(ORIGIN_ALLOW_ALL|ALLOW_ALL_ORIGINS)\s*=\s*True/.exec(c);
      if (dj) {
        seen = true;
        const fd = ctx.at(f, dj.index, { category: 'cors', severity: 'medium', title: 'django-cors-headers allows all origins', why: 'Any website can call your API.', fix: 'Set CORS_ALLOWED_ORIGINS to your domains.' });
        edits.push({ index: dj.index, old: dj[0], new: `CORS_${dj[1]} = False\nCORS_ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(",")`, finding: fd, summary: 'Wildcard disabled; origins come from ALLOWED_ORIGINS.' });
      }
      if (edits.length && ctx.applyEdits(f, edits)) { ctx.ensurePythonImport(f, 'import os'); ctx.envExampleAdd(['ALLOWED_ORIGINS'], f); }
      if (/CORSMiddleware|flask_cors|corsheaders/.test(c)) seen = true;
    }
    if (seen || det.hasBackend) ctx.checked('cors');
    else ctx.na('cors', 'No API server found — CORS only matters for your own backend.');
  },
};
