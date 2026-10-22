'use strict';
const { safeJSON } = require('../lib/detect');

module.exports = {
  id: 'debug',
  title: 'Turning off debug mode and source maps',
  async run(ctx) {
    const { p, det } = ctx;
    let seen = false;
    for (const f of p.byExt('.py')) {
      const c = p.read(f) || '';
      const edits = [];
      let m;
      const run = /\.run\(([^)\n]*?)\bdebug\s*=\s*True([^)\n]*)\)/g;
      while ((m = run.exec(c))) {
        seen = true;
        const fd = ctx.at(f, m.index, { category: 'debug', severity: 'critical', title: 'Flask/app runs with debug=True', why: 'The Werkzeug debugger gives anyone who triggers an error a Python console on your server (remote code execution).', fix: 'Read it from the environment: debug=os.environ.get("FLASK_DEBUG") == "1".' });
        edits.push({ index: m.index, old: m[0], new: m[0].replace(/debug\s*=\s*True/, 'debug=os.environ.get("FLASK_DEBUG") == "1"'), finding: fd, summary: 'Debug is now off unless FLASK_DEBUG=1 is set.' });
      }
      const cfg = /(app\.config\[\s*['"]DEBUG['"]\s*\]|app\.debug)\s*=\s*True/g;
      while ((m = cfg.exec(c))) {
        seen = true;
        const fd = ctx.at(f, m.index, { category: 'debug', severity: 'critical', title: 'Debug mode enabled in config', why: 'Debug mode exposes an interactive debugger and detailed errors.', fix: 'Set it from an environment variable.' });
        edits.push({ index: m.index, old: m[0], new: `${m[1]} = os.environ.get("FLASK_DEBUG") == "1"`, finding: fd, summary: 'Debug now controlled by FLASK_DEBUG (off by default).' });
      }
      if (/settings/.test(f)) {
        const dj = /^DEBUG\s*=\s*True\s*$/m.exec(c);
        if (dj) {
          seen = true;
          const fd = ctx.at(f, dj.index, { category: 'debug', severity: 'high', title: 'Django DEBUG = True', why: 'Error pages show settings, SQL and source code to anyone.', fix: 'DEBUG = os.environ.get("DJANGO_DEBUG", "False") == "True"' });
          edits.push({ index: dj.index, old: dj[0], new: 'DEBUG = os.environ.get("DJANGO_DEBUG", "False") == "True"', finding: fd, summary: 'DEBUG is now off unless DJANGO_DEBUG=True.' });
        }
        const ah = /^ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\s*\]\s*$/m.exec(c);
        if (ah) {
          seen = true;
          const fd = ctx.at(f, ah.index, { category: 'debug', severity: 'medium', title: "ALLOWED_HOSTS = ['*']", why: 'Allows Host-header attacks (password-reset poisoning, cache poisoning).', fix: 'List your real domains.' });
          edits.push({ index: ah.index, old: ah[0], new: 'ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")', finding: fd, summary: 'Hosts now come from DJANGO_ALLOWED_HOSTS.' });
        }
      }
      const uv = /uvicorn\.run\([^)]*reload\s*=\s*True/.exec(c);
      if (uv) { seen = true; ctx.at(f, uv.index, { category: 'debug', severity: 'low', title: 'uvicorn reload=True in code', why: 'Auto-reload is a development feature; in production it wastes resources and watches files.', fix: 'Pass --reload only in your dev command.' }); }
      const fa = /FastAPI\([^)]*debug\s*=\s*True/.exec(c);
      if (fa) { seen = true; ctx.at(f, fa.index, { category: 'debug', severity: 'high', title: 'FastAPI(debug=True)', why: 'Returns full tracebacks to clients.', fix: 'Remove debug=True or read it from the environment.' }); }
      if (edits.length && ctx.applyEdits(f, edits)) ctx.ensurePythonImport(f, 'import os');
      if (/\.run\(|DEBUG|FastAPI\(/.test(c)) seen = true;
    }

    // JS frameworks: source maps & debug flags
    for (const f of p.files.filter((x) => /(^|\/)(next\.config\.(js|mjs|ts|cjs)|vite\.config\.(js|mjs|ts)|webpack\.config\.(js|ts)|nuxt\.config\.(js|ts)|angular\.json)$/.test(x.path)).map((x) => x.path)) {
      seen = true;
      const c = p.read(f) || '';
      const edits = [];
      let m;
      const pm = /productionBrowserSourceMaps\s*:\s*true/.exec(c);
      if (pm) {
        const fd = ctx.at(f, pm.index, { category: 'debug', severity: 'medium', title: 'Production source maps are public', why: 'Anyone can download your original, readable source code (including comments and internal logic).', fix: 'Set productionBrowserSourceMaps: false.' });
        edits.push({ index: pm.index, old: pm[0], new: 'productionBrowserSourceMaps: false', finding: fd, summary: 'Source maps disabled in production.' });
      }
      const vs = /sourcemap\s*:\s*true/.exec(c);
      if (vs && /vite|build\s*:/.test(c)) {
        const fd = ctx.at(f, vs.index, { category: 'debug', severity: 'medium', title: 'Build publishes source maps', why: 'Your original source code is downloadable from the deployed site.', fix: "Use sourcemap: false (or 'hidden' and upload maps only to your error tracker)." });
        edits.push({ index: vs.index, old: vs[0], new: "sourcemap: process.env.NODE_ENV !== 'production'", finding: fd, summary: 'Source maps only outside production.' });
      }
      if ((m = /devtool\s*:\s*['"](eval|source-map|cheap[^'"]*|inline[^'"]*)['"]/.exec(c)) && !/mode\s*:\s*['"]development/.test(c)) {
        ctx.at(f, m.index, { category: 'debug', severity: 'low', title: `webpack devtool "${m[1]}" may ship source maps`, why: 'Source maps in production expose your source.', fix: "Use devtool: false (or 'hidden-source-map') for production builds." });
      }
      ctx.applyEdits(f, edits);
    }
    if (p.exists('angular.json')) {
      const j = safeJSON(p.read('angular.json'));
      if (j && JSON.stringify(j).includes('"sourceMap":true') && /production/.test(p.read('angular.json'))) {
        ctx.add({ category: 'debug', severity: 'low', file: 'angular.json', title: 'Source maps may be enabled for production', why: 'Exposes source code.', fix: 'Set "sourceMap": false in the production configuration.' });
      }
    }
    // Express: errorhandler / NODE_ENV forced to development
    for (const f of p.codeFiles((x) => /\.(m|c)?(js|ts)$/.test(x)).map((x) => x.path)) {
      const c = p.read(f) || '';
      let m = /app\.use\(\s*errorhandler\(\)\s*\)/.exec(c);
      if (m) { seen = true; ctx.at(f, m.index, { category: 'debug', severity: 'medium', title: 'errorhandler() middleware enabled', why: 'Shows full stack traces in production.', fix: "Only use it when process.env.NODE_ENV === 'development'." }); }
      m = /process\.env\.NODE_ENV\s*=\s*['"]development['"]/.exec(c);
      if (m) { seen = true; ctx.at(f, m.index, { category: 'debug', severity: 'medium', title: 'NODE_ENV forced to development in code', why: 'Frameworks enable verbose errors and disable optimizations/security in development mode.', fix: 'Remove this line; set NODE_ENV in your hosting environment.' }); }
      if (/express\(\)|createServer|listen\(/.test(c)) seen = true;
    }
    // .env with debug flags
    for (const f of p.files.filter((x) => /(^|\/)\.env(\.production)?$/.test(x.path)).map((x) => x.path)) {
      const c = p.read(f) || '';
      const m = /^(APP_DEBUG|DEBUG|FLASK_DEBUG|DJANGO_DEBUG)\s*=\s*(true|1|True)\s*$/m.exec(c);
      if (m) { seen = true; ctx.at(f, m.index, { category: 'debug', severity: /production/.test(f) ? 'high' : 'low', title: `${m[1]} enabled in ${f}`, why: 'If this file is used in production, debug output is exposed.', fix: 'Set it to false in production environments.' }); }
    }
    // Android debuggable handled by mobile check
    if (seen || det.hasBackend || det.pkgs.length) ctx.checked('debug');
    else ctx.na('debug', 'No framework configuration found.');
  },
};
