'use strict';
const { posix } = require('./util');

function safeJSON(s) { try { return JSON.parse(s); } catch { return null; } }

function detect(p) {
  const pkgs = p.byName('package.json')
    .map((file) => ({ file, dir: posix.dirname(file), json: safeJSON(p.read(file)) }))
    .filter((x) => x.json && typeof x.json === 'object');
  const deps = new Set();
  for (const k of pkgs) for (const sec of ['dependencies', 'devDependencies']) Object.keys(k.json[sec] || {}).forEach((d) => deps.add(d));
  const has = (n) => deps.has(n);
  const hasAny = (...n) => n.some(has);

  const pyReq = [...p.byName('requirements.txt'), ...p.byName('pyproject.toml'), ...p.byName('Pipfile')].map((f) => (p.read(f) || '').toLowerCase()).join('\n');
  const pyFiles = p.byExt('.py');
  const pyText = (re) => pyFiles.some((f) => re.test(p.read(f) || ''));

  const fw = new Set();
  const add = (cond, name) => { if (cond) fw.add(name); };
  add(has('next'), 'Next.js');
  add(has('nuxt'), 'Nuxt');
  add(has('@sveltejs/kit'), 'SvelteKit');
  add(has('svelte') && !has('@sveltejs/kit'), 'Svelte');
  add(has('@remix-run/node') || has('@remix-run/react') || has('react-router') && has('@react-router/node'), 'Remix/React Router');
  add(has('astro'), 'Astro');
  add(has('react') && !has('next') && !has('react-native'), 'React');
  add(has('vue') && !has('nuxt'), 'Vue');
  add(has('@angular/core'), 'Angular');
  add(has('vite'), 'Vite');
  add(has('express'), 'Express');
  add(has('fastify'), 'Fastify');
  add(has('koa'), 'Koa');
  add(has('hono'), 'Hono');
  add(has('@nestjs/core'), 'NestJS');
  add(/\bflask\b/.test(pyReq) || pyText(/Flask\(__name__/), 'Flask');
  add(/\bdjango\b/.test(pyReq) || p.byName('manage.py').length > 0, 'Django');
  add(/\bfastapi\b/.test(pyReq) || pyText(/FastAPI\(/), 'FastAPI');
  add(has('react-native'), 'React Native');
  add(has('expo'), 'Expo');
  add(hasAny('@capacitor/core', '@ionic/react', '@ionic/angular', '@ionic/vue'), 'Capacitor/Ionic');
  add(has('electron'), 'Electron');
  add(hasAny('firebase', 'firebase-admin') || p.byName('firebase.json').length > 0, 'Firebase');
  add(hasAny('@supabase/supabase-js', '@supabase/ssr') || p.dirs.includes('supabase') || /supabase/.test(pyReq), 'Supabase');
  add(hasAny('mongoose', 'mongodb') || /pymongo/.test(pyReq), 'MongoDB');
  add(hasAny('prisma', '@prisma/client'), 'Prisma');
  add(hasAny('pg', 'postgres', 'mysql2', 'mysql', 'sqlite3', 'better-sqlite3', 'sequelize', 'drizzle-orm', 'knex', 'typeorm') || /psycopg|sqlalchemy|mysqlclient|pymysql/.test(pyReq), 'SQL database');
  add(hasAny('stripe', '@stripe/stripe-js') || /\bstripe\b/.test(pyReq), 'Stripe');
  add(hasAny('openai', '@anthropic-ai/sdk', '@google/generative-ai', '@google/genai', 'ai', 'langchain', '@langchain/core', 'groq-sdk') || /openai|anthropic|langchain|google-generativeai|google-genai|groq/.test(pyReq), 'AI/LLM');

  const pubspec = p.byName('pubspec.yaml').find((f) => /\bflutter:/.test(p.read(f) || ''));
  if (pubspec) fw.add('Flutter');
  const androidManifests = p.files.filter((f) => /(^|\/)AndroidManifest\.xml$/.test(f.path) && !/\/build\//.test(f.path)).map((f) => f.path);
  const iosPlists = p.files.filter((f) => /(^|\/)Info\.plist$/.test(f.path) && !/\/(build|Pods)\//.test(f.path)).map((f) => f.path);
  if (androidManifests.length) fw.add('Android');
  if (iosPlists.length || p.dirs.some((d) => d.endsWith('.xcodeproj'))) fw.add('iOS');

  const isTest = (f) => /(^|\/)(test|tests|__tests__|spec|specs|e2e|fixtures?|__mocks__)\/|\.(test|spec)\.[cm]?[jt]sx?$/.test(f);
  const jsFiles = p.byExt('.js', '.mjs', '.cjs', '.ts', '.mts', '.cts').filter((f) => !isTest(f));
  const expressEntries = [];
  for (const f of jsFiles) {
    const c = p.read(f) || '';
    const m = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[\w.<>]+\s*)?=\s*express\s*\(\s*\)/.exec(c);
    if (m) expressEntries.push({ file: f, appVar: m[1], index: m.index });
  }
  const flaskApps = [];
  const fastapiApps = [];
  for (const f of pyFiles) {
    const c = p.read(f) || '';
    const m = /^([A-Za-z_]\w*)\s*=\s*Flask\(/m.exec(c);
    if (m) flaskApps.push({ file: f, appVar: m[1], index: m.index });
    const n = /^([A-Za-z_]\w*)\s*=\s*FastAPI\(/m.exec(c);
    if (n) fastapiApps.push({ file: f, appVar: n[1], index: n.index });
  }
  const djangoSettings = pyFiles.filter((f) => /(^|\/)settings(\.py|\/[^/]+\.py)$/.test(f) && /INSTALLED_APPS|SECRET_KEY|DEBUG\s*=/.test(p.read(f) || ''));

  const nextPkgs = pkgs.filter((k) => (k.json.dependencies || {}).next || (k.json.devDependencies || {}).next);
  const isApp = ['React Native', 'Expo', 'Flutter', 'Android', 'iOS', 'Capacitor/Ionic'].some((x) => fw.has(x));
  const hasBackend = expressEntries.length > 0 || flaskApps.length > 0 || fastapiApps.length > 0 || djangoSettings.length > 0 || nextPkgs.length > 0 || ['Fastify', 'Koa', 'Hono', 'NestJS', 'Nuxt', 'SvelteKit', 'Remix/React Router'].some((x) => fw.has(x)) || p.files.some((f) => /(^|\/)(api|functions|netlify\/functions|supabase\/functions)\//.test(f.path) && /\.(js|ts|py)$/.test(f.path));
  const hasHtml = p.files.some((f) => /\.html?$/.test(f.path) && !f.skipped);
  const isStatic = !hasBackend && hasHtml && pkgs.length === 0 && pyFiles.length === 0;
  const tsProject = p.byName('tsconfig.json').length > 0;

  return {
    pkgs, deps, has, hasAny, frameworks: fw, expressEntries, flaskApps, fastapiApps, djangoSettings,
    nextPkgs, androidManifests, iosPlists, pubspec, isApp, hasBackend, isStatic, hasHtml, tsProject,
    suggestedMode: isApp ? 'app' : 'web',
    deploy: { vercel: p.exists('vercel.json'), netlify: p.exists('netlify.toml') || p.exists('_headers') || p.exists('_redirects') },
    usesDotenv: has('dotenv') || /python-dotenv/.test(pyReq),
    pyReq, isTest,
  };
}

module.exports = { detect, safeJSON };
