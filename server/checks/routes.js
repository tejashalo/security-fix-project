'use strict';
/**
 * Route-level analysis: admin protection, authentication, access control (IDOR /
 * mass assignment), private data exposure, input validation, CSRF, webhooks.
 * Supports Express (incl. routers mounted from other files), Next.js API routes,
 * Flask, FastAPI and Django.
 */
const { posix, matchParen } = require('../lib/util');

const ROUTE_AUTH = /\b(auth\w*|\w*Auth(?:enticate|orize|enticated|Guard|Middleware|Required|User)?\b|protect\w*|\w+Protect\w*|verify(?!Webhook)\w*|ensure[A-Z]\w*|require[A-Z]\w*|isLogged\w*|isAuth\w*|isAdmin\w*|\w*[aA]dmin(?:Only|Guard|Middleware|Required|Check)\w*|passport\.authenticate|checkJwt|jwtCheck|expressjwt|expressJwt|jwtAuth|jwtMiddleware|withAuth|clerk\w*|ClerkExpress\w*|guard\w*|\w+Guard|validateToken|validateUser|checkAuth|checkRole|hasRole|permit\w*|loggedIn\w*|mustBeLoggedIn|vibeguardRequireAdmin)\b/;
const GLOBAL_AUTH = /\b(auth\w*Middleware|authenticate\w*|requireAuth\w*|ensureAuth\w*|isAuthenticated|verifyToken|verifyJwt|verifyJWT|checkJwt|jwtCheck|expressjwt|expressJwt|clerkMiddleware|ClerkExpressRequireAuth|requireLogin|loginRequired|protect|authMiddleware|auth)\s*(\(|,|\))/;
const ROLE_CHECK = /\b(isAdmin|requireAdmin|adminOnly|admin\w*(Middleware|Guard|Required|Check)|checkRole|hasRole|requireRole|authorize\s*\(|roles?\s*[=:]|permit\s*\(|vibeguardRequireAdmin)|role\s*[!=]==?\s*['"`]admin|['"`]admin['"`]\s*[!=]==?\s*\w+\.role|is_admin|roles\.includes\(\s*['"`]admin/i;
const ADMIN_PATH = /(^|\/)(admin|administrator|superuser|staff|internal|backoffice|manage)(\/|$|-|_)/i;
const PUBLIC_PATH = /(login|signin|sign-in|logout|signout|register|signup|sign-up|oauth|callback|forgot|reset|verify|confirm|health|healthz|status|ping|webhook|public|contact|newsletter|subscribe|csrf|refresh|token|otp|magic|docs|swagger|favicon|robots|sitemap|waitlist|feedback)/i;
const PRIVATE_GET = /(\/me\b|\/users?\b|account|profile|orders?\b|dashboard|settings|billing|payments?|invoices?|private|messages?|notes?|documents?|files?|uploads?|customers?|transactions?|wallet|history)/i;
const HANDLER_START = /(?:async\s*)?\(\s*\{?\s*(?:req|request|_req|_)\b|(?:async\s+)?function\s*[\w$]*\s*\(|\b(?:req|request)\s*=>|(?:async\s*)?\(\s*\w+\s*,\s*\w+\s*(?:,\s*\w+\s*)?\)\s*=>|\basyncHandler\(|\bcatchAsync\(|\bwrapAsync\(|\b[\w$]+Controller\.\w+|\b[\w$]+\.(?:controller|handler)\b/;
const AUTH_LIBS = ['passport', 'jsonwebtoken', 'jose', 'express-session', 'cookie-session', 'next-auth', '@auth/core', '@auth/express', '@clerk/nextjs', '@clerk/express', '@clerk/clerk-sdk-node', '@clerk/clerk-react', '@supabase/supabase-js', '@supabase/ssr', 'firebase', 'firebase-admin', 'lucia', 'better-auth', '@kinde-oss/kinde-auth-nextjs', 'express-openid-connect', '@auth0/nextjs-auth0', 'express-jwt', 'passport-jwt', 'iron-session', 'appwrite', '@descope/node-sdk', 'stytch'];
const VALIDATION_LIBS = ['zod', 'joi', 'yup', 'express-validator', 'celebrate', 'ajv', 'class-validator', 'valibot', '@sinclair/typebox', 'superstruct', '@vinejs/vine', 'fastest-validator', 'arktype', 'validator', '@hapi/joi'];
const CSRF_LIBS = ['csurf', 'csrf-csrf', 'lusca', 'tiny-csrf', '@dr.pogodin/csurf', 'csrf-sync', 'csrf'];

function joinPath(a, b) {
  const s = `${a || ''}/${b || ''}`.replace(/\/+/g, '/');
  return s.length > 1 ? s.replace(/\/$/, '') : s;
}

function resolveImport(p, fromFile, spec) {
  if (!spec.startsWith('.')) return null;
  const base = posix.normalize(posix.join(posix.dirname(fromFile), spec));
  for (const cand of [base, ...['.js', '.ts', '.mjs', '.cjs'].map((e) => base + e), ...['index.js', 'index.ts'].map((e) => base + '/' + e)]) {
    if (p.exists(cand)) return cand;
  }
  if (/\.js$/.test(base) && p.exists(base.replace(/\.js$/, '.ts'))) return base.replace(/\.js$/, '.ts');
  return null;
}

function parseExpressFile(p, file) {
  const content = p.read(file) || '';
  if (!/express|Router\s*\(/.test(content)) return null;
  const receivers = new Set();
  const rv = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:express\s*\(\s*\)|(?:express\.)?Router\s*\(|new\s+Router\s*\()/g;
  let m;
  while ((m = rv.exec(content))) receivers.add(m[1]);
  if (!receivers.size) ['app', 'router', 'routes', 'api', 'server'].forEach((r) => receivers.add(r));

  const imports = new Map();
  const ir = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)|import\s+([A-Za-z_$][\w$]*)\s+from\s+['"]([^'"]+)['"]/g;
  while ((m = ir.exec(content))) {
    const name = m[1] || m[3], spec = m[2] || m[4];
    const target = resolveImport(p, file, spec);
    if (target) imports.set(name, target);
  }

  const globalAuth = []; // { receiver, index }
  const gu = /\b([A-Za-z_$][\w$]*)\s*\.\s*use\s*\(\s*(?!['"`])/g;
  while ((m = gu.exec(content))) {
    if (!receivers.has(m[1])) continue;
    const open = content.indexOf('(', m.index + m[1].length);
    const close = matchParen(content, open);
    const args = content.slice(open + 1, close > 0 ? close : open + 200);
    if (/passport\.(initialize|session)|express\.|cors\(|helmet|session\(|cookieParser|morgan|compression|bodyParser|applyVibeGuard|vibeguard/i.test(args) && !GLOBAL_AUTH.test(args.replace(/express-session|cookieParser/g, ''))) continue;
    if (GLOBAL_AUTH.test(args)) globalAuth.push({ receiver: m[1], index: m.index, role: ROLE_CHECK.test(args) });
  }

  const routes = [];
  const re = /\b([A-Za-z_$][\w$]*)\s*\.\s*(get|post|put|patch|delete|all|use)\s*\(\s*(['"`])([^'"`\n]*)\3\s*,/g;
  while ((m = re.exec(content))) {
    if (!receivers.has(m[1])) continue;
    const open = content.indexOf('(', m.index + m[1].length);
    const close = matchParen(content, open);
    if (close < 0) continue;
    const argsStart = re.lastIndex;
    const args = content.slice(argsStart, close);
    const h = args.search(HANDLER_START);
    let mwText, body = '', lastArg = null;
    if (m[2] === 'use') {
      const parts = args.split(',');
      lastArg = parts[parts.length - 1].trim();
      mwText = parts.slice(0, -1).join(',');
      if (h >= 0) { mwText = args.slice(0, h); body = args.slice(h); lastArg = null; }
    } else if (h >= 0) { mwText = args.slice(0, h); body = args.slice(h); }
    else { const parts = args.split(','); mwText = parts.slice(0, -1).join(','); body = parts[parts.length - 1]; }
    routes.push({
      file, receiver: m[1], method: m[2], path: m[4], index: m.index,
      afterPathIndex: argsStart, handlerIndex: h >= 0 ? argsStart + h : (lastArg ? argsStart + args.lastIndexOf(lastArg) : -1),
      mwText, body, lastArgName: lastArg && /^[A-Za-z_$][\w$]*$/.test(lastArg) ? lastArg : null,
      routeAuth: ROUTE_AUTH.test(mwText.replace(/express\.\w+\([^)]*\)/g, '')),
      routeRole: ROLE_CHECK.test(mwText) || ROLE_CHECK.test(body.slice(0, 600)),
      globallyProtected: globalAuth.some((g) => g.receiver === m[1] && g.index < m.index),
      globalRole: globalAuth.some((g) => g.receiver === m[1] && g.index < m.index && g.role),
    });
  }
  return { file, content, routes, imports };
}

module.exports = {
  id: 'routes',
  title: 'Checking authentication, admin routes and access control',
  async run(ctx) {
    const { p, det } = ctx;
    const jsFiles = p.codeFiles((x) => /\.(m|c)?(js|ts)$/.test(x) && !/vibeguard-security/.test(x) && !det.isTest(x)).map((f) => f.path);
    const parsed = jsFiles.map((f) => parseExpressFile(p, f)).filter((x) => x && x.routes.length);
    const allRoutes = [];
    const hasAuthLib = det.hasAny(...AUTH_LIBS) || /flask[_-]login|flask[_-]jwt|djangorestframework|django\b|fastapi[-_]users|authlib|pyjwt|python-jose/.test(det.pyReq);
    const hasValidation = det.hasAny(...VALIDATION_LIBS) || /pydantic|marshmallow|wtforms|cerberus|fastapi|django/.test(det.pyReq);
    const canFixExpress = det.expressEntries.length > 0;

    // ---- resolve router mounts: app.use('/admin', auth, adminRouter) ----
    const mounts = new Map(); // targetFile -> { prefix, auth, role, route }
    for (const pf of parsed) {
      for (const r of pf.routes) {
        if (r.method === 'use' && r.lastArgName && pf.imports.has(r.lastArgName)) {
          const target = pf.imports.get(r.lastArgName);
          if (!mounts.has(target)) mounts.set(target, { prefix: r.path, auth: r.routeAuth || r.globallyProtected, role: r.routeRole || r.globalRole, route: r });
        }
      }
    }
    const fixedMounts = new Set();
    const editsByFile = new Map();
    const pushEdit = (file, e) => { if (!editsByFile.has(file)) editsByFile.set(file, []); editsByFile.get(file).push(e); };

    const adminFix = (r, finding) => {
      if (!canFixExpress) return;
      // insert after existing auth middleware (so req.user is set), otherwise right after the path
      const insertAt = r.routeAuth && r.handlerIndex > 0 ? r.handlerIndex : r.afterPathIndex;
      const text = r.routeAuth && r.handlerIndex > 0 ? 'vibeguardRequireAdmin, ' : ' vibeguardRequireAdmin,';
      pushEdit(r.file, { index: insertAt, old: '', new: text, finding, summary: 'Added vibeguardRequireAdmin: only users whose role is "admin" get through (fails closed with 401/403).' });
      ctx._adminImports = ctx._adminImports || new Set();
      ctx._adminImports.add(r.file);
    };

    // mounts first (fix at mount site protects every route inside)
    for (const [target, mt] of mounts) {
      const r = mt.route;
      const isAdmin = ADMIN_PATH.test(mt.prefix) || /admin/i.test(posix.basename(target));
      const inner = parsed.find((x) => x.file === target);
      const innerAuth = inner && inner.routes.length && inner.routes.every((x) => x.routeAuth || x.globallyProtected);
      if (isAdmin && !mt.role && innerAuth) continue; // routes log users in themselves — guard each route after its auth middleware
      if (isAdmin && !mt.role) {
        const fd = ctx.at(r.file, r.index, {
          category: 'admin', severity: 'high',
          title: mt.auth ? `Admin routes under "${mt.prefix}" only check login, not admin role` : `Admin routes under "${mt.prefix}" are open to everyone`,
          why: mt.auth ? 'Any signed-up user can call these admin endpoints — there is no check that they are actually an admin.' : 'Anyone on the internet can call these admin endpoints. No login is required.',
          fix: 'Add server-side middleware that checks the user\'s role is admin before the router.',
        });
        adminFix(r, fd);
        fixedMounts.add(target);
        mt.role = true;
        mt.auth = true;
      }
    }

    for (const pf of parsed) {
      const mount = mounts.get(pf.file);
      const unauthMut = [], privateGets = [];
      for (const r of pf.routes) {
        if (r.method === 'use' && r.lastArgName && pf.imports.has(r.lastArgName)) continue;
        const prefix = mount ? mount.prefix : '';
        const full = joinPath(prefix, r.path);
        const protectedAuth = r.routeAuth || r.globallyProtected || (mount && mount.auth);
        const protectedRole = r.routeRole || r.globalRole || (mount && mount.role);
        const route = { ...r, full, protectedAuth, protectedRole };
        allRoutes.push(route);
        const isAdmin = ADMIN_PATH.test(full) || (!mount && /admin/i.test(posix.basename(pf.file)) && r.method !== 'use');
        if (isAdmin && !protectedRole && !(mount && fixedMounts.has(pf.file))) {
          const fd = ctx.at(pf.file, r.index, {
            category: 'admin', severity: 'high',
            title: `${r.method.toUpperCase()} ${full} — admin route ${protectedAuth ? 'without an admin role check' : 'is not protected'}`,
            why: protectedAuth ? 'Logged-in users who are not admins can still call this admin endpoint.' : 'Anyone can call this admin endpoint without logging in.',
            fix: 'Check on the server that req.user is an admin before running the handler.',
          });
          adminFix(r, fd);
          continue;
        }
        if (['post', 'put', 'patch', 'delete'].includes(r.method) && !protectedAuth && !PUBLIC_PATH.test(full)) unauthMut.push(route);
        if (r.method === 'get' && !protectedAuth && PRIVATE_GET.test(full) && !PUBLIC_PATH.test(full)) privateGets.push(route);

        // ---- access control: IDOR / mass assignment / role from body ----
        const body = r.body || '';
        if (/(?:role|isAdmin|is_admin|admin|permissions?)\s*:\s*req\.body\.\w+/.test(body)) {
          ctx.at(pf.file, r.index, {
            category: 'access', severity: 'high', title: `${r.method.toUpperCase()} ${full} lets the client set its own role`,
            why: 'The role/admin flag comes from the request body, so a user can simply send {"role":"admin"} and promote themselves.',
            fix: 'Never take role/isAdmin from the request. Set it on the server (default "user"); only an admin endpoint should change roles.',
          });
        } else if (/\.(create|insertOne|insertMany|update\w*|findByIdAndUpdate|findOneAndUpdate|upsert|bulkCreate|insert)\s*\(\s*(?:[^,()]*,\s*)?(?:req\.body\s*[,)]|\{\s*\.\.\.req\.body)|new\s+[A-Z]\w*\(\s*req\.body\s*\)|Object\.assign\(\s*\w+\s*,\s*req\.body\s*\)/.test(body)) {
          ctx.at(pf.file, r.index, {
            category: 'access', severity: 'high', title: `${r.method.toUpperCase()} ${full} saves the whole request body (mass assignment)`,
            why: 'Passing req.body straight to the database lets users set fields you never intended — role, isAdmin, balance, ownerId, verified…',
            fix: 'Pick allowed fields explicitly, e.g. `const { name, bio } = req.body;` or validate with a zod schema using .strict().',
          });
        }
        const idUse = /req\.(params|query|body)\.(\w*(?:id|Id|ID)\w*)/.exec(body);
        const dbCall = /\.(findById|findOne|findByPk|findUnique|findFirst|update\w*|delete\w*|destroy|remove\w*|query|from\(|doc\(|where)\s*\(/.test(body);
        const ownerCheck = /req\.(user|auth|session)|res\.locals\.user|userId\s*[:=]|user_id|ownerId|owner|createdBy|author(Id)?\s*[:=]|\.uid\b|currentUser|getUser|session\.user/.test(body);
        if (idUse && dbCall && !ownerCheck && !PUBLIC_PATH.test(full) && !/^\/?(products?|posts?|articles?|blog|categories|items?|public)/i.test(full.replace(/^\/api/, ''))) {
          ctx.at(pf.file, r.index, {
            category: 'access', severity: protectedAuth ? 'medium' : 'high',
            title: `${r.method.toUpperCase()} ${full} may expose other users' data (IDOR)`,
            why: `The record is looked up with req.${idUse[1]}.${idUse[2]} but the handler never checks it belongs to the logged-in user. Changing the id in the URL could show or modify someone else's data.`,
            fix: 'Add the owner to the query, e.g. `findOne({ _id: req.params.id, userId: req.user.id })`, or return 404 when record.userId !== req.user.id.',
          });
        }
      }
      if (unauthMut.length) {
        ctx.at(pf.file, unauthMut[0].index, {
          category: 'auth', severity: 'high',
          title: `${unauthMut.length} endpoint(s) change data without requiring login`,
          snippet: unauthMut.slice(0, 6).map((r) => `${r.method.toUpperCase()} ${r.full}`).join(' · '),
          why: 'Anyone can create, edit or delete data through these endpoints — no account needed. Bots will find them.',
          fix: hasAuthLib
            ? 'Add your auth middleware to these routes (e.g. `router.post(\'/x\', requireAuth, handler)`) or protect the whole router with `router.use(requireAuth)`.'
            : 'Add an authentication system first (Clerk, Auth.js, Supabase Auth, Firebase Auth, or Passport/JWT), then require it on these routes.',
        });
      }
      if (privateGets.length) {
        ctx.at(pf.file, privateGets[0].index, {
          category: 'api', severity: 'medium',
          title: `${privateGets.length} endpoint(s) look private but don't require login`,
          snippet: privateGets.slice(0, 6).map((r) => `GET ${r.full}`).join(' · '),
          why: 'Routes with names like users/orders/profile/billing usually return personal data. Without auth anyone can read it.',
          fix: 'Require authentication and return only the current user\'s records.',
        });
      }
    }
    for (const [file, edits] of editsByFile) {
      // edits were computed on the current content, so apply them before adding the import
      if (ctx.applyEdits(file, edits)) ctx.ensureSecurityImport(file, ['vibeguardRequireAdmin']);
    }
    if ((ctx._adminImports || new Set()).size) ctx.note('vibeguardRequireAdmin expects your login middleware to set `req.user` with `role: "admin"` (or `isAdmin: true`). Admin routes now fail closed (401/403) until that is true.');

    // ---- Next.js API routes & server actions ----
    const nextMwAuth = p.files.some((f) => /(^|\/)(src\/)?(middleware|proxy)\.(ts|js)$/.test(f.path) && /clerkMiddleware|authMiddleware|withAuth|getToken|auth\(|NextAuth|updateSession|supabase|createServerClient|kinde|withMiddlewareAuth/.test(p.read(f.path) || ''));
    const nextApi = jsFiles.filter((f) => /(^|\/)pages\/api\/.+\.(js|ts)$|(^|\/)app\/(.+\/)?route\.(js|ts)$/.test(f));
    for (const f of nextApi) {
      const content = p.read(f) || '';
      const route = '/' + f.replace(/^.*?(pages\/|app\/)/, '').replace(/\/route\.(js|ts)$|\.(js|ts)$/, '').replace(/\/index$/, '');
      const mutates = /export\s+(async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b|export\s+const\s+(POST|PUT|PATCH|DELETE)\b|req\.method\s*===?\s*['"](POST|PUT|PATCH|DELETE)|export\s+default/.test(content);
      const authed = /getServerSession|auth\(\)|await\s+auth\b|getToken|currentUser|getAuth|clerkClient|supabase\.auth\.getUser|auth\.getUser|getUser\(|verifyIdToken|jwt\.verify|jwtVerify|requireAuth|withAuth|getSession|session\??\.user|cookies\(\)\.get\(\s*['"](token|session)/.test(content);
      const role = ROLE_CHECK.test(content);
      if (ADMIN_PATH.test(route) && !role) {
        ctx.add({ category: 'admin', severity: 'high', file: f, title: `Next.js admin API ${route} has no admin role check`, why: 'Admin API routes must verify on the server that the caller is an admin — hiding the button in the UI is not protection.', fix: 'At the top of the handler, get the session and return 403 unless session.user.role === "admin".' });
        continue;
      }
      if (/webhook/i.test(route)) continue;
      if (mutates && !authed && !PUBLIC_PATH.test(route)) {
        ctx.add({ category: 'auth', severity: nextMwAuth ? 'low' : 'high', file: f, title: `API route ${route} changes data without checking the user`,
          why: nextMwAuth ? 'Your middleware may protect it, but API routes should also verify the session themselves (middleware matchers are easy to get wrong).' : 'Anyone can call this endpoint directly with curl — no login needed.',
          fix: 'Get the session/user at the start of the handler and return 401 if missing; use the user id from the session, not from the request body.' });
      }
      if (!mutates && !authed && PRIVATE_GET.test(route) && !PUBLIC_PATH.test(route) && !nextMwAuth) {
        ctx.add({ category: 'api', severity: 'medium', file: f, title: `API route ${route} may return private data without login`, why: 'Route name suggests personal data; there is no session check.', fix: 'Verify the session and filter by the current user.' });
      }
      allRoutes.push({ full: route, protectedAuth: authed || nextMwAuth });
    }
    const nextAdminPages = p.codeFiles((x) => /(^|\/)(app|pages)\/(.*\/)?admin(\/|\.)/.test(x) && /\.(jsx|tsx|js|ts)$/.test(x) && !/\/api\//.test(x)).map((f) => f.path);
    for (const f of nextAdminPages.slice(0, 3)) {
      const c = p.read(f) || '';
      if (!ROLE_CHECK.test(c) && !nextMwAuth && !/redirect\(|notFound\(/.test(c)) {
        ctx.add({ category: 'admin', severity: 'medium', file: f, title: 'Admin page has no server-side role check', why: 'If the check happens only in the browser (or not at all), anyone can open the page and see admin data.', fix: 'Check the session role on the server (server component / middleware) and redirect non-admins.' });
      }
    }
    // Server actions
    for (const f of jsFiles.concat(p.byExt('.tsx', '.jsx'))) {
      const c = p.read(f) || '';
      if (!/^\s*['"]use server['"]/m.test(c)) continue;
      if (/(create|update|delete|insert|remove|upsert)\w*\(/.test(c) && !/auth\(|getServerSession|currentUser|getUser|getSession|session/.test(c)) {
        ctx.add({ category: 'auth', severity: 'high', file: f, title: 'Server actions modify data without checking the user', why: 'Server actions are public HTTP endpoints. Anyone can call them, not just your UI.', fix: 'Call your auth()/getSession() at the start of every action and verify ownership.' });
      }
    }

    // ---- React SPA admin routes protected only on the client ----
    for (const f of p.codeFiles((x) => /\.(jsx|tsx|vue)$/.test(x)).map((x) => x.path)) {
      const c = p.read(f) || '';
      const m = /path\s*[=:]\s*['"]\/admin/.exec(c);
      if (m && !det.hasBackend) {
        ctx.at(f, m.index, { category: 'admin', severity: 'medium', title: 'Admin area is protected only in the browser', why: 'A client-side route guard just hides the page. Anyone can call the underlying API/database directly.', fix: 'Enforce admin access where the data lives: database rules (Supabase RLS / Firebase rules with a role check) or a server endpoint that checks the role.' });
        break;
      }
    }

    // ---- Python frameworks ----
    for (const f of p.byExt('.py')) {
      const c = p.read(f) || '';
      const flaskRe = /@(\w+)\.(route|get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]([^)]*)\)\s*\n((?:\s*@[^\n]+\n)*)\s*(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)/g;
      let m;
      const unauth = [];
      while ((m = flaskRe.exec(c))) {
        const [, , kind, path, args, decorators, , params] = m;
        let methods = kind === 'route' ? ((/methods\s*=\s*\[([^\]]*)\]/.exec(args) || [])[1] || 'GET') : kind.toUpperCase();
        methods = methods.toUpperCase();
        const authed = /login_required|jwt_required|auth|token_required|roles_required|admin_required|permission|requires_|Depends\(\s*\w*(user|auth|token|verify|admin)|Security\(/i.test(decorators + args + params);
        const role = /admin|role|superuser|staff|permission/i.test(decorators + params);
        allRoutes.push({ full: path, protectedAuth: authed });
        if (ADMIN_PATH.test(path) && !role) {
          ctx.at(f, m.index, { category: 'admin', severity: 'high', title: `${path} — admin route ${authed ? 'without role check' : 'is not protected'}`, why: 'Admin endpoints must verify the user is an admin on the server.', fix: 'Add a decorator/dependency that checks current_user is an admin (e.g. @admin_required or Depends(require_admin)).' });
        } else if (/POST|PUT|PATCH|DELETE/.test(methods) && !authed && !PUBLIC_PATH.test(path)) unauth.push({ path, methods, index: m.index });
      }
      if (unauth.length) {
        ctx.at(f, unauth[0].index, { category: 'auth', severity: 'high', title: `${unauth.length} endpoint(s) change data without requiring login`, snippet: unauth.slice(0, 6).map((u) => `${u.methods.replace(/['"\s]/g, '')} ${u.path}`).join(' · '), why: 'Anyone can call these endpoints without an account.', fix: 'Add @login_required / @jwt_required (Flask) or a Depends(get_current_user) dependency (FastAPI).' });
      }
      const csrfEx = /@csrf_exempt/.exec(c);
      if (csrfEx) ctx.at(f, csrfEx.index, { category: 'csrf', severity: 'medium', title: 'View is exempt from CSRF protection', why: '@csrf_exempt lets other websites submit this form on behalf of logged-in users.', fix: 'Remove @csrf_exempt unless this is a webhook that verifies its own signature.' });
    }

    // ---- project-level: no auth at all ----
    const mutating = allRoutes.filter((r) => !PUBLIC_PATH.test(r.full || ''));
    if (det.hasBackend && mutating.length && !hasAuthLib && !allRoutes.some((r) => r.protectedAuth)) {
      ctx.add({ category: 'auth', severity: 'high', file: null, title: 'No authentication system found',
        why: 'The backend has endpoints but no login library or auth checks. Every endpoint is public.',
        fix: 'Use a proven auth provider instead of rolling your own: Clerk, Auth.js (NextAuth), Supabase Auth, Firebase Auth, Lucia/Better Auth, or Passport + bcrypt + httpOnly session cookies.' });
    }
    if (det.hasBackend || allRoutes.length) { ctx.checked('auth'); ctx.checked('admin'); ctx.checked('access'); ctx.checked('api'); }
    else {
      const baas = det.frameworks.has('Supabase') || det.frameworks.has('Firebase');
      for (const c of ['auth', 'admin', 'access', 'api']) ctx.na(c, baas ? 'No custom server routes. Access control lives in your Supabase RLS / Firebase rules (see Database).' : 'No server routes found.');
    }

    // ---- input validation ----
    const bodyRoutes = parsed.flatMap((pf) => pf.routes.filter((r) => /req\.(body|query|params)\./.test(r.body)).map((r) => ({ ...r })));
    if (bodyRoutes.length && !hasValidation) {
      ctx.at(bodyRoutes[0].file, bodyRoutes[0].index, {
        category: 'input', severity: 'medium', title: `${bodyRoutes.length} route(s) use request data with no validation library`,
        snippet: bodyRoutes.slice(0, 6).map((r) => `${r.method.toUpperCase()} ${r.path}`).join(' · '),
        why: 'Unvalidated input lets attackers send wrong types, huge strings, objects instead of strings ({"$ne":null}) or extra fields — the root of injection and logic bugs.',
        fix: "Validate every body/query with a schema, e.g. `const Body = z.object({ email: z.string().email().max(254), name: z.string().max(100) }).strict(); const data = Body.parse(req.body);`",
      });
    } else if (bodyRoutes.length || det.hasBackend) ctx.checked('input');
    // HTML forms that send passwords with GET
    for (const f of p.codeFiles((x) => /\.(html?|ejs|hbs|jsx|tsx|vue|svelte|php)$/.test(x)).map((x) => x.path)) {
      const c = p.read(f) || '';
      const re = /<form\b([^>]*)>([\s\S]{0,4000}?)<\/form>/gi;
      let m;
      const edits = [];
      while ((m = re.exec(c))) {
        const attrs = m[1];
        if (/type=["']password["']/i.test(m[2]) && (/method=["']get["']/i.test(attrs) || (!/method=/i.test(attrs) && /action=/i.test(attrs)))) {
          const fd = ctx.at(f, m.index, { category: 'input', severity: 'high', title: 'Login/password form submits with GET', why: 'GET puts the password in the URL — it ends up in browser history, server logs and analytics.', fix: 'Use method="post".' });
          const newAttrs = /method=["']get["']/i.test(attrs) ? attrs.replace(/method=["']get["']/i, 'method="post"') : attrs + ' method="post"';
          edits.push({ index: m.index, old: `<form${attrs}>`, new: `<form${newAttrs}>`, finding: fd, summary: 'Form now submits with POST.' });
        }
      }
      ctx.applyEdits(f, edits);
      if (/<(input|textarea)\b/i.test(c)) ctx.checked('input');
    }
    if (!ctx.status.has('input')) ctx.na('input', 'No forms or request handlers found.');

    // ---- CSRF ----
    const cookieAuth = det.hasAny('express-session', 'cookie-session') || jsFiles.some((f) => /res\.cookie\(\s*['"`](token|session|auth|jwt|access_token|sid)/i.test(p.read(f) || ''));
    if (cookieAuth && allRoutes.some((r) => ['post', 'put', 'patch', 'delete'].includes(r.method)) && !det.hasAny(...CSRF_LIBS)) {
      ctx.add({ category: 'csrf', severity: 'medium', file: det.expressEntries[0]?.file || null, title: 'Cookie-based login without CSRF protection',
        why: 'Browsers attach cookies automatically, so a malicious site can make a logged-in user\'s browser submit forms to your API.',
        fix: 'Keep cookies SameSite=Lax/Strict (VibeGuard sets this where it can) and add CSRF tokens with csrf-csrf for form posts.' });
    } else if (det.hasBackend) ctx.checked('csrf');
    else ctx.na('csrf', 'No server-side sessions found.');

    // ---- Webhooks ----
    let webhookSeen = false;
    for (const f of jsFiles.concat(p.byExt('.py'))) {
      const c = p.read(f) || '';
      if (!/webhook/i.test(f + c)) continue;
      const routeRe = /(\.(post|all)\s*\(\s*['"`][^'"`]*webhook[^'"`]*['"`]|@\w+\.(route|post)\(\s*['"][^'"]*webhook)/gi;
      const isWebhookFile = /webhook/i.test(f) && /(export\s+(async\s+)?function\s+POST|export\s+default|def\s+\w+\()/.test(c);
      const m = routeRe.exec(c);
      if (!m && !isWebhookFile) continue;
      webhookSeen = true;
      const stripe = /stripe/i.test(c);
      const verified = /constructEvent|constructEventAsync|construct_event|Webhook\.construct/.test(c);
      const genericVerified = /signature|hmac|createHmac|timingSafeEqual|svix|verifyWebhook|x-hub-signature|compare_digest|verify/i.test(c);
      if (stripe && !verified) {
        ctx.at(f, m ? m.index : 0, { category: 'webhooks', severity: 'critical', title: 'Stripe webhook does not verify the signature', why: 'Anyone can POST a fake "payment succeeded" event to this URL and get paid features for free.', fix: 'Use `stripe.webhooks.constructEvent(rawBody, req.headers["stripe-signature"], process.env.STRIPE_WEBHOOK_SECRET)` with the raw request body.' });
      } else if (!stripe && !genericVerified) {
        ctx.at(f, m ? m.index : 0, { category: 'webhooks', severity: 'medium', title: 'Webhook endpoint does not verify who sent it', why: 'Without a signature check, anyone can send fake events to this endpoint.', fix: 'Verify the provider\'s signature header with HMAC + timingSafeEqual (or the provider SDK) before trusting the payload.' });
      } else ctx.checked('webhooks');
    }
    if (!webhookSeen) ctx.na('webhooks', 'No webhook endpoints found.');
  },
};
