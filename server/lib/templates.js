'use strict';
/** Code that VibeGuard adds to user projects. All of it is dependency-free. */

const HEADER_LIST = [
  ['X-Content-Type-Options', 'nosniff'],
  ['X-Frame-Options', 'DENY'],
  ['Referrer-Policy', 'strict-origin-when-cross-origin'],
  ['Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()'],
  ['Cross-Origin-Opener-Policy', 'same-origin'],
  ['X-DNS-Prefetch-Control', 'off'],
];
const CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'";

function expressSecurityModule(kind) {
  const ts = kind === 'ts';
  const esm = kind === 'esm' || ts;
  const A = ts ? ': any' : '';
  const body = `// ---------------------------------------------------------------------------
// vibeguard-security — added by VibeGuard (https://github.com/tejashalo/security-fix-project)
// Zero dependencies. Security headers, rate limiting, CORS allow-list and an
// admin guard for Express. Tune the settings with environment variables:
//   ALLOWED_ORIGINS="https://myapp.com,https://www.myapp.com"
//   RATE_LIMIT_MAX=300            (requests per 15 min per IP, all routes)
//   AUTH_RATE_LIMIT_MAX=10        (login/signup/reset attempts per 15 min per IP)
//   AI_RATE_LIMIT_MAX=30          (AI/LLM endpoints per 15 min per IP)
//   VIBEGUARD_CSP_ENFORCE=1       (switch Content-Security-Policy from report-only to enforced)
// If you deploy behind a proxy (Render, Railway, Heroku, Nginx), also call
// app.set('trust proxy', 1) so rate limits use the real client IP.
// ---------------------------------------------------------------------------

const WINDOW_MS = 15 * 60 * 1000;
const HEADERS${ts ? ': [string, string][]' : ''} = ${JSON.stringify(HEADER_LIST)};
const CSP = ${JSON.stringify(CSP)};

function vibeguardSecurityHeaders() {
  return function (req${A}, res${A}, next${A}) {
    for (const [k, v] of HEADERS) res.setHeader(k, v);
    res.setHeader(process.env.VIBEGUARD_CSP_ENFORCE === '1' ? 'Content-Security-Policy' : 'Content-Security-Policy-Report-Only', CSP);
    const proto = req.headers['x-forwarded-proto'];
    if (req.secure || proto === 'https') res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.removeHeader('X-Powered-By');
    next();
  };
}

function vibeguardRateLimit(opts${ts ? ': { windowMs?: number; max?: number; message?: string }' : ''} = {}) {
  const windowMs = opts.windowMs || WINDOW_MS;
  const max = opts.max || 300;
  const hits = new Map();
  const timer = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset <= now) hits.delete(k);
  }, windowMs);
  if (timer.unref) timer.unref();
  return function (req${A}, res${A}, next${A}) {
    const key = req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
    const now = Date.now();
    let entry = hits.get(key);
    if (!entry || entry.reset <= now) { entry = { count: 0, reset: now + windowMs }; hits.set(key, entry); }
    entry.count++;
    res.setHeader('RateLimit-Limit', String(max));
    res.setHeader('RateLimit-Remaining', String(Math.max(0, max - entry.count)));
    if (entry.count > max) {
      res.setHeader('Retry-After', String(Math.ceil((entry.reset - now) / 1000)));
      return res.status(429).json({ error: opts.message || 'Too many requests, please try again later.' });
    }
    next();
  };
}

// Read lazily so values loaded from .env after this module is imported still apply.
const allowedOrigins = () => (process.env.ALLOWED_ORIGINS || 'http://localhost:3000,http://localhost:5173')
  .split(',').map((s) => s.trim()).filter(Boolean);

const vibeguardCorsOptions = {
  origin(origin${ts ? ': string | undefined' : ''}, cb${A}) {
    // Requests with no Origin header (curl, mobile apps, same-origin) are allowed.
    if (!origin || allowedOrigins().includes(origin)) return cb(null, true);
    return cb(null, false);
  },
  credentials: true,
};

/** Fails closed: requires your auth middleware to have set req.user (or req.auth / req.session.user) with an admin role. */
function vibeguardRequireAdmin(req${A}, res${A}, next${A}) {
  const user = req.user || req.auth || (req.session && req.session.user);
  const isAdmin = !!user && (user.role === 'admin' || user.isAdmin === true || user.is_admin === true ||
    (Array.isArray(user.roles) && user.roles.includes('admin')));
  if (!isAdmin) return res.status(user ? 403 : 401).json({ error: user ? 'Forbidden' : 'Unauthorized' });
  next();
}

const AUTH_PATHS = ['/login', '/signin', '/sign-in', '/register', '/signup', '/sign-up', '/auth', '/forgot-password', '/reset-password', '/verify', '/otp',
  '/api/login', '/api/signin', '/api/register', '/api/signup', '/api/auth', '/api/forgot-password', '/api/reset-password', '/api/verify', '/api/otp'];
const AI_PATHS = ['/api/chat', '/api/ai', '/api/generate', '/api/completion', '/api/completions', '/api/llm', '/api/ask', '/chat', '/generate'];

function applyVibeGuard(app${A}, options${ts ? ': { headers?: boolean; rateLimit?: boolean }' : ''} = {}) {
  app.disable('x-powered-by');
  if (options.headers !== false) app.use(vibeguardSecurityHeaders());
  if (options.rateLimit !== false) {
    app.use(AUTH_PATHS, vibeguardRateLimit({ max: Number(process.env.AUTH_RATE_LIMIT_MAX || 10), message: 'Too many attempts. Please wait 15 minutes and try again.' }));
    app.use(AI_PATHS, vibeguardRateLimit({ max: Number(process.env.AI_RATE_LIMIT_MAX || 30) }));
    app.use(vibeguardRateLimit({ max: Number(process.env.RATE_LIMIT_MAX || 300) }));
  }
}
`;
  const exportsLine = esm
    ? `\nexport { applyVibeGuard, vibeguardSecurityHeaders, vibeguardRateLimit, vibeguardCorsOptions, vibeguardRequireAdmin };\n`
    : `\nmodule.exports = { applyVibeGuard, vibeguardSecurityHeaders, vibeguardRateLimit, vibeguardCorsOptions, vibeguardRequireAdmin };\n`;
  return (esm ? '' : "'use strict';\n") + body + exportsLine;
}

function nextMiddleware(ts) {
  return `// Added by VibeGuard: security headers for every page and API route.
// Content-Security-Policy starts in report-only mode so nothing breaks;
// set VIBEGUARD_CSP_ENFORCE=1 once your browser console shows no CSP reports.
import { NextResponse } from 'next/server';${ts ? "\nimport type { NextRequest } from 'next/server';" : ''}

const HEADERS = ${JSON.stringify([...HEADER_LIST, ['Strict-Transport-Security', 'max-age=31536000; includeSubDomains']])};
const CSP = ${JSON.stringify(CSP.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'"))};

export function middleware(${ts ? '_request: NextRequest' : '_request'}) {
  const res = NextResponse.next();
  for (const [k, v] of HEADERS) res.headers.set(k, v);
  res.headers.set(process.env.VIBEGUARD_CSP_ENFORCE === '1' ? 'Content-Security-Policy' : 'Content-Security-Policy-Report-Only', CSP);
  return res;
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
`;
}

function staticHeadersFile() {
  return `# Added by VibeGuard — security headers for Netlify / Cloudflare Pages.
/*
${HEADER_LIST.map(([k, v]) => `  ${k}: ${v}`).join('\n')}
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  Content-Security-Policy-Report-Only: ${CSP}
`;
}

function vercelHeaders() {
  return [{ source: '/(.*)', headers: [...HEADER_LIST, ['Strict-Transport-Security', 'max-age=31536000; includeSubDomains']].map(([key, value]) => ({ key, value })) }];
}

function flaskBlock(appVar) {
  return `

# --- Added by VibeGuard: security headers + simple rate limiting -------------
# For multi-server deployments, switch to Flask-Limiter with Redis.
import time as _vg_time
from flask import request as _vg_request, jsonify as _vg_jsonify

_VG_HITS = {}
_VG_WINDOW = 15 * 60
_VG_AUTH_PATHS = ("/login", "/signin", "/register", "/signup", "/auth", "/forgot", "/reset", "/api/login", "/api/register", "/api/auth")


@${appVar}.before_request
def _vibeguard_rate_limit():
    ip = _vg_request.headers.get("X-Forwarded-For", _vg_request.remote_addr or "unknown").split(",")[0].strip()
    strict = _vg_request.path.startswith(_VG_AUTH_PATHS) and _vg_request.method == "POST"
    key = (ip, "auth" if strict else "all")
    limit = 10 if strict else 300
    now = _vg_time.time()
    count, reset = _VG_HITS.get(key, (0, now + _VG_WINDOW))
    if reset <= now:
        count, reset = 0, now + _VG_WINDOW
    count += 1
    _VG_HITS[key] = (count, reset)
    if count > limit:
        return _vg_jsonify(error="Too many requests, please try again later."), 429


@${appVar}.after_request
def _vibeguard_security_headers(response):
${HEADER_LIST.map(([k, v]) => `    response.headers["${k}"] = "${v}"`).join('\n')}
    response.headers["Content-Security-Policy-Report-Only"] = "${CSP}"
    if _vg_request.is_secure or _vg_request.headers.get("X-Forwarded-Proto") == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response
# -----------------------------------------------------------------------------
`;
}

function fastapiBlock(appVar) {
  return `

# --- Added by VibeGuard: security headers + simple rate limiting -------------
import time as _vg_time
from fastapi import Request as _VGRequest
from fastapi.responses import JSONResponse as _VGJSONResponse

_VG_HITS = {}
_VG_WINDOW = 15 * 60
_VG_AUTH_PATHS = ("/login", "/signin", "/register", "/signup", "/auth", "/token", "/api/login", "/api/register", "/api/auth")


@${appVar}.middleware("http")
async def _vibeguard_security(request: _VGRequest, call_next):
    ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown").split(",")[0].strip()
    strict = request.url.path.startswith(_VG_AUTH_PATHS) and request.method == "POST"
    key = (ip, "auth" if strict else "all")
    limit = 10 if strict else 300
    now = _vg_time.time()
    count, reset = _VG_HITS.get(key, (0, now + _VG_WINDOW))
    if reset <= now:
        count, reset = 0, now + _VG_WINDOW
    _VG_HITS[key] = (count + 1, reset)
    if count + 1 > limit:
        return _VGJSONResponse({"error": "Too many requests, please try again later."}, status_code=429)
    response = await call_next(request)
${HEADER_LIST.map(([k, v]) => `    response.headers["${k}"] = "${v}"`).join('\n')}
    response.headers["Content-Security-Policy-Report-Only"] = "${CSP}"
    if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response
# -----------------------------------------------------------------------------
`;
}

const DJANGO_BLOCK = `

# --- Added by VibeGuard: production security settings ------------------------
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
if not DEBUG:
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SECURE_SSL_REDIRECT = os.environ.get("DJANGO_SECURE_SSL_REDIRECT", "True") == "True"
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
# -----------------------------------------------------------------------------
`;

const GITIGNORE_BLOCK = [
  '# --- added by VibeGuard: never commit secrets ---',
  '.env', '.env.*', '!.env.example', '*.pem', '*.key', '*.p12', '*.pfx', '*.jks', '*.keystore',
  'service-account*.json', '*-firebase-adminsdk-*.json', 'credentials.json', '.vscode/sftp.json',
  '*.sqlite', '*.sqlite3', '*.db', '*.sql.gz', '*.dump', '*.log', 'npm-debug.log*', '.DS_Store',
  'node_modules/', '_vibeguard_quarantine/', '.vibeguard/',
];

const DOCKERIGNORE = `# Added by VibeGuard: keep secrets and junk out of Docker images
.git
.env
.env.*
!.env.example
node_modules
npm-debug.log*
*.pem
*.key
*.sqlite
*.db
coverage
.vscode
.idea
_vibeguard_quarantine
.vibeguard
`;

module.exports = { expressSecurityModule, nextMiddleware, staticHeadersFile, vercelHeaders, flaskBlock, fastapiBlock, DJANGO_BLOCK, GITIGNORE_BLOCK, DOCKERIGNORE, HEADER_LIST, CSP };
