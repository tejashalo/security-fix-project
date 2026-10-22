'use strict';
/** Every audit area VibeGuard reports on. `requested` = on the original checklist. */
const CATEGORIES = [
  { id: 'secrets', title: 'Hide API keys & secrets', requested: true, blurb: 'Hardcoded keys, tokens and passwords in code.' },
  { id: 'env', title: 'Environment variables', requested: true, blurb: '.env handling, .gitignore, public-prefixed secrets, insecure fallbacks.' },
  { id: 'admin', title: 'Protect admin routes', requested: true, blurb: 'Admin endpoints must check the user is an admin on the server.' },
  { id: 'auth', title: 'Proper authentication', requested: true, blurb: 'Endpoints that change data must require a logged-in user.' },
  { id: 'access', title: 'Access control (users only reach their own data)', requested: true, blurb: 'IDOR, mass assignment, role escalation.' },
  { id: 'input', title: 'Form sanitisation & input validation', requested: true, blurb: 'Validate and limit everything users send.' },
  { id: 'xss', title: 'XSS protection', requested: true, blurb: 'Untrusted data rendered as HTML.' },
  { id: 'ratelimit', title: 'Rate limiting', requested: true, blurb: 'Stops brute-force logins, spam and API-bill attacks.' },
  { id: 'api', title: 'Secure API endpoints', requested: true, blurb: 'Body limits, private data exposure, GraphQL introspection.' },
  { id: 'cors', title: 'CORS settings', requested: true, blurb: 'Which websites may call your API from a browser.' },
  { id: 'headers', title: 'Security headers', requested: true, blurb: 'CSP, HSTS, clickjacking and sniffing protection.' },
  { id: 'debug', title: 'Debug mode off', requested: true, blurb: 'Debug flags, source maps, verbose error pages.' },
  { id: 'deps', title: 'Update dependencies & known vulnerabilities', requested: true, blurb: 'Outdated and vulnerable packages.' },
  { id: 'unused', title: 'Remove unused packages', requested: true, blurb: 'Packages installed but never used.' },
  { id: 'exposed', title: 'Exposed files', requested: true, blurb: 'Keys, dumps, backups and logs that should never be public.' },
  { id: 'database', title: 'Secure the database', requested: true, blurb: 'Row Level Security, Firebase rules, exposed ports, TLS.' },
  { id: 'passwords', title: 'Hash passwords properly', requested: true, blurb: 'bcrypt/argon2 with a safe cost, never plaintext or MD5/SHA.' },
  { id: 'git', title: 'Git history leaked secrets', requested: true, blurb: 'Secrets that were committed in the past, even if deleted now.' },
  { id: 'injection', title: 'Injection attacks (SQL, NoSQL, command, code)', requested: false, blurb: 'User input reaching queries, shells or eval.' },
  { id: 'csrf', title: 'CSRF protection', requested: false, blurb: 'Forged requests using a logged-in user\'s cookies.' },
  { id: 'sessions', title: 'Cookies, sessions & JWT', requested: false, blurb: 'Cookie flags, token expiry, token storage.' },
  { id: 'supply', title: 'Supply chain (fake & look-alike packages)', requested: false, blurb: 'AI-hallucinated or typo-squatted package names.' },
  { id: 'uploads', title: 'File uploads', requested: false, blurb: 'Size limits, file types and safe file names.' },
  { id: 'ssrf', title: 'SSRF, open redirects & path traversal', requested: false, blurb: 'User-controlled URLs and file paths.' },
  { id: 'errors', title: 'Error handling & logging leaks', requested: false, blurb: 'Stack traces to users, secrets in logs.' },
  { id: 'webhooks', title: 'Webhook signature verification', requested: false, blurb: 'Fake payment/webhook events.' },
  { id: 'ai', title: 'AI / LLM app risks', requested: false, blurb: 'Keys in the browser, prompt injection, cost abuse.' },
  { id: 'https', title: 'HTTPS & transport security', requested: false, blurb: 'Plain-HTTP API calls and TLS settings.' },
  { id: 'deploy', title: 'Docker & deployment config', requested: false, blurb: 'Root containers, baked-in secrets, .dockerignore.' },
  { id: 'mobile', title: 'Mobile app security', requested: false, blurb: 'Manifest/Info.plist flags, token storage, WebViews.', modes: ['app'] },
];

const SEVERITY = { critical: 25, high: 12, medium: 5, low: 2, info: 0 };
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

module.exports = { CATEGORIES, SEVERITY, SEVERITY_ORDER };
