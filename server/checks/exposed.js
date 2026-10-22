'use strict';
const { posix } = require('../lib/util');
const T = require('../lib/templates');
const git = require('../lib/git');

const RULES = [
  { re: /(^|\/)\.env(\.(?!example|sample|template)[\w-]+)?$/, sev: 'critical', what: 'environment file with secrets', webOnly: true },
  { re: /(^|\/)(id_rsa|id_dsa|id_ecdsa|id_ed25519)$/, sev: 'critical', what: 'SSH private key' },
  { re: /\.(pem|key|p12|pfx)$/i, sev: 'critical', what: 'private key / certificate bundle', unless: /(public|cert|fullchain|chain)\.pem$|\.pub$/i },
  { re: /\.(jks|keystore)$/i, sev: 'critical', what: 'app signing keystore' },
  { re: /(^|\/)(service[-_]?account[\w-]*|[\w-]*firebase-adminsdk[\w-]*|gcp[-_]?key[\w-]*|credentials)\.json$/i, sev: 'critical', what: 'cloud service-account credentials' },
  { re: /(^|\/)\.vscode\/sftp\.json$/, sev: 'critical', what: 'SFTP config with server password' },
  { re: /(^|\/)\.(npmrc|pypirc)$/, sev: 'high', what: 'package-registry config (may hold tokens)', check: (c) => /_authToken|password|:_auth/.test(c || '') },
  { re: /(^|\/)\.(htpasswd)$/, sev: 'high', what: 'password file' },
  { re: /\.(sql|dump|bak|backup|old|orig|swp|sql\.gz|tar\.gz|tgz|7z|rar)$/i, sev: 'high', what: 'database dump / backup file', unless: /(^|\/)(migrations?|schema|seed|init|supabase|prisma|db\/migrate)[\w./-]*\.sql$/i },
  { re: /\.(sqlite|sqlite3|db)$/i, sev: 'high', what: 'database file' },
  { re: /(^|\/)(npm-debug|yarn-error|firebase-debug|firestore-debug|ui-debug|debug)\.log$|\.log$/i, sev: 'low', what: 'log file' },
  { re: /(^|\/)\.DS_Store$/, sev: 'low', what: 'macOS folder metadata (reveals file names)' },
  { re: /(^|\/)phpinfo\.php$/i, sev: 'high', what: 'phpinfo page (reveals server config)' },
  { re: /(^|\/)(wp-config\.php\.bak|config\.php\.bak|\.env\.bak|\.env\.old)$/i, sev: 'critical', what: 'backup of a config file with secrets' },
];
const SAFE_GLOB_EXTS = new Set(['.pem', '.key', '.p12', '.pfx', '.jks', '.keystore', '.sqlite', '.sqlite3', '.db', '.log', '.bak', '.old', '.orig', '.swp', '.dump']);
const WEB_ROOT = /(^|\/)(public|static|www|dist|build|out|_site|htdocs|public_html|assets)\//;

module.exports = {
  id: 'exposed',
  title: 'Looking for exposed files',
  async run(ctx) {
    const { p } = ctx;
    ctx.checked('exposed');
    const moved = [];
    const tracked = new Set(p.hasGit ? git.trackedFiles(p.root) : []);
    for (const f of p.files) {
      if (/(^|\/)(node_modules|\.git|_vibeguard_quarantine|\.vibeguard)\//.test(f.path)) continue;
      const rule = RULES.find((r) => r.re.test(f.path) && !(r.unless && r.unless.test(f.path)));
      if (!rule) continue;
      if (rule.check && !rule.check(p.read(f.path))) continue;
      const inWebRoot = WEB_ROOT.test(f.path);
      if (rule.webOnly && !inWebRoot) continue;
      const ignored = ctx.gitignoreCovers(f.path);
      const isTracked = tracked.has(f.path);
      if (ignored && !inWebRoot && !isTracked && ctx.initialIgnored && ctx.initialIgnored(f.path)) continue; // already handled before VibeGuard
      let severity = rule.sev;
      if (inWebRoot && severity === 'low') severity = 'medium';
      if (inWebRoot && severity === 'high') severity = 'critical';
      const fd = ctx.add({
        category: 'exposed', severity, file: f.path,
        title: `${rule.what[0].toUpperCase() + rule.what.slice(1)}${inWebRoot ? ' inside a public web folder' : isTracked ? ' is committed to git' : ' in the project'}`,
        why: inWebRoot
          ? `Files in ${f.path.split('/')[0]}/ are served to anyone who guesses the URL — automated scanners request these names constantly.`
          : 'If this gets committed or deployed, it is downloadable by anyone. It should not live in the project.',
        fix: inWebRoot ? 'Move it out of the public folder (VibeGuard quarantines it) and delete it if not needed.'
          : isTracked ? `Run \`git rm --cached ${f.path}\` and commit (VibeGuard already added a .gitignore rule). Then clean it from history and rotate anything it contains.`
          : 'Keep it out of git (VibeGuard adds a .gitignore rule) and store it somewhere safe. Rotate any key it contains.',
      });
      if (inWebRoot && /critical|high|medium/.test(severity)) {
        const to = `_vibeguard_quarantine/${f.path}`;
        if (p.move(f.path, to)) { moved.push(f.path); ctx.markFixed(fd, { before: f.path, after: to, summary: `Moved to ${to} (git-ignored, not deployed). Delete it once you've checked it.` }); }
      } else if (isTracked) {
        ctx.ensureGitignore([T.GITIGNORE_BLOCK[0], SAFE_GLOB_EXTS.has(posix.extname(f.path).toLowerCase()) ? '*' + posix.extname(f.path).toLowerCase() : f.path]);
      } else if (ignored) {
        ctx.markFixed(fd, { before: '(not ignored)', after: '.gitignore rule added', summary: 'Covered by the .gitignore rules VibeGuard added, so it will not be committed.' });
      } else {
        const ext = posix.extname(f.path).toLowerCase();
        const pattern = SAFE_GLOB_EXTS.has(ext) ? '*' + ext : posix.basename(f.path) === '.DS_Store' ? '.DS_Store' : f.path;
        const added = ctx.ensureGitignore([T.GITIGNORE_BLOCK[0], pattern]);
        if (added.length || ctx.gitignoreCovers(f.path)) ctx.markFixed(fd, { before: '(not ignored)', after: `.gitignore: ${pattern}`, summary: 'Added to .gitignore so it is never committed.' });
      }
    }
    if (moved.length) ctx.ensureGitignore(['_vibeguard_quarantine/']);
    // .git folder deployed inside a web root
    for (const d of p.dirs) {
      if (/(^|\/)(public|static|dist|build|www)\/\.git$/.test(d)) ctx.add({ category: 'exposed', severity: 'critical', file: d, title: '.git folder inside a public folder', why: 'Attackers download /.git/ and rebuild your full source code and history (including old secrets).', fix: 'Delete this .git folder from the public directory and block /.git in your server config.' });
    }
    // source maps in build output
    const maps = p.files.filter((f) => /\.(js|css)\.map$/.test(f.path) && WEB_ROOT.test(f.path));
    if (maps.length) {
      ctx.add({ category: 'debug', severity: 'medium', file: maps[0].path, title: `${maps.length} source map file(s) in build output`, why: 'Deployed .map files let anyone read your original source.', fix: 'Disable source maps for production builds or delete .map files before deploying.' });
    }
  },
};
