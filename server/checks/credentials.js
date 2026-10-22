'use strict';
const { matchParen, splitArgs } = require('../lib/util');
/** Password hashing, cookies, sessions and JWT. */

module.exports = {
  id: 'credentials',
  title: 'Checking password hashing, cookies, sessions and JWT',
  async run(ctx) {
    const { p, det } = ctx;
    let pwSeen = false, sessSeen = false;
    const files = p.codeFiles((x) => /\.(m|c)?(js|ts)x?$|\.py$/.test(x) && !/vibeguard-security/.test(x)).map((x) => x.path);
    for (const f of files) {
      const c = p.read(f) || '';
      const py = /\.py$/.test(f);
      const edits = [];
      let m;
      const hasPasswordWord = /password|passwd|pwd/i.test(c);

      // ---------- weak hashing ----------
      if (hasPasswordWord) {
        const weak = /createHash\(\s*['"](md5|sha1|sha256|sha512)['"]\s*\)|hashlib\.(md5|sha1|sha256|sha512)\(|\bmd5\(|\bsha1\(|CryptoJS\.(MD5|SHA1|SHA256)\(/g;
        while ((m = weak.exec(c))) {
          const near = c.slice(Math.max(0, m.index - 250), m.index + 250);
          if (!/pass(word)?|pwd/i.test(near)) continue;
          pwSeen = true;
          ctx.at(f, m.index, { category: 'passwords', severity: 'critical', title: `Passwords hashed with ${(m[1] || m[2] || m[3] || 'a fast hash').toUpperCase()}`, why: 'MD5/SHA hashes are designed to be fast — a GPU can try billions of guesses per second, so leaked hashes are cracked in minutes.', fix: py ? 'Use argon2-cffi or bcrypt (or werkzeug generate_password_hash with the default scrypt/pbkdf2).' : 'Use bcrypt (`await bcrypt.hash(password, 12)`) or argon2 (`await argon2.hash(password)`).' });
        }
        // plaintext compare / storage
        const cmp = /(\w+\.password\s*(===?|!==?)\s*(?:req\.body\.)?\w*password\b|(?:req\.body\.)?password\s*(===?|!==?)\s*\w+\.password\b)/gi;
        while ((m = cmp.exec(c))) {
          pwSeen = true;
          ctx.at(f, m.index, { category: 'passwords', severity: 'critical', title: 'Password compared as plain text', why: 'This means passwords are stored unhashed. One database leak exposes every user\'s password (which they reuse elsewhere).', fix: 'Store `await bcrypt.hash(password, 12)` and verify with `await bcrypt.compare(password, user.passwordHash)`.' });
        }
        const store = /\b(password|passwd)\s*:\s*(req\.body\.password|password|data\.password|body\.password)\s*[,}\n]/g;
        while ((m = store.exec(c))) {
          const near = c.slice(Math.max(0, m.index - 600), m.index + 200);
          if (/hash|bcrypt|argon|scrypt|pbkdf2|crypt\(|encrypt/i.test(near)) continue;
          if (!/create|insert|save|new\s+\w+|signup|register|update|set\(|find|where/i.test(near)) continue;
          pwSeen = true;
          const lineTxt = c.slice(c.lastIndexOf('\n', m.index) + 1, c.indexOf('\n', m.index) === -1 ? c.length : c.indexOf('\n', m.index));
          if (/find|where|select|filter/i.test(lineTxt)) ctx.at(f, m.index, { category: 'passwords', severity: 'critical', title: 'Login looks up the user by plain-text password', why: 'Querying the database with the raw password means passwords are stored unhashed — one leak exposes every user.', fix: 'Find the user by email only, then check `await bcrypt.compare(password, user.passwordHash)`.' });
          else ctx.at(f, m.index, { category: 'passwords', severity: 'critical', title: 'Password saved without hashing', why: 'Plain-text passwords in the database are a disaster when (not if) it leaks.', fix: 'Hash before saving: `password: await bcrypt.hash(req.body.password, 12)`.' });
        }
        // bcrypt cost too low → raise to 12
        const bc = /\b(bcrypt(?:js)?\.(?:hash|hashSync|genSalt|genSaltSync))\s*\(\s*([^,)]*,\s*)?(\d{1,2})\s*\)/g;
        while ((m = bc.exec(c))) {
          pwSeen = true;
          const rounds = Number(m[3]);
          if (rounds >= 10) continue;
          const fd = ctx.at(f, m.index, { category: 'passwords', severity: 'medium', title: `bcrypt cost factor is only ${rounds}`, why: 'Low cost factors make offline cracking much faster. 10 is the minimum; 12 is a good default.', fix: 'Use a cost of 12.' });
          edits.push({ index: m.index, old: m[0], new: m[0].replace(new RegExp(`${m[3]}\\s*\\)$`), '12)'), finding: fd, summary: 'Raised bcrypt cost factor to 12.' });
        }
        if (/bcrypt|argon2|scrypt|pbkdf2|generate_password_hash|make_password|passlib/.test(c)) pwSeen = true;
        const wz = /generate_password_hash\([^)]*method\s*=\s*['"](plain|md5|sha1|sha256)['"]/.exec(c);
        if (wz) { pwSeen = true; ctx.at(f, wz.index, { category: 'passwords', severity: 'high', title: `generate_password_hash uses method="${wz[1]}"`, why: 'A fast/plain method makes stored passwords easy to crack.', fix: 'Remove the method argument to use the secure default (scrypt).' }); }
      }

      // ---------- cookies ----------
      const ck = /res\.cookie\(/g;
      while ((m = ck.exec(c))) {
        const open = m.index + m[0].length - 1;
        const close = matchParen(c, open);
        if (close < 0) continue;
        const args = splitArgs(c.slice(open + 1, close));
        if (args.length < 2) continue;
        sessSeen = true;
        const name = args[0].trim();
        const opts = args[2] ? args[2].trim() : '';
        const sensitive = /token|session|auth|jwt|sid|refresh|access/i.test(name);
        const missing = ['httpOnly', 'secure', 'sameSite'].filter((k) => !new RegExp(k, 'i').test(opts));
        if (!missing.length || !sensitive) continue;
        if (opts && !/^\{[\s\S]*\}$/.test(opts)) continue; // options come from a variable — can't safely edit
        const fd = ctx.at(f, m.index, { category: 'sessions', severity: 'medium', title: `Cookie ${name} is missing ${missing.join(', ')}`, why: 'Without httpOnly, JavaScript (and any XSS) can steal the cookie; without secure it is sent over plain HTTP; without sameSite other sites can ride on it (CSRF).', fix: "Add `{ httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax' }`." });
        const add = { httpOnly: 'httpOnly: true', secure: "secure: process.env.NODE_ENV === 'production'", sameSite: "sameSite: 'lax'" };
        const extra = missing.map((k) => add[k]).join(', ');
        const inner = opts ? opts.replace(/^\{\s*/, '').replace(/\s*,?\s*\}$/, '') : '';
        const newOpts = `{ ${inner ? inner + ', ' : ''}${extra} }`;
        const old = c.slice(m.index, close + 1);
        const replacement = `res.cookie(${name}, ${args[1].trim()}, ${newOpts}${args.length > 3 ? ', ' + args.slice(3).join(',').trim() : ''})`;
        edits.push({ index: m.index, old, new: replacement, finding: fd, summary: `Added ${missing.join(', ')} to the cookie.` });
      }
      // express-session config
      const es = /\bsession\(\s*\{([\s\S]{0,800}?)\}\s*\)/g;
      while ((m = es.exec(c))) {
        if (!/express-session|cookie-session/.test(c)) break;
        sessSeen = true;
        const body = m[1];
        if (!/cookie\s*:/.test(body)) {
          const fd = ctx.at(f, m.index, { category: 'sessions', severity: 'medium', title: 'Session cookie uses default (insecure) settings', why: 'Default session cookies are not marked secure or SameSite.', fix: "Add `cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 }`." });
          const insert = `\n  cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 }, // added by VibeGuard`;
          const at = m.index + m[0].indexOf('{') + 1;
          edits.push({ index: at, old: '', new: insert, finding: fd, summary: 'Session cookie now httpOnly, SameSite=Lax, secure in production, 7-day expiry.' });
        } else if (/secure\s*:\s*false/.test(body)) {
          ctx.at(f, m.index, { category: 'sessions', severity: 'medium', title: 'Session cookie has secure: false', why: 'The session cookie can be sent over plain HTTP and intercepted.', fix: "Use `secure: process.env.NODE_ENV === 'production'`." });
        }
        if (/saveUninitialized\s*:\s*true/.test(body)) ctx.at(f, m.index, { category: 'sessions', severity: 'low', title: 'saveUninitialized: true', why: 'Creates sessions for every visitor (storage abuse, privacy).', fix: 'Set saveUninitialized: false.' });
      }

      // ---------- JWT ----------
      const sign = /\bjwt\.sign\(/g;
      while ((m = sign.exec(c))) {
        const open = m.index + m[0].length - 1;
        const close = matchParen(c, open);
        if (close < 0) continue;
        const args = splitArgs(c.slice(open + 1, close));
        sessSeen = true;
        if (args.length >= 3 && /expiresIn|exp\b/.test(args[2])) continue;
        if (/\bexp\s*:/.test(args[0] || '')) continue;
        if (args.length > 3 || (args.length === 3 && !/^\s*\{[\s\S]*\}\s*$/.test(args[2]))) continue;
        const fd = ctx.at(f, m.index, { category: 'sessions', severity: 'medium', title: 'JWT is issued without an expiry', why: 'A token that never expires works forever if stolen — you cannot log the user out.', fix: "Add `{ expiresIn: '1h' }` (use refresh tokens for long sessions)." });
        if (args.length === 2) {
          edits.push({ index: close, old: ')', new: ", { expiresIn: '1h' })", finding: fd, summary: 'Tokens now expire after 1 hour (adjust as needed).' });
        } else {
          const third = args[2];
          const brace = c.indexOf('{', open + 1 + args[0].length + 1 + args[1].length + 1);
          if (brace > 0 && brace < close) edits.push({ index: brace, old: '{', new: "{ expiresIn: '1h'," + (/^\s*\{\s*\}\s*$/.test(third) ? '' : ''), finding: fd, summary: 'Tokens now expire after 1 hour (adjust as needed).' });
        }
      }
      const dec = /\bjwt\.decode\(/g;
      while ((m = dec.exec(c))) {
        sessSeen = true;
        if (/jwt\.verify\(/.test(c)) continue;
        ctx.at(f, m.index, { category: 'sessions', severity: 'critical', title: 'JWT decoded but never verified', why: 'jwt.decode() does not check the signature — anyone can craft a token claiming to be any user (or admin).', fix: 'Use jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] }).' });
      }
      const ver = /\bjwt\.verify\(/g;
      while ((m = ver.exec(c))) {
        sessSeen = true;
        const close = matchParen(c, m.index + m[0].length - 1);
        const vargs = close > 0 ? splitArgs(c.slice(m.index + m[0].length, close)) : [];
        if (vargs.length !== 2 && !(vargs.length === 3 && /^\s*(\(|async|function)/.test(vargs[2]))) continue;
        ctx.at(f, m.index, { category: 'sessions', severity: 'low', title: 'jwt.verify() without pinned algorithms', why: 'Pinning the algorithm prevents algorithm-confusion attacks.', fix: 'Pass `{ algorithms: ["HS256"] }` (or the algorithm you actually use).' });
      }
      const none = /algorithms?\s*:\s*\[?\s*['"]none['"]/i.exec(c);
      if (none) ctx.at(f, none.index, { category: 'sessions', severity: 'critical', title: 'JWT "none" algorithm allowed', why: 'Unsigned tokens are accepted — anyone can log in as anyone.', fix: 'Remove "none" from allowed algorithms.' });
      if (py) {
        const pyNoVerify = /jwt\.decode\([^)]*(verify\s*=\s*False|"verify_signature"\s*:\s*False|options\s*=\s*\{[^}]*verify_signature[^}]*False)/.exec(c);
        if (pyNoVerify) { sessSeen = true; ctx.at(f, pyNoVerify.index, { category: 'sessions', severity: 'critical', title: 'JWT signature verification disabled', why: 'Forged tokens are accepted.', fix: 'Always verify signatures and pass algorithms=["HS256"].' }); }
      }
      ctx.applyEdits(f, edits);
    }
    if (pwSeen) ctx.checked('passwords');
    else if (det.frameworks.has('Supabase') || det.frameworks.has('Firebase') || det.hasAny('@clerk/nextjs', '@clerk/clerk-react', 'next-auth', '@auth0/nextjs-auth0')) ctx.na('passwords', 'Passwords are handled by your auth provider (Supabase/Firebase/Clerk/Auth.js), which hashes them correctly.');
    else ctx.na('passwords', 'No password handling code found.');
    if (sessSeen || det.hasBackend) ctx.checked('sessions');
    else ctx.na('sessions', 'No session or token code found.');
  },
};
