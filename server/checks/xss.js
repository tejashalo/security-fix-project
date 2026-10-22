'use strict';

const SANITIZER = /DOMPurify|sanitize|sanitizeHtml|xss\(|purify|escapeHtml|he\.encode|bleach|markupsafe\.escape/i;

module.exports = {
  id: 'xss',
  title: 'Looking for XSS (cross-site scripting) holes',
  async run(ctx) {
    const { p } = ctx;
    let anyFrontend = false;
    for (const f of p.codeFiles((x) => /\.(m|c)?(js|ts)x?$|\.(vue|svelte|html?|ejs|hbs|handlebars|njk|jinja2?|j2|py|php|astro)$/.test(x)).map((x) => x.path)) {
      if (/vibeguard-security/.test(f)) continue;
      const c = p.read(f) || '';
      if (/\.(jsx|tsx|vue|svelte|html?|ejs|hbs|astro)$/.test(f)) anyFrontend = true;
      const edits = [];
      let m;

      // element.innerHTML = expr  (auto-fix to textContent when the value is plain data, not markup)
      const ih = /(\b[\w$.\[\]'"()]+)\.(innerHTML|outerHTML)\s*(\+?=)\s*([^;\n]+)/g;
      while ((m = ih.exec(c))) {
        const rhs = m[4].trim();
        if (/^(['"`])[^'"`$]*\1$/.test(rhs) || rhs === "''" || rhs === '""') continue; // static string
        anyFrontend = true;
        const sanitized = SANITIZER.test(rhs);
        if (sanitized) continue;
        const plainData = !/[<>]/.test(rhs) && !/html|template|markup|svg|render/i.test(rhs) && m[3] === '=' && m[2] === 'innerHTML';
        const fd = ctx.at(f, m.index, {
          category: 'xss', severity: plainData ? 'high' : 'medium',
          title: `${m[2]} is set from a variable`,
          why: 'If this value ever contains user input (names, comments, URL params, API data), an attacker can inject <script> or <img onerror> and take over the visitor\'s session.',
          fix: plainData ? 'Use textContent for text.' : 'Build elements with textContent / createElement, or sanitize with DOMPurify.sanitize(html) before assigning.',
        });
        if (plainData) edits.push({ index: m.index, old: m[0], new: `${m[1]}.textContent ${m[3]} ${m[4]}`, finding: fd, summary: 'Switched to textContent so the value is shown as text, never executed as HTML.' });
      }
      // insertAdjacentHTML / document.write
      const ia = /\.(insertAdjacentHTML)\s*\(\s*['"][\w-]+['"]\s*,\s*([^)]+)\)|document\.write(?:ln)?\s*\(([^)]+)\)/g;
      while ((m = ia.exec(c))) {
        const arg = (m[2] || m[3] || '').trim();
        if (/^(['"`])[^'"`$]*\1$/.test(arg) || SANITIZER.test(arg)) continue;
        ctx.at(f, m.index, { category: 'xss', severity: 'medium', title: `${m[1] || 'document.write'} with dynamic content`, why: 'Inserts raw HTML; any user-controlled part becomes executable script.', fix: 'Create elements and set textContent, or sanitize with DOMPurify first.' });
      }
      // React dangerouslySetInnerHTML
      const dz = /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+)\}\s*\}/g;
      while ((m = dz.exec(c))) {
        if (SANITIZER.test(m[1]) || /^\s*(['"`])[^'"`$]*\1\s*$/.test(m[1])) continue;
        ctx.at(f, m.index, { category: 'xss', severity: 'high', title: 'dangerouslySetInnerHTML with unsanitized content', why: 'React escapes everything except this. Markdown, rich text, AI output or user bios rendered this way can run attacker scripts.', fix: "Sanitize first: `import DOMPurify from 'dompurify'` → `{{ __html: DOMPurify.sanitize(" + m[1].trim().slice(0, 40) + ') }}`.' });
      }
      // Vue v-html / Svelte {@html}
      const vh = /v-html\s*=\s*"([^"]+)"|\{@html\s+([^}]+)\}/g;
      while ((m = vh.exec(c))) {
        if (SANITIZER.test(m[1] || m[2])) continue;
        ctx.at(f, m.index, { category: 'xss', severity: 'high', title: m[1] ? 'v-html renders raw HTML' : '{@html} renders raw HTML', why: 'Any user-controlled content rendered this way can execute scripts.', fix: 'Render as text ({{ value }}) or sanitize with DOMPurify before rendering.' });
      }
      // Templates: EJS <%- %>, Handlebars {{{ }}}, Jinja |safe, Django mark_safe
      if (/\.ejs$/.test(f)) {
        const re = /<%-\s*(?!include\b)([^%]+?)\s*%>/g;
        while ((m = re.exec(c))) {
          if (/^(body|content|partial|layout|script|style|defineContent)/i.test(m[1].trim())) continue;
          const fd = ctx.at(f, m.index, { category: 'xss', severity: 'high', title: 'EJS outputs unescaped value with <%-', why: '<%- prints raw HTML. User data here becomes an XSS hole.', fix: 'Use <%= %> which escapes HTML.' });
          if (/^[\w.$\[\]'"]+$/.test(m[1].trim())) edits.push({ index: m.index, old: m[0], new: m[0].replace('<%-', '<%='), finding: fd, summary: 'Switched to escaped output <%= %>.' });
        }
      }
      if (/\.(hbs|handlebars)$/.test(f)) {
        const re = /\{\{\{\s*([^}]+)\}\}\}/g;
        while ((m = re.exec(c))) {
          if (/^(body|>|yield)/.test(m[1].trim())) continue;
          ctx.at(f, m.index, { category: 'xss', severity: 'high', title: 'Handlebars triple-stash outputs raw HTML', why: '{{{ }}} disables escaping.', fix: 'Use {{ }} unless the value is trusted, sanitized HTML.' });
        }
      }
      const jin = /\{\{[^}]*\|\s*safe\s*\}\}|\{%\s*autoescape\s+(false|off)\s*%\}|mark_safe\(|Markup\(\s*f?["']|render_template_string\(/g;
      while ((m = jin.exec(c))) {
        ctx.at(f, m.index, { category: 'xss', severity: /render_template_string/.test(m[0]) ? 'high' : 'medium', title: /render_template_string/.test(m[0]) ? 'render_template_string with dynamic template' : 'Template auto-escaping disabled', why: /render_template_string/.test(m[0]) ? 'Building templates from strings can lead to server-side template injection (remote code execution) if user input is included.' : 'This marks content as safe HTML; user data here can run scripts.', fix: 'Keep auto-escaping on; only mark sanitized, trusted HTML as safe (bleach.clean first).' });
      }
      // href/src from user data: javascript: URLs
      const jsUrl = /(href|src)\s*=\s*\{\s*(?:user|profile|data|props|item|post|comment)\.\w*(url|link|website|href)\w*\s*\}/gi;
      while ((m = jsUrl.exec(c))) {
        ctx.at(f, m.index, { category: 'xss', severity: 'low', title: 'Link URL comes from user data', why: 'A user can save a link like javascript:alert(document.cookie) which runs when clicked.', fix: 'Allow only http(s) URLs: `/^https?:\\/\\//.test(url) ? url : "#"`.' });
      }
      // PHP echo of request data
      const php = /echo\s+\$_(GET|POST|REQUEST|COOKIE)\[/g;
      while ((m = php.exec(c))) {
        ctx.at(f, m.index, { category: 'xss', severity: 'high', title: 'PHP echoes request data directly', why: 'Reflected XSS: the attacker\'s input is printed as HTML.', fix: 'Wrap with htmlspecialchars($value, ENT_QUOTES, "UTF-8").' });
      }
      ctx.applyEdits(f, edits);
    }
    // tokens in localStorage (stolen by any XSS)
    for (const f of p.codeFiles((x) => /\.(m|c)?(js|ts)x?$|\.(vue|svelte)$/.test(x)).map((x) => x.path)) {
      const c = p.read(f) || '';
      const m = /localStorage\.setItem\(\s*['"`]([^'"`]*(token|jwt|auth|session|access|refresh)[^'"`]*)['"`]/i.exec(c);
      if (m) {
        ctx.at(f, m.index, { category: 'sessions', severity: 'medium', title: `Auth token stored in localStorage ("${m[1]}")`, why: 'Any XSS bug (or malicious npm package) can read localStorage and steal the token. httpOnly cookies cannot be read by JavaScript.', fix: 'Prefer an httpOnly, Secure, SameSite cookie set by the server; or keep tokens in memory with short expiry. If you use Supabase/Firebase SDKs, their defaults are acceptable — just keep XSS out.' });
        break;
      }
    }
    if (anyFrontend || ctx.det.hasHtml) ctx.checked('xss');
    else ctx.na('xss', 'No HTML-rendering code found.');
  },
};
