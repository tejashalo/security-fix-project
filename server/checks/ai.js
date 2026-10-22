'use strict';

module.exports = {
  id: 'ai',
  title: 'Checking AI / LLM features',
  async run(ctx) {
    const { p, det } = ctx;
    let seen = det.frameworks.has('AI/LLM');
    for (const f of p.codeFiles((x) => /\.(m|c)?(js|ts)x?$|\.(py|vue|svelte|dart|swift|kt)$/.test(x)).map((x) => x.path)) {
      const c = p.read(f) || '';
      if (!/openai|anthropic|generativelanguage|gemini|groq|mistral|cohere|replicate|huggingface|llm|chat\.completions|messages\.create|generateContent|langchain|ollama|deepseek|openrouter/i.test(c)) continue;
      seen = true;
      const client = ctx.isClient(f);
      let m = /dangerouslyAllowBrowser\s*:\s*true/.exec(c);
      if (m) ctx.at(f, m.index, { category: 'ai', severity: 'critical', title: 'AI SDK runs in the browser (dangerouslyAllowBrowser)', why: 'Your API key is sent to every visitor. People will copy it and use your account for their own projects — bills of thousands of dollars happen.', fix: 'Call the AI provider only from a server route (e.g. /api/chat) that keeps the key in an environment variable, checks the user is logged in, and rate-limits.' });
      m = /(fetch|axios\.\w+)\(\s*['"`]https:\/\/(api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.groq\.com|api\.mistral\.ai|openrouter\.ai|api\.deepseek\.com)/.exec(c);
      if (m && client) ctx.at(f, m.index, { category: 'ai', severity: 'critical', title: `Front-end calls ${m[2]} directly`, why: 'Calling the AI API from the browser/app means the API key is in the client.', fix: 'Proxy the request through your backend and keep the key server-side.' });
      if (!client) {
        const sys = /(role\s*:\s*['"]system['"]\s*,\s*content\s*:\s*`[^`]*\$\{[^}]*(req\.|body|input|message|prompt|query|user)|system\s*[:=]\s*`[^`]*\$\{[^}]*(req\.|body|input|message|query|user))/i.exec(c);
        if (sys) ctx.at(f, sys.index, { category: 'ai', severity: 'medium', title: 'User input is inserted into the system prompt', why: 'Prompt injection: a user can write "ignore previous instructions…" and override your rules, leak the system prompt or misuse tools.', fix: 'Keep the system prompt static; pass user text only as a user message. Never give the model tools/data the user is not allowed to access directly.' });
        const call = /chat\.completions\.create\(|messages\.create\(|generateContent\(|responses\.create\(|streamText\(|generateText\(/.exec(c);
        if (call && !/max_tokens|maxTokens|max_output_tokens|maxOutputTokens|max_completion_tokens/.test(c)) {
          ctx.at(f, call.index, { category: 'ai', severity: 'low', title: 'AI call has no output token limit', why: 'Without a cap, a single abusive request can generate very long (expensive) outputs.', fix: 'Set max_tokens / maxOutputTokens, and set a monthly spend limit in the provider dashboard.' });
        }
        const exec = /(?<![\w.$])(eval|exec|execSync|new Function)\s*\(\s*[^)]*(completion|response|output|result|message|content|text)\b/i.exec(c);
        if (exec) ctx.at(f, exec.index, { category: 'ai', severity: 'critical', title: 'AI output is executed as code', why: 'Anything the model outputs — including text injected by users or web pages — would run on your server.', fix: 'Never eval model output. Parse structured output (JSON schema) and act only on allowed operations.' });
        const html = /(innerHTML|dangerouslySetInnerHTML|v-html)[^;\n]*(completion|response|answer|output|message)/i.exec(c);
        if (html) ctx.at(f, html.index, { category: 'xss', severity: 'medium', title: 'AI output rendered as raw HTML', why: 'Prompt injection can make the model output <script>/<img onerror> that runs in users\' browsers.', fix: 'Render as text or markdown with sanitization (DOMPurify).' });
      }
    }
    if (seen) {
      ctx.checked('ai');
      ctx.note('For AI features: set a hard monthly spend limit in your AI provider dashboard, require login for AI endpoints, and keep per-user rate limits.');
    } else ctx.na('ai', 'No AI/LLM usage found.');
  },
};
