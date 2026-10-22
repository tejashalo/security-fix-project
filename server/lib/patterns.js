'use strict';
/** Secret detection patterns shared by the code scanner and the git history scanner. */

const SECRET_PATTERNS = [
  { id: 'private-key', name: 'Private key', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g, severity: 'critical', multiline: true },
  { id: 'anthropic', name: 'Anthropic API key', re: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}/g, env: 'ANTHROPIC_API_KEY', severity: 'critical' },
  { id: 'openai', name: 'OpenAI API key', re: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}|\bsk-[A-Za-z0-9]{40,}\b/g, env: 'OPENAI_API_KEY', severity: 'critical' },
  { id: 'stripe-live', name: 'Stripe/Clerk live secret key', re: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/g, env: 'STRIPE_SECRET_KEY', severity: 'critical' },
  { id: 'stripe-test', name: 'Stripe/Clerk test secret key', re: /\b(?:sk|rk)_test_[A-Za-z0-9]{16,}\b/g, env: 'STRIPE_SECRET_KEY', severity: 'high' },
  { id: 'stripe-webhook', name: 'Stripe webhook signing secret', re: /\bwhsec_[A-Za-z0-9]{20,}\b/g, env: 'STRIPE_WEBHOOK_SECRET', severity: 'critical' },
  { id: 'aws-access', name: 'AWS access key ID', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, env: 'AWS_ACCESS_KEY_ID', severity: 'critical' },
  { id: 'aws-secret', name: 'AWS secret access key', re: /aws_?secret(?:_?access)?_?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})\b/gi, group: 1, env: 'AWS_SECRET_ACCESS_KEY', severity: 'critical' },
  { id: 'github', name: 'GitHub token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b/g, env: 'GITHUB_TOKEN', severity: 'critical' },
  { id: 'gitlab', name: 'GitLab token', re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g, env: 'GITLAB_TOKEN', severity: 'critical' },
  { id: 'google', name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g, env: 'GOOGLE_API_KEY', severity: 'high' },
  { id: 'google-oauth', name: 'Google OAuth client secret', re: /\bGOCSPX-[A-Za-z0-9_-]{28}\b/g, env: 'GOOGLE_CLIENT_SECRET', severity: 'critical' },
  { id: 'slack-token', name: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, env: 'SLACK_TOKEN', severity: 'critical' },
  { id: 'slack-webhook', name: 'Slack webhook URL', re: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+/g, env: 'SLACK_WEBHOOK_URL', severity: 'high' },
  { id: 'discord-webhook', name: 'Discord webhook URL', re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/g, env: 'DISCORD_WEBHOOK_URL', severity: 'high' },
  { id: 'discord-bot', name: 'Discord bot token', re: /\b[MN][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27,38}\b/g, env: 'DISCORD_BOT_TOKEN', severity: 'critical' },
  { id: 'telegram', name: 'Telegram bot token', re: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g, env: 'TELEGRAM_BOT_TOKEN', severity: 'critical' },
  { id: 'sendgrid', name: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, env: 'SENDGRID_API_KEY', severity: 'critical' },
  { id: 'mailgun', name: 'Mailgun API key', re: /\bkey-[0-9a-zA-Z]{32}\b/g, env: 'MAILGUN_API_KEY', severity: 'critical' },
  { id: 'twilio', name: 'Twilio API key', re: /\bSK[0-9a-f]{32}\b/g, env: 'TWILIO_API_KEY', severity: 'high' },
  { id: 'huggingface', name: 'Hugging Face token', re: /\bhf_[A-Za-z0-9]{34,}\b/g, env: 'HF_TOKEN', severity: 'critical' },
  { id: 'groq', name: 'Groq API key', re: /\bgsk_[A-Za-z0-9]{40,}\b/g, env: 'GROQ_API_KEY', severity: 'critical' },
  { id: 'replicate', name: 'Replicate API token', re: /\br8_[A-Za-z0-9]{37}\b/g, env: 'REPLICATE_API_TOKEN', severity: 'critical' },
  { id: 'resend', name: 'Resend API key', re: /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}\b/g, env: 'RESEND_API_KEY', severity: 'critical' },
  { id: 'npm', name: 'npm access token', re: /\bnpm_[A-Za-z0-9]{36}\b/g, env: 'NPM_TOKEN', severity: 'critical' },
  { id: 'supabase-secret', name: 'Supabase secret key', re: /\bsb_secret_[A-Za-z0-9_-]{20,}\b/g, env: 'SUPABASE_SECRET_KEY', severity: 'critical' },
  { id: 'razorpay-secret', name: 'Razorpay key secret', re: /razorpay[_-]?(?:key[_-]?)?secret["']?\s*[:=]\s*["']([A-Za-z0-9]{20,})["']/gi, group: 1, env: 'RAZORPAY_KEY_SECRET', severity: 'critical' },
  { id: 'jwt', name: 'JSON Web Token', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, env: 'API_TOKEN', severity: 'medium', jwt: true },
  { id: 'db-url', name: 'Database URL with password', re: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss|amqps?|mssql):\/\/[^\s:@/'"`]+:([^\s@'"`]+)@[^\s'"`]+/g, passwordGroup: 1, env: 'DATABASE_URL', severity: 'critical' },
];

// key = "value" style assignments with secret-ish names
const GENERIC_RE = /([A-Za-z0-9_.$-]*(?:api[_-]?key|apikey|secret|token|passwd|password|pwd|auth[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|signing[_-]?key|encryption[_-]?key)[A-Za-z0-9_]*)["']?\s*(?::|=|:=|=>)\s*(["'`])([^"'`\s\n]{8,200})\2/dgi;
const GENERIC_NAME_EXCLUDE = /(url|uri|endpoint|path|field|name|header|type|label|placeholder|length|min|max|regex|pattern|prefix|expires?|ttl|count|policy|storage|cookie_?name|input|selector|hint|id_?token_?url|key_?name|reset|forgot|confirm|validation|error|message|text|title)$/i;

function decodeJwtPayload(token) {
  try {
    const part = token.split('.')[1];
    return JSON.parse(Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
  } catch { return null; }
}

/** Returns [{ pattern, value, index, length }] for a text blob. */
function findSecrets(text, { generic = true, isPlaceholder, shannon } = {}) {
  const out = [];
  const taken = [];
  const overlaps = (s, e) => taken.some(([a, b]) => s < b && e > a);
  for (const pat of SECRET_PATTERNS) {
    pat.re.lastIndex = 0;
    let m;
    while ((m = pat.re.exec(text))) {
      let value = m[0], index = m.index;
      if (pat.group) { value = m[pat.group]; index = m.index + m[0].indexOf(value); }
      if (pat.passwordGroup) {
        const pw = m[pat.passwordGroup];
        if (/^(\$\{|\{|<|%|\$[A-Z_])/.test(pw) || /^(password|pass|pwd|secret|changeme|xxx+|\*+|user|admin|root|example)$/i.test(pw)) continue;
      }
      let meta = {};
      if (pat.jwt) {
        const payload = decodeJwtPayload(value);
        if (!payload) continue;
        if (payload.role === 'anon') { meta.supabaseAnon = true; }
        else if (payload.role === 'service_role') meta = { severity: 'critical', name: 'Supabase service_role key', env: 'SUPABASE_SERVICE_ROLE_KEY', serviceRole: true };
        else meta = {};
      }
      if (overlaps(index, index + value.length)) continue;
      taken.push([index, index + value.length]);
      out.push({ pattern: { ...pat, ...meta }, value, index, length: value.length });
    }
  }
  if (generic) {
    GENERIC_RE.lastIndex = 0;
    let m;
    while ((m = GENERIC_RE.exec(text))) {
      const name = m[1];
      const value = m[3];
      const vStart = m.indices[3][0];
      if (overlaps(vStart, vStart + value.length)) continue;
      if (GENERIC_NAME_EXCLUDE.test(name.replace(/[_-]/g, '_'))) continue;
      if (isPlaceholder && isPlaceholder(value)) continue;
      if (/^(https?:|\/|\.\/|#|[a-z]+(?:[A-Z][a-z]+)+$|[a-z]+(?:[_-][a-z]+)+$)/.test(value)) continue;
      if (/^[A-Z_]+$/.test(value) || /^\d+$/.test(value)) continue;
      if (shannon && shannon(value) < 3.0 && value.length < 20) continue;
      taken.push([vStart, vStart + value.length]);
      out.push({ pattern: { id: 'generic', name: `Hardcoded ${/pass|pwd/i.test(name) ? 'password' : 'secret'} in "${name}"`, severity: 'high', assignName: name }, value, index: vStart, length: value.length });
    }
  }
  return out;
}

module.exports = { SECRET_PATTERNS, findSecrets, decodeJwtPayload };
