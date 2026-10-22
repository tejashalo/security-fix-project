'use strict';
const T = require('../lib/templates');
const { posix } = require('../lib/util');

module.exports = {
  id: 'deploy',
  title: 'Checking HTTPS and deployment config',
  async run(ctx) {
    const { p, det } = ctx;
    // ---------- HTTPS ----------
    let httpSeen = false;
    for (const f of p.codeFiles((x) => /\.(m|c)?(js|ts)x?$|\.(py|vue|svelte|dart|swift|kt|java)$/.test(x)).map((x) => x.path)) {
      const c = p.read(f) || '';
      const re = /(fetch|axios(?:\.\w+)?|baseURL\s*:|baseUrl\s*[:=]|API_URL\s*[:=]|Uri\.parse|URL\(string:|http\.(?:get|post))\s*\(?\s*['"`](http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|10\.0\.2\.2|192\.168\.|10\.|\[::1\]|\$\{)[^'"`\s]+)/g;
      let m;
      while ((m = re.exec(c))) {
        httpSeen = true;
        ctx.at(f, m.index, { category: 'https', severity: 'medium', title: `API called over plain HTTP (${m[2].slice(0, 60)})`, why: 'Anyone on the same Wi-Fi or network path can read and modify the traffic, including tokens and passwords.', fix: `Use https:// (${m[2].replace('http://', 'https://').slice(0, 60)}).` });
        break;
      }
    }
    ctx.checked('https');
    void httpSeen;

    // ---------- Docker ----------
    const dockerfiles = p.files.filter((f) => /(^|\/)Dockerfile[\w.-]*$/i.test(f.path) && !f.skipped).map((f) => f.path);
    for (const f of dockerfiles) {
      const c = p.read(f) || '';
      const dir = posix.dirname(f);
      let m;
      if (!/^\s*USER\s+(?!root\b)\S+/m.test(c)) ctx.add({ category: 'deploy', severity: 'medium', file: f, title: 'Container runs as root', why: 'If the app is compromised, the attacker is root inside the container, making escapes and damage easier.', fix: 'Add `USER node` (Node images) or create an unprivileged user before CMD.' });
      const env = /^\s*(ENV|ARG)\s+([A-Z0-9_]*(SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE)[A-Z0-9_]*)[\s=]+(\S+)/gim;
      while ((m = env.exec(c))) {
        if (/^\$|^""$|^''$/.test(m[4])) continue;
        ctx.secretValues.add(m[4]);
        ctx.at(f, m.index, { category: 'deploy', severity: 'high', title: `Secret ${m[2]} baked into the Docker image`, why: 'Anyone who pulls the image can read it with `docker history`.', fix: 'Pass secrets at runtime (environment variables / secrets manager), not in the Dockerfile.' });
      }
      if ((m = /^\s*FROM\s+\S+:latest\b/im.exec(c))) ctx.at(f, m.index, { category: 'deploy', severity: 'low', title: 'Base image uses :latest', why: 'Builds are not reproducible and can silently pull a broken or compromised image.', fix: 'Pin a version, e.g. node:20-alpine.' });
      if ((m = /^\s*COPY\s+\.\s+\./m.exec(c))) {
        const di = dir === '.' ? '.dockerignore' : `${dir}/.dockerignore`;
        if (!p.exists(di)) {
          const fd = ctx.at(f, m.index, { category: 'deploy', severity: 'high', title: '`COPY . .` without a .dockerignore', why: 'Your .env, .git history and local databases get copied into the image.', fix: 'Add a .dockerignore that excludes .env, .git, node_modules and keys.' });
          ctx.createFile(di, T.DOCKERIGNORE, 'Keeps .env, .git, keys and node_modules out of Docker images.');
          ctx.markFixed(fd, { before: '(no .dockerignore)', after: `${di} created`, summary: 'Created .dockerignore excluding secrets, git history and dependencies.' });
        }
      }
    }
    // compose privileged
    for (const f of p.files.filter((x) => /(^|\/)(docker-)?compose[\w.-]*\.ya?ml$/.test(x.path)).map((x) => x.path)) {
      const c = p.read(f) || '';
      const m = /privileged:\s*true|\/var\/run\/docker\.sock/.exec(c);
      if (m) ctx.at(f, m.index, { category: 'deploy', severity: 'high', title: m[0].includes('sock') ? 'Docker socket mounted into a container' : 'Privileged container', why: 'Gives the container full control of the host machine.', fix: 'Remove it unless absolutely required.' });
    }
    // Vercel / Netlify / Firebase hosting
    const fh = p.read('firebase.json') || '';
    if (/"public"\s*:\s*"\."/.test(fh)) ctx.add({ category: 'exposed', severity: 'high', file: 'firebase.json', title: 'Firebase Hosting serves the whole project folder', why: 'Your source code, configs and possibly .env become publicly downloadable.', fix: 'Set "public" to your build folder (e.g. "dist" or "build").' });
    if (dockerfiles.length || p.exists('vercel.json') || p.exists('netlify.toml') || p.exists('firebase.json') || p.exists('fly.toml') || p.exists('render.yaml') || p.exists('Procfile') || p.exists('railway.json')) ctx.checked('deploy');
    else ctx.na('deploy', 'No Docker or hosting config files found.');
    void det;
  },
};
