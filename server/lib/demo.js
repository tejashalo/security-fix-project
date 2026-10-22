'use strict';
/**
 * Builds deliberately vulnerable demo projects (used by the "Try a demo" button and tests).
 * Fake secrets are assembled at runtime so this source file itself contains no secret-looking strings.
 */
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const j = (...parts) => parts.join('');
const FAKE = {
  openai: j('sk-', 'proj-', 'Vg7dEmoKeyNotReal', '9x2LmQ4tR8wZ1aB3cD5eF6gH7iJ'),
  stripe: j('sk', '_live_', '51DemoNotARealKey', 'Xy9Zt3Lq8Wm2Pn6'),
  jwtSecret: j('super-secret', '-jwt-key-123'),
  dbPass: j('Sup3rS3cret', 'DbPass!'),
  mongo: j('mongodb+srv://', 'admin', ':', 'Hunter2Demo', '@cluster0.example.mongodb.net/app'),
  google: j('AIza', 'SyDemoKeyNotReal_', '0123456789abcdefgh'),
  aws: j('AKIA', 'DEMONOTREAL1234'),
};

function write(root, rel, content) {
  const abs = path.join(root, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content);
}

function webDemo(root) {
  write(root, 'package.json', JSON.stringify({
    name: 'my-vibe-app', version: '1.0.0', main: 'server/index.js',
    scripts: { start: 'node server/index.js', dev: 'nodemon server/index.js' },
    dependencies: { express: '^4.18.2', cors: '^2.8.5', mongoose: '^7.0.0', jsonwebtoken: '^9.0.0', 'crypto-js': '^4.1.1', multer: '^1.4.5-lts.1', 'left-pad': '^1.3.0', 'express-ai-helper-utils': '^1.0.0', lodahs: '^4.17.21' },
    devDependencies: { nodemon: '^3.0.0' },
  }, null, 2) + '\n');
  write(root, 'server/index.js', `const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const CryptoJS = require('crypto-js');
const multer = require('multer');
const adminRoutes = require('./routes/admin');

const app = express();
app.use(cors());
app.use(express.json());

const OPENAI_API_KEY = "${FAKE.openai}";
const JWT_SECRET = process.env.JWT_SECRET || '${FAKE.jwtSecret}';
mongoose.connect("${FAKE.mongo}");

const upload = multer({ dest: 'uploads/' });
app.use('/files', express.static('uploads'));

app.post('/api/register', async (req, res) => {
  const user = await User.create({ email: req.body.email, password: CryptoJS.MD5(req.body.password).toString(), role: req.body.role });
  res.json(user);
});

app.post('/api/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email, password: req.body.password });
  if (!user) return res.status(401).json({ error: 'bad login' });
  const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET);
  res.cookie('token', token);
  res.json({ token });
});

app.get('/api/orders/:id', async (req, res) => {
  const order = await Order.findById(req.params.id);
  res.json(order);
});

app.delete('/api/posts/:id', async (req, res) => {
  await Post.findByIdAndDelete(req.params.id);
  res.json({ ok: true });
});

app.put('/api/profile', async (req, res) => {
  const user = await User.findByIdAndUpdate(req.query.userId, req.body);
  res.json(user);
});

app.post('/api/upload', upload.single('file'), (req, res) => res.json({ file: req.file.filename }));

app.get('/api/download', (req, res) => res.sendFile(__dirname + '/files/' + req.query.name));

app.get('/go', (req, res) => res.redirect(req.query.next));

app.post('/api/chat', async (req, res) => {
  const r = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + OPENAI_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: 'gpt-4o-mini', messages: [{ role: 'system', content: \`You are a helpful bot for \${req.body.company}\` }, { role: 'user', content: req.body.message }] }),
  });
  res.json(await r.json());
});

app.use('/admin', adminRoutes);

app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

app.listen(3000, () => console.log('listening on 3000'));
`);
  write(root, 'server/routes/admin.js', `const express = require('express');
const router = express.Router();

router.get('/users', async (req, res) => {
  res.json(await User.find({}));
});

router.delete('/users/:id', async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.json({ ok: true });
});

module.exports = router;
`);
  write(root, 'server/db.js', `const mysql = require('mysql2');
const pool = mysql.createPool({ host: 'localhost', user: 'root', password: '${FAKE.dbPass}' });
async function findUser(email) {
  return pool.query(\`SELECT * FROM users WHERE email = '\${email}'\`);
}
module.exports = { findUser };
`);
  write(root, 'public/index.html', `<!doctype html>
<html><head><title>My Vibe App</title></head>
<body>
  <form action="/api/login">
    <input name="email" type="email"><input name="password" type="password">
    <button>Log in</button>
  </form>
  <div id="greeting"></div>
  <script src="app.js"></script>
</body></html>
`);
  write(root, 'public/app.js', `const STRIPE_KEY = "${FAKE.stripe}";
const params = new URLSearchParams(location.search);
document.getElementById('greeting').innerHTML = params.get('name');
localStorage.setItem('authToken', 'abc');
fetch('http://api.myvibeapp.com/data').then((r) => r.json());
`);
  write(root, 'public/backup.sql', `-- database dump\nINSERT INTO users VALUES (1, 'admin@example.com', 'password123');\n`);
  write(root, '.env', `GOOGLE_MAPS_KEY=${FAKE.google}\n`);
  write(root, '.gitignore', 'node_modules\n');
  write(root, 'Dockerfile', `FROM node:latest\nWORKDIR /app\nCOPY . .\nRUN npm install\nENV JWT_SECRET=${FAKE.jwtSecret}\nCMD ["node", "server/index.js"]\n`);
  write(root, 'docker-compose.yml', `services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_PASSWORD: postgres\n    ports:\n      - "5432:5432"\n`);
}

function appDemo(root) {
  write(root, 'package.json', JSON.stringify({
    name: 'my-vibe-mobile-app', version: '1.0.0', main: 'expo-router/entry',
    dependencies: { expo: '~51.0.0', 'react-native': '0.74.0', react: '18.2.0', '@react-native-async-storage/async-storage': '1.23.1', '@supabase/supabase-js': '^2.39.0', openai: '^4.20.0', moment: '^2.29.4' },
  }, null, 2) + '\n');
  write(root, 'app.json', JSON.stringify({ expo: { name: 'MyVibeApp', slug: 'my-vibe-app', extra: { openaiSecretKey: FAKE.openai } } }, null, 2) + '\n');
  write(root, 'app/index.tsx', `import AsyncStorage from '@react-native-async-storage/async-storage';
import OpenAI from 'openai';
import { createClient } from '@supabase/supabase-js';

const openai = new OpenAI({ apiKey: "${FAKE.openai}", dangerouslyAllowBrowser: true });
const supabase = createClient('https://demo.supabase.co', process.env.EXPO_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!);

export async function login(email: string, password: string) {
  const { data } = await supabase.auth.signInWithPassword({ email, password });
  await AsyncStorage.setItem('session_token', data.session?.access_token ?? '');
}

export async function ask(q: string) {
  return openai.chat.completions.create({ model: 'gpt-4o-mini', messages: [{ role: 'user', content: q }] });
}

export const API = 'http://api.myvibeapp.com';
`);
  write(root, 'supabase/migrations/20240101000000_init.sql', `create table profiles (id uuid primary key, user_id uuid, full_name text, phone text);\ncreate table messages (id bigserial primary key, user_id uuid, body text);\nalter table messages enable row level security;\ncreate policy "anyone" on messages for all using (true);\n`);
  write(root, 'android/app/src/main/AndroidManifest.xml', `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:label="MyVibeApp" android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter><action android:name="android.intent.action.MAIN" /><category android:name="android.intent.category.LAUNCHER" /></intent-filter>
    </activity>
    <service android:name=".SyncService" android:exported="true" />
  </application>
</manifest>
`);
  write(root, 'ios/MyVibeApp/Info.plist', `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>NSAppTransportSecurity</key>
  <dict><key>NSAllowsArbitraryLoads</key><true/></dict>
</dict></plist>
`);
  write(root, 'android/app/release.keystore', 'not-a-real-keystore');
  write(root, 'backend/server.js', `const express = require('express');
const app = express();
app.use(express.json());
app.post('/api/delete-account', async (req, res) => {
  await db.query('DELETE FROM users WHERE id = ' + req.body.id);
  res.json({ ok: true });
});
app.listen(4000);
`);
  write(root, 'backend/package.json', JSON.stringify({ name: 'backend', version: '1.0.0', dependencies: { express: '^4.18.2' } }, null, 2) + '\n');
}

function gitCommitSecret(root) {
  const env = { ...process.env, GIT_AUTHOR_NAME: 'Demo', GIT_AUTHOR_EMAIL: 'demo@example.com', GIT_COMMITTER_NAME: 'Demo', GIT_COMMITTER_EMAIL: 'demo@example.com', GIT_CONFIG_NOSYSTEM: '1' };
  const git = (...args) => spawnSync('git', ['-c', 'init.defaultBranch=main', '-c', 'commit.gpgsign=false', ...args], { cwd: root, env, encoding: 'utf8' });
  if (git('init', '-q').status !== 0) return false;
  write(root, 'config/keys.js', `module.exports = { awsKey: "${FAKE.aws}" };\n`);
  git('add', '-A');
  git('commit', '-q', '-m', 'initial commit');
  fs.rmSync(path.join(root, 'config/keys.js'));
  git('add', '-A');
  git('commit', '-q', '-m', 'remove keys');
  return true;
}

function buildDemo(root, mode = 'web', { withGit = true } = {}) {
  fs.mkdirSync(root, { recursive: true });
  if (mode === 'app') appDemo(root); else webDemo(root);
  if (withGit) gitCommitSecret(root);
  return root;
}

module.exports = { buildDemo, FAKE };
