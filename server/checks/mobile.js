'use strict';
const { posix } = require('../lib/util');

module.exports = {
  id: 'mobile',
  title: 'Checking mobile app security',
  async run(ctx) {
    const { p, det } = ctx;
    if (!det.isApp) {
      ctx.na('mobile', ctx.opts.mode === 'app' ? 'No React Native, Expo, Flutter, Capacitor, Android or iOS project files found.' : 'Not a mobile app project.');
      return;
    }
    ctx.checked('mobile');

    // ---------- Android manifest ----------
    for (const f of det.androidManifests) {
      const c = p.read(f) || '';
      const edits = [];
      const flag = (attr, bad, sev, title, why, fix, good) => {
        const re = new RegExp(`android:${attr}\\s*=\\s*"${bad}"`);
        const m = re.exec(c);
        if (!m) return;
        const fd = ctx.at(f, m.index, { category: 'mobile', severity: sev, title, why, fix });
        if (good !== undefined) edits.push({ index: m.index, old: m[0], new: `android:${attr}="${good}"`, finding: fd, summary: fix });
      };
      flag('debuggable', 'true', 'critical', 'Android app is debuggable', 'Anyone with the APK can attach a debugger, read memory and bypass checks.', 'Set android:debuggable="false" (release builds set this automatically if the attribute is removed).', 'false');
      flag('allowBackup', 'true', 'medium', 'android:allowBackup is enabled', 'App data (including tokens) can be extracted with adb backup.', 'Set android:allowBackup="false" (or define backup rules that exclude secrets).', 'false');
      flag('usesCleartextTraffic', 'true', 'high', 'App allows plain HTTP traffic', 'Traffic can be read and modified on public Wi-Fi.', 'Set android:usesCleartextTraffic="false" and use HTTPS everywhere.', 'false');
      const exp = /<(activity|service|receiver|provider)\b[^>]*android:exported\s*=\s*"true"[^>]*>/g;
      let m, count = 0;
      while ((m = exp.exec(c))) {
        if (/MAIN|LAUNCHER/.test(c.slice(m.index, m.index + 600)) || /android:permission=/.test(m[0])) continue;
        if (++count > 3) break;
        ctx.at(f, m.index, { category: 'mobile', severity: 'low', title: `Exported ${m[1]} without a permission`, why: 'Other apps on the device can launch/call it and pass crafted data.', fix: 'Set android:exported="false" unless other apps need it; otherwise require a permission and validate intent data.' });
      }
      ctx.applyEdits(f, edits);
    }
    for (const f of p.files.filter((x) => /network_security_config\.xml$/.test(x.path)).map((x) => x.path)) {
      const c = p.read(f) || '';
      const m = /cleartextTrafficPermitted\s*=\s*"true"/.exec(c);
      if (m && !/<domain[^>]*>\s*(localhost|10\.0\.2\.2|127\.0\.0\.1)/.test(c)) {
        const fd = ctx.at(f, m.index, { category: 'mobile', severity: 'high', title: 'Network security config permits cleartext HTTP', why: 'Traffic can be intercepted.', fix: 'Set cleartextTrafficPermitted="false".' });
        ctx.applyEdits(f, [{ index: m.index, old: m[0], new: 'cleartextTrafficPermitted="false"', finding: fd, summary: 'Cleartext traffic disabled.' }]);
      }
    }
    for (const f of p.files.filter((x) => /(^|\/)build\.gradle(\.kts)?$/.test(x.path) && !x.skipped).map((x) => x.path)) {
      const c = p.read(f) || '';
      const m = /release\s*\{[^}]*minifyEnabled\s*(=\s*)?false/.exec(c);
      if (m) ctx.at(f, m.index, { category: 'mobile', severity: 'low', title: 'Release build is not minified/obfuscated', why: 'Makes reverse-engineering the APK (and finding embedded keys/logic) trivial.', fix: 'Enable minifyEnabled true with R8/ProGuard rules for release.' });
      const s = /storePassword\s*(=\s*)?["']([^"']+)["']|keyPassword\s*(=\s*)?["']([^"']+)["']/.exec(c);
      if (s) { ctx.secretValues.add(s[2] || s[4]); ctx.at(f, s.index, { category: 'secrets', severity: 'critical', title: 'Signing key password hardcoded in build.gradle', why: 'With the keystore and this password, anyone can sign malicious updates as your app.', fix: 'Read passwords from gradle.properties (git-ignored) or environment variables.' }); }
    }

    // ---------- iOS ----------
    for (const f of det.iosPlists) {
      const c = p.read(f) || '';
      const m = /<key>NSAllowsArbitraryLoads<\/key>\s*<true\s*\/>/.exec(c);
      if (m) {
        const fd = ctx.at(f, m.index, { category: 'mobile', severity: 'high', title: 'iOS App Transport Security is disabled', why: 'NSAllowsArbitraryLoads lets the app use plain HTTP to any server.', fix: 'Remove it (or set false) and add narrow exceptions only for domains that need them.' });
        ctx.applyEdits(f, [{ index: m.index, old: m[0], new: m[0].replace(/<true\s*\/>/, '<false/>'), finding: fd, summary: 'ATS re-enabled (NSAllowsArbitraryLoads = false).' }]);
      }
    }

    // ---------- Expo / RN / Flutter code ----------
    const insecureStore = [];
    for (const f of p.codeFiles((x) => /\.(m|c)?(js|ts)x?$|\.dart$|\.(kt|java|swift)$/.test(x)).map((x) => x.path)) {
      const c = p.read(f) || '';
      let m;
      if ((m = /AsyncStorage\.setItem\(\s*['"`][^'"`]*(token|jwt|auth|session|password|secret|key)[^'"`]*['"`]/i.exec(c))) insecureStore.push({ f, i: m.index, what: 'AsyncStorage', fix: 'Use expo-secure-store or react-native-keychain for tokens.' });
      if ((m = /(SharedPreferences|prefs)\.(setString|edit\(\)\.putString)\(\s*['"][^'"]*(token|jwt|auth|password|secret)[^'"]*['"]/i.exec(c))) insecureStore.push({ f, i: m.index, what: 'SharedPreferences', fix: 'Use flutter_secure_storage / EncryptedSharedPreferences.' });
      if ((m = /UserDefaults\.standard\.set\([^)]*forKey:\s*"[^"]*(token|password|secret)/i.exec(c))) insecureStore.push({ f, i: m.index, what: 'UserDefaults', fix: 'Store tokens in the iOS Keychain.' });
      if ((m = /addJavascriptInterface\(/.exec(c))) ctx.at(f, m.index, { category: 'mobile', severity: 'high', title: 'WebView exposes a JavaScript bridge', why: 'Any page loaded in the WebView (or injected script) can call native code.', fix: 'Load only your own HTTPS content in that WebView and validate every bridge call.' });
      if ((m = /originWhitelist=\{\s*\[\s*['"]\*['"]\s*\]\s*\}/.exec(c))) ctx.at(f, m.index, { category: 'mobile', severity: 'medium', title: "WebView allows any origin (originWhitelist={['*']})", why: 'The WebView can navigate to attacker pages that then talk to your app.', fix: "Restrict to your own domains, e.g. originWhitelist={['https://yourapp.com']}." });
      if ((m = /setAllowFileAccess\(\s*true|allowFileAccess(FromFileURLs)?=\{\s*true/.exec(c))) ctx.at(f, m.index, { category: 'mobile', severity: 'medium', title: 'WebView file access enabled', why: 'Malicious content can read local app files.', fix: 'Disable file access unless required.' });
      if ((m = /badCertificateCallback\s*=\s*\([^)]*\)\s*=>\s*true|onReceivedSslError[\s\S]{0,200}proceed\(\)|trustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER/.exec(c))) ctx.at(f, m.index, { category: 'https', severity: 'critical', title: 'App accepts any TLS certificate', why: 'All HTTPS traffic can be intercepted with a fake certificate.', fix: 'Remove the override; fix the certificate on the server instead.' });
    }
    for (const s of insecureStore.slice(0, 5)) ctx.at(s.f, s.i, { category: 'mobile', severity: 'medium', title: `Sensitive data stored in ${s.what}`, why: `${s.what} is unencrypted and readable on rooted/jailbroken devices and from backups.`, fix: s.fix });

    // Expo config: secrets in app.json extra
    for (const f of [...p.byName('app.json'), ...p.byName('app.config.js'), ...p.byName('app.config.ts')]) {
      const c = p.read(f) || '';
      const m = /"?extra"?\s*:\s*\{[^}]*(secret|private|service_role|sk_live|password)/i.exec(c);
      if (m) ctx.at(f, m.index, { category: 'mobile', severity: 'high', title: 'Secret-looking value in Expo "extra" config', why: 'Everything in app config is bundled into the app and readable by users.', fix: 'Keep only public values in the app; move secrets to your backend.' });
    }
    ctx.note('Mobile apps can always be unpacked: never ship private API keys in the app. Put sensitive calls behind your own backend, and consider certificate pinning for high-value apps.');
    void posix;
  },
};
