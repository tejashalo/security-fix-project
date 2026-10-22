'use strict';
// Caches the app shell so VibeGuard opens instantly and installs as an app.
// API calls are never cached (results stay private and fresh).
const CACHE = 'vibeguard-shell-v1';
const SHELL = ['/', '/index.html', '/styles.css', '/app.js', '/icon.svg', '/manifest.webmanifest'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin || url.pathname.startsWith('/api/')) return;
  const isPage = e.request.mode === 'navigate';
  e.respondWith(
    fetch(e.request)
      .then((res) => {
        if (res.ok && (isPage || SHELL.includes(url.pathname))) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(isPage ? '/' : e.request, copy)); }
        return res;
      })
      .catch(() => caches.match(isPage ? '/' : e.request).then((r) => r || caches.match('/')))
  );
});
