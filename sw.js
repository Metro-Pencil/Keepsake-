// Bump this string on any deploy that changes index.html, app.js, or any
// other shell file. It's the only way the browser notices sw.js itself
// changed and re-fetches the shell — otherwise installed PWAs can get
// stuck on an old cached version forever. See the "Force refresh" button
// in Settings for a manual way out of that if a deploy forgets to.
const CACHE_NAME = 'keepsake-shell-v20';
const SHELL_FILES = [
  './',
  './index.html',
  './app.js',
  './b2.js',
  './media.js',
  './migrate.js',
  './manifest.json',
  './icon-192.png',
  './icon-512.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) =>
      Promise.all(SHELL_FILES.map((url) =>
        fetch(url, { cache: 'reload' })
          .then((response) => { if (response.ok) return cache.put(url, response); })
          .catch(() => { /* best-effort — one missing file shouldn't fail install */ })
      ))
    )
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;
  event.respondWith(
    caches.match(event.request).then((cached) => cached || fetch(event.request))
  );
});
