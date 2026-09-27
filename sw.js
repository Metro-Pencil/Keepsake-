// Bump this string on any deploy that changes index.html, app.js, or any
// other shell file. It's the only way the browser notices sw.js itself
// changed and re-fetches the shell — otherwise installed PWAs can get
// stuck on an old cached version forever. See the "Force refresh" button
// in Settings for a manual way out of that if a deploy forgets to.
const CACHE_NAME = 'keepsake-shell-v4';
const SHELL_FILES = [
  './',
  './index.html',
  './app.js',
  './manifest.json',
  './icon-192.png',
  './icon-512.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(SHELL_FILES))
      .catch(() => { /* best-effort — first load can still work online */ })
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
  // Only ever serve the app shell from cache. Anything cross-origin —
  // i.e. every call to your Worker — always goes straight to the network,
  // so notes are never served stale or offline.
  if (url.origin !== self.location.origin) return;
  event.respondWith(
    caches.match(event.request).then((cached) => cached || fetch(event.request))
  );
});
