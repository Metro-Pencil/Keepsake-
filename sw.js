// Bump this string on any deploy that changes index.html, app.js, or any
// other shell file. It's the only way the browser notices sw.js itself
// changed and re-fetches the shell — otherwise installed PWAs can get
// stuck on an old cached version forever. See the "Force refresh" button
// in Settings for a manual way out of that if a deploy forgets to.
const CACHE_PREFIX = 'keepsake-shell-';
const CACHE_NAME = CACHE_PREFIX + 'v40';
const CRITICAL_FILES = [
  './',
  './index.html',
  './version.js',
  './app.js',
  './b2.js',
  './media.js',
  './video.js',
  './player.js',
  './devices.js',
  './offline.js',
];
const OPTIONAL_FILES = [
  './manifest.json',
  './icon-192.png',
  './icon-512.png',
  './icon-512-maskable.png',
  './font-inter-400.woff2',
  './font-inter-500.woff2',
  './font-inter-600.woff2',
  './font-inter-700.woff2',
  './font-serif-400.woff2',
  './font-serif-700.woff2',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      await Promise.all(CRITICAL_FILES.map(async (url) => {
        const response = await fetch(url, { cache: 'reload' });
        if (!response.ok) throw new Error('Failed to cache critical shell file: ' + url);
        await cache.put(url, response);
      }));
      await Promise.all(OPTIONAL_FILES.map((url) =>
        fetch(url, { cache: 'reload' })
          .then((response) => { if (response.ok) return cache.put(url, response); })
          .catch(() => {})
      ));
      await self.skipWaiting();
    })
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      // Only delete Keepsake's own old caches so sibling apps on the same GitHub Pages origin stay intact.
      .then((keys) => Promise.all(keys.filter((k) => k.startsWith(CACHE_PREFIX) && k !== CACHE_NAME).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;
  // Always let version-check probes hit the network directly.
  if (url.searchParams.has('_vcheck')) return;
  event.respondWith(
    caches.match(event.request, { cacheName: CACHE_NAME }).then((cached) => {
      if (cached) return cached;
      if (event.request.mode === 'navigate') {
        return caches.match(event.request, { cacheName: CACHE_NAME, ignoreSearch: true })
          .then((navMatch) => navMatch || caches.match('./index.html', { cacheName: CACHE_NAME }))
          .then((shell) => shell || fetch(event.request));
      }
      return fetch(event.request);
    })
  );
});
