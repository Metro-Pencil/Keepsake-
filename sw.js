// Bump this string on any deploy that changes index.html, app.js, or any
// other shell file. It's the only way the browser notices sw.js itself
// changed and re-fetches the shell — otherwise installed PWAs can get
// stuck on an old cached version forever. See the "Force refresh" button
// in Settings for a manual way out of that if a deploy forgets to.
const CACHE_NAME = 'keepsake-shell-v7';
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
    caches.open(CACHE_NAME).then((cache) =>
      Promise.all(SHELL_FILES.map((url) =>
        // `cache: 'reload'` is the important part here — it bypasses the
        // browser's own HTTP disk cache, not just this Cache Storage
        // bucket. A plain fetch() (what cache.addAll() uses internally)
        // can silently hand back an old, still-"fresh" cached response
        // with no network request at all, which means a brand new SW
        // version — even one installed by the "Force refresh" button —
        // could precache the exact same stale files it was meant to
        // replace. This forces every shell file to actually come from
        // the network on every install.
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
  // Only ever serve the app shell from cache. Anything cross-origin —
  // i.e. every call to your Worker — always goes straight to the network.
  // Offline access to *notes* isn't handled here: app.js keeps its own
  // copy of every note in IndexedDB and reads from that when a request
  // can't get through.
  if (url.origin !== self.location.origin) return;
  event.respondWith(
    caches.match(event.request).then((cached) => cached || fetch(event.request))
  );
});
