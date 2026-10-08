/* Keepsake — app.js
 * A private notebook with per-note quick locks and time locks.
 * No build step, no framework — plain DOM + fetch, meant to be read top to bottom.
 */

/* ---------------------------------------------------------------------
 * Crypto core
 * ------------------------------------------------------------------- */

const SEP = '\u241F'; // unit separator — combines password1 + password2 for time-locked notes
const PBKDF2_ITERATIONS = 250000;

function bytesToB64(bytes) {
  if (bytes.toBase64) return bytes.toBase64(); // native, where the browser has it
  // Build the binary string in chunks: one-character-at-a-time concatenation
  // over a multi-megabyte note was a measurable slice of every save and open.
  let binary = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

function b64ToBytes(str) {
  if (Uint8Array.fromBase64) return Uint8Array.fromBase64(str);
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function randomBytes(len) {
  return crypto.getRandomValues(new Uint8Array(len));
}

// Password 2: a random secret Keepsake generates for time-locked notes.
// Never shown in the UI — it only travels inside a downloaded note file.
function generateSecondPassword() {
  return bytesToB64(randomBytes(24));
}

function combine(password1, password2) {
  return password2 ? password1 + SEP + password2 : password1;
}

async function deriveKey(passphrase, saltBytes) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptNote(passphrase, noteObj) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveKey(passphrase, salt);
  const enc = new TextEncoder();
  const plaintext = enc.encode(JSON.stringify(noteObj));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  return { salt: bytesToB64(salt), iv: bytesToB64(iv), ciphertext: bytesToB64(new Uint8Array(ciphertext)) };
}

async function decryptNote(passphrase, record) {
  const salt = b64ToBytes(record.salt);
  const iv = b64ToBytes(record.iv);
  const key = await deriveKey(passphrase, salt);
  const ciphertext = b64ToBytes(record.ciphertext);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return JSON.parse(new TextDecoder().decode(plaintext));
}

/* ---------------------------------------------------------------------
 * Config + API client
 * ------------------------------------------------------------------- */

// Photo / audio quality presets (Settings → Media quality). The size hints are
// rough: they depend on the picture or the voice, and a locked note stores
// everything about a third larger again (encryption is kept as text).
const PHOTO_QUALITY = {
  standard: { label: 'Standard', maxDim: 1600, quality: 0.82, hint: 'Resized to 1600px. Roughly 0.3\u20130.7 MB per photo.' },
  high:     { label: 'High',     maxDim: 2560, quality: 0.92, hint: 'Resized to 2560px, light compression. Roughly 1\u20132.5 MB per photo.' },
  original: { label: 'Original', maxDim: 0,    quality: 1,    hint: 'Kept exactly as taken \u2014 no resizing or re-compression. Often 3\u20138 MB per photo, and it keeps the photo\u2019s location data.' },
};
const AUDIO_QUALITY = {
  standard: { label: 'Standard', bps: 64000,  hint: 'Clear for voice. About 0.6 MB per minute.' },
  high:     { label: 'High',     bps: 128000, hint: 'Good for voice and music. About 1.3 MB per minute.' },
  max:      { label: 'Maximum',  bps: 256000, hint: 'Best the browser offers. About 2.6 MB per minute.' },
};

const Config = {
  base() { return localStorage.getItem('ks_apiBase') || ''; },
  token() { return localStorage.getItem('ks_token') || ''; },
  setBase(v) { localStorage.setItem('ks_apiBase', v.trim().replace(/\/+$/, '')); },
  setToken(v) { localStorage.setItem('ks_token', v.trim()); },
  configured() { return !!(this.base() && this.token()); },
  photoQuality() { const v = localStorage.getItem('ks_photoQuality'); return PHOTO_QUALITY[v] ? v : 'high'; },
  setPhotoQuality(v) { localStorage.setItem('ks_photoQuality', v); },
  audioQuality() { const v = localStorage.getItem('ks_audioQuality'); return AUDIO_QUALITY[v] ? v : 'high'; },
  setAudioQuality(v) { localStorage.setItem('ks_audioQuality', v); },
  // Free plan: 1 GB for the whole account. People on a paid Workers plan can raise it.
  storageLimitMB() { const n = Number(localStorage.getItem('ks_storageLimitMB')); return n >= 50 ? n : 1000; },
  setStorageLimitMB(n) { localStorage.setItem('ks_storageLimitMB', String(Math.round(n))); },
};

const API = {
  async request(path, opts = {}) {
    let res;
    try {
      res = await fetch(Config.base() + path, {
        ...opts,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + Config.token(),
          ...(opts.headers || {}),
        },
      });
    } catch (e) {
      // fetch() only rejects when the request never got an HTTP response at
      // all (offline, DNS, dropped connection). Flagged so callers can treat
      // that as "queue it locally", unlike a 401/500 which is a real error.
      const err = new Error('Network error — check your connection');
      err.isNetworkError = true;
      throw err;
    }
    if (!res.ok) {
      let body = {};
      try { body = await res.json(); } catch (e) { /* non-JSON error body */ }
      const err = new Error(body.error || ('Request failed (' + res.status + ')'));
      err.status = res.status;
      err.body = body;
      throw err;
    }
    return res.json();
  },
  // Same contract as request() (resolves with parsed JSON, rejects with an
  // Error carrying .status/.body, or .isNetworkError for a connection-level
  // failure) but over XHR instead of fetch, so we can report real upload
  // progress for payloads that carry photos.
  requestWithProgress(path, method, payload, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open(method, Config.base() + path);
      xhr.setRequestHeader('Content-Type', 'application/json');
      xhr.setRequestHeader('Authorization', 'Bearer ' + Config.token());
      if (onProgress) {
        xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(e.loaded / e.total); };
      }
      xhr.onload = () => {
        let body = {};
        try { body = JSON.parse(xhr.responseText); } catch (e) { /* non-JSON error body */ }
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(body);
        } else {
          const err = new Error(body.error || ('Request failed (' + xhr.status + ')'));
          err.status = xhr.status;
          err.body = body;
          reject(err);
        }
      };
      const networkFail = () => {
        const err = new Error('Network error — check your connection');
        err.isNetworkError = true;
        reject(err);
      };
      xhr.onerror = networkFail;
      xhr.ontimeout = networkFail;
      xhr.onabort = networkFail;
      xhr.send(JSON.stringify(payload));
    });
  },

  listNotes() { return this.request('/api/notes'); },
  getNote(id) { return this.request('/api/notes/' + id); },
  // Always a PUT to a client-generated id — see worker.js's upsertNote.
  // There's no separate "create" call anymore: a note's first save and
  // every save after it go through the exact same idempotent path, so
  // retrying a save that looked like it failed can never create a
  // duplicate note — it just overwrites the same one.
  // Photos and audio that were moved out to Backblaze (see media.js) go up first, through the
  // Worker; the note itself \u2014 by then just text and references \u2014 follows. Both the editor's
  // saves and the offline queue come through here, so a queued note uploads its media too.
  async saveNote(id, payload, onProgress) {
    let uploaded = 0;
    if (payload && payload.mediaKeep && payload.mediaKeep.length && window.KSMedia) {
      uploaded = await KSMedia.uploadPending(id, payload.mediaKeep, onProgress);
    }
    return this.requestWithProgress('/api/notes/' + id, 'PUT', payload, uploaded ? null : onProgress);
  },
  deleteNote(id) { return this.request('/api/notes/' + id, { method: 'DELETE' }); },
  getVault(id) { return this.request('/api/notes/' + id + '/vault'); },
  exportNote(id) { return this.request('/api/notes/' + id + '/export'); },
};

/* ---------------------------------------------------------------------
 * Image handling — resize/compress before it ever leaves the device
 * ------------------------------------------------------------------- */

function loadImageFromFile(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => { URL.revokeObjectURL(url); resolve(img); };
    img.onerror = (e) => { URL.revokeObjectURL(url); reject(e); };
    img.src = url;
  });
}

async function fileToCompressedDataURL(file, maxDim = 1600, quality = 0.82) {
  const img = await loadImageFromFile(file);
  let { width, height } = img;
  if (width > maxDim || height > maxDim) {
    const scale = maxDim / Math.max(width, height);
    width = Math.round(width * scale);
    height = Math.round(height * scale);
  }
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  // JPEG has no alpha: without a backdrop, transparent areas (PNG logos,
  // screenshots, stickers) come out solid black.
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, width, height);
  ctx.drawImage(img, 0, 0, width, height);
  return canvas.toDataURL('image/jpeg', quality);
}

function readFileAsDataURL(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result);
    r.onerror = () => reject(r.error);
    r.readAsDataURL(file);
  });
}

// Stores a photo at the quality chosen in Settings. "Original" keeps the
// file's own bytes (after checking this browser can actually display it).
async function fileToStoredDataURL(file) {
  const q = PHOTO_QUALITY[Config.photoQuality()];
  if (!q.maxDim) {
    await loadImageFromFile(file);
    return readFileAsDataURL(file);
  }
  return fileToCompressedDataURL(file, q.maxDim, q.quality);
}

/* ---------------------------------------------------------------------
 * Size limits.
 *   25 MB   Workers KV's hard cap on one value — content:{id} holds a note's
 *           text, photos, audio and drawing together, so this is the ceiling
 *           for all of it combined.
 *   12 MB   from here a note is slow to open and sync, especially on mobile data.
 *   20 MB   the Worker holds a note in memory several times over while it
 *           handles it (128 MB per request), and the Free plan allows only
 *           10 ms of CPU per request — so risk of a failed save rises here.
 *           (12 and 20 are this app's own cautious lines, not Cloudflare's.)
 * ------------------------------------------------------------------- */
const NOTE_SIZE_LIMIT = 25 * 1024 * 1024;
const NOTE_HEAVY_BYTES = 12 * 1024 * 1024;
const NOTE_DANGER_BYTES = 20 * 1024 * 1024;
// With Backblaze set up (media.js), photos and audio no longer count toward the 25 MB above —
// the note only keeps small references. They are still held in memory while a note is open,
// so there is a ceiling on how much one note carries. (Sizes here are base64 text lengths.)
const MEDIA_ITEM_MAX_CHARS = 120 * 1024 * 1024;  // one file, about 90 MB of real data
const MEDIA_NOTE_MAX_CHARS = 200 * 1024 * 1024;  // all of a note's photos + audio, about 150 MB
function limitWord() { return mediaOffloadOn() ? 'its 150 MB of photos and audio' : '25 MB'; }
function mediaOffloadOn() { return !!(window.KSMedia && KSMedia.enabled()); }
function mediaZone(chars) {
  const r = chars / MEDIA_NOTE_MAX_CHARS;
  return r > 1 ? 'over' : r >= 0.85 ? 'danger' : r >= 0.6 ? 'heavy' : 'ok';
}
const STORAGE_WARN_RATIO = 0.7;
const STORAGE_DANGER_RATIO = 0.9;

function noteSizeZone(bytes) {
  if (bytes > NOTE_SIZE_LIMIT) return 'over';
  if (bytes >= NOTE_DANGER_BYTES) return 'danger';
  if (bytes >= NOTE_HEAVY_BYTES) return 'heavy';
  return 'ok';
}

// What the note open in the editor will take up once saved — from string
// lengths, so it is cheap enough to run as you type. A locked note is bigger
// than its contents: the encrypted bytes are stored as base64 text.
function noteSizeBreakdown() {
  const body = document.getElementById('editor-body');
  const text = utf8Len(document.getElementById('editor-title').value) + utf8Len(body.innerHTML) * 2; // html + its plain-text copy
  let photos = 0;
  for (const src of editorImages) photos += src.length + 4;
  let audio = 0;
  let clips = 0;
  const seen = new Set();
  body.querySelectorAll('ks-audio').forEach((el) => {
    const id = el.getAttribute('data-id');
    if (seen.has(id) || !editorAudio[id]) return;
    seen.add(id);
    audio += editorAudio[id].data.length + 120;
    clips++;
  });
  const drawing = inkEstimateBytes();
  // Offloaded media: only a reference + manifest entry stays in the note.
  const mediaChars = photos + audio;
  const offload = mediaOffloadOn();
  let offloaded = 0;
  if (offload) {
    offloaded = Math.round(mediaChars * 3 / 4);
    photos = editorImages.length * 160;
    audio = clips * 260;
  }
  let total = 160 + text + photos + audio + drawing;
  const locked = lockIsActive();
  let lockExtra = 0;
  if (locked) {
    const encrypted = Math.ceil((total + 16) * 4 / 3) + 80;
    lockExtra = encrypted - total;
    total = encrypted;
  }
  return { text, photos, photoCount: editorImages.length, audio, clips, drawing, lockExtra, locked, total, offload, offloaded, mediaChars };
}

function estimateContentBytes() { return noteSizeBreakdown().total; }

// Cheap fingerprint of a big base64 string (length + 48 sampled characters),
// so "did the photos/audio change?" doesn't mean comparing megabytes of text.
function mediaSig(str) {
  str = String(str || '');
  let sig = str.length + ':';
  const step = Math.max(1, Math.floor(str.length / 48));
  for (let i = 0; i < str.length; i += step) sig += str[i];
  return sig + str.slice(-16);
}

// Identity of a snapshot's photos + audio — what decides "Saving photos…".
function mediaKey(snapshot) {
  const audio = snapshot.audio || {};
  return JSON.stringify([
    (snapshot.images || []).map(mediaSig),
    Object.keys(audio).sort().map((id) => id + mediaSig(audio[id].data)),
  ]);
}

// Same as JSON.stringify(snapshot) for "has anything changed?" purposes, but
// with the big media fingerprinted instead of copied.
function snapshotKey(snapshot) {
  const audio = {};
  for (const id of Object.keys(snapshot.audio || {}).sort()) {
    audio[id] = mediaSig(snapshot.audio[id].data) + '|' + snapshot.audio[id].dur + '|' + snapshot.audio[id].name;
  }
  return JSON.stringify({ ...snapshot, images: (snapshot.images || []).map(mediaSig), audio });
}

// Precise-enough byte size of one compressed photo, straight from its
// base64 data URL — used both for the per-photo size shown under each
// thumbnail/in the lightbox, and (summed) for the 25MB ceiling check above.
function estimateImageBytes(dataUrl) {
  const comma = dataUrl.indexOf(',');
  const base64 = comma >= 0 ? dataUrl.slice(comma + 1) : dataUrl;
  const len = base64.length;
  const padding = base64.endsWith('==') ? 2 : base64.endsWith('=') ? 1 : 0;
  return Math.max(0, Math.round((len * 3) / 4) - padding);
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return Math.round(bytes / 1024) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

/* ---------------------------------------------------------------------
 * Size accounting — how many bytes a note takes up in Workers KV. Measured
 * from string lengths (photos and audio are base64 text), not by
 * serialising, so it is cheap enough to run while you type.
 * ------------------------------------------------------------------- */

function utf8Len(s) {
  s = String(s || '');
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xD800 && c <= 0xDBFF) { n += 4; i++; }
    else n += 3;
  }
  return n;
}

// The size of a content object as the server stores it.
function contentStoredBytes(c) {
  if (!c) return 0;
  if (typeof c.ciphertext === 'string') {
    return c.ciphertext.length + String(c.salt || '').length + String(c.iv || '').length + 80;
  }
  let n = 160;
  n += utf8Len(c.title) + utf8Len(c.body) + utf8Len(c.html);
  for (const src of c.images || []) n += typeof src === 'string' ? src.length + 4 : 0;
  if (c.audio) for (const k in c.audio) n += (c.audio[k] && typeof c.audio[k].data === 'string' ? c.audio[k].data.length : 0) + 120;
  if (c.drawing && Array.isArray(c.drawing.strokes)) for (const s of c.drawing.strokes) n += (s.p ? s.p.length : 0) * 7 + 40;
  return n;
}

/* ---------------------------------------------------------------------
 * IndexedDB — one database. Light records and heavy records live in
 * SEPARATE stores, because IndexedDB can only read or write a record whole:
 * keeping a note's multi-megabyte content next to its title meant every
 * little update (a title, a password, a "last seen" stamp) re-read and
 * re-wrote all of it. That was the main reason opening a note felt slow.
 *
 *   drafts         - a same-device safety net for an *abrupt* close only
 *                    (crash, dead battery, a swiped-away tab). Cleared the
 *                    moment its content reaches the server OR the outbox.
 *   noteCache      - LIGHT: one small record per note — its metadata, the
 *                    cached locked title / second password, flags and sizes.
 *                    The grid renders from this alone.
 *   noteContent    - HEAVY: the note's content (encrypted or plain, exactly
 *                    as the server stores it). Touched only when a note is
 *                    opened, downloaded or its content actually changes.
 *   outbox         - LIGHT: { id, op, queuedAt } for every note with a local
 *                    change the server hasn't seen (a save or a delete).
 *   outboxPayload  - HEAVY: the exact PUT payload for a queued save.
 * ------------------------------------------------------------------- */

const KEEPSAKE_DB_NAME = 'keepsake-drafts'; // unchanged so existing installs upgrade in place
const KEEPSAKE_DB_VERSION = 3;
const DRAFT_STORE = 'drafts';
const NOTE_CACHE_STORE = 'noteCache';
const NOTE_CONTENT_STORE = 'noteContent';
const OUTBOX_STORE = 'outbox';
const OUTBOX_PAYLOAD_STORE = 'outboxPayload';

// One shared connection instead of opening a fresh one for every little read.
let dbPromise = null;

function migrateToV3(tx) {
  // v2 kept content inside the noteCache records and payloads inside outbox
  // records. Move the heavy part out, once, and leave a light record behind.
  const cache = tx.objectStore(NOTE_CACHE_STORE);
  const content = tx.objectStore(NOTE_CONTENT_STORE);
  cache.openCursor().onsuccess = (e) => {
    const cur = e.target.result;
    if (!cur) return;
    const v = cur.value || {};
    const light = { ...v, hasContent: !!v.content };
    if (v.content) {
      content.put({ id: v.id, content: v.content });
      light.bytes = contentStoredBytes(v.content);
    }
    if (v.vault) light.vaultUpdatedAt = v.meta ? v.meta.updatedAt : undefined;
    delete light.content;
    cur.update(light);
    cur.continue();
  };
  const outbox = tx.objectStore(OUTBOX_STORE);
  const payloads = tx.objectStore(OUTBOX_PAYLOAD_STORE);
  outbox.openCursor().onsuccess = (e) => {
    const cur = e.target.result;
    if (!cur) return;
    const v = cur.value || {};
    if (v.payload) payloads.put({ id: v.id, payload: v.payload });
    cur.update({ id: v.id, op: v.op, queuedAt: v.queuedAt });
    cur.continue();
  };
}

function openKeepsakeDB() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    if (!window.indexedDB) { dbPromise = null; reject(new Error('IndexedDB unavailable')); return; }
    const req = indexedDB.open(KEEPSAKE_DB_NAME, KEEPSAKE_DB_VERSION);
    req.onupgradeneeded = (ev) => {
      const db = req.result;
      for (const [name, keyPath] of [
        [DRAFT_STORE, 'id'], [NOTE_CACHE_STORE, 'id'], [NOTE_CONTENT_STORE, 'id'],
        [OUTBOX_STORE, 'id'], [OUTBOX_PAYLOAD_STORE, 'id'],
      ]) {
        if (!db.objectStoreNames.contains(name)) db.createObjectStore(name, { keyPath });
      }
      if (ev.oldVersion > 0 && ev.oldVersion < 3) migrateToV3(req.transaction);
    };
    req.onsuccess = () => {
      const db = req.result;
      db.onversionchange = () => { db.close(); dbPromise = null; };
      db.onclose = () => { dbPromise = null; };
      resolve(db);
    };
    req.onerror = () => { dbPromise = null; reject(req.error); };
  });
  return dbPromise;
}

// Runs fn(tx) in one transaction and resolves when it has committed.
function idbRun(db, stores, mode, fn) {
  return new Promise((resolve, reject) => {
    let tx;
    try { tx = db.transaction(stores, mode); } catch (e) { reject(e); return; }
    let result;
    try { result = fn(tx); } catch (e) { try { tx.abort(); } catch (e2) { /* already done */ } reject(e); return; }
    tx.oncomplete = () => resolve(result);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error || new Error('Transaction aborted'));
  });
}

function idbPut(db, store, value) { return idbRun(db, store, 'readwrite', (tx) => { tx.objectStore(store).put(value); }); }
function idbDelete(db, store, key) { return idbRun(db, store, 'readwrite', (tx) => { tx.objectStore(store).delete(key); }); }
function idbPutMany(db, entries) {
  return idbRun(db, [...new Set(entries.map((e) => e[0]))], 'readwrite', (tx) => {
    for (const [store, value] of entries) tx.objectStore(store).put(value);
  });
}
function idbDeleteMany(db, entries) {
  return idbRun(db, [...new Set(entries.map((e) => e[0]))], 'readwrite', (tx) => {
    for (const [store, key] of entries) tx.objectStore(store).delete(key);
  });
}

function idbRequest(db, store, method, arg) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readonly');
    const req = tx.objectStore(store)[method](arg);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function idbGet(db, store, key) { return (await idbRequest(db, store, 'get', key)) || null; }
async function idbGetAll(db, store) { return (await idbRequest(db, store, 'getAll')) || []; }
async function idbGetAllKeys(db, store) { return (await idbRequest(db, store, 'getAllKeys')) || []; }

async function saveLocalDraft(id, title, body, images, html, drawing, audio) {
  if (!id) return;
  try {
    const db = await openKeepsakeDB();
    await idbPut(db, DRAFT_STORE, { id, title, body, images, html, drawing, audio, savedAt: Date.now() });
  } catch (e) {
    // Best-effort only — local caching should never interrupt the editor.
  }
}

async function loadLocalDraft(id) {
  try {
    const db = await openKeepsakeDB();
    return await idbGet(db, DRAFT_STORE, id);
  } catch (e) { return null; }
}

async function clearLocalDraft(id) {
  if (!id) return;
  try {
    const db = await openKeepsakeDB();
    await idbDelete(db, DRAFT_STORE, id);
  } catch (e) {
    // Worst case an orphaned draft lingers and gets offered for recovery
    // again later, which is harmless.
  }
}

async function listLocalDraftIds() {
  try {
    const db = await openKeepsakeDB();
    return await idbGetAllKeys(db, DRAFT_STORE);
  } catch (e) { return []; }
}

/* ---------------------------------------------------------------------
 * Note cache — the local mirror every render/open/download reads from.
 * ------------------------------------------------------------------- */

// `lockedTitle` is the title of a locked note as last seen decrypted on this
// device (older notes have no title on the server). Pass undefined to keep
// whatever is already cached, a string to set it, or null to clear it.
async function cacheNote(meta, content, lockedTitle) {
  try {
    const db = await openKeepsakeDB();
    const existing = await idbGet(db, NOTE_CACHE_STORE, meta.id);
    const light = {
      id: meta.id,
      meta,
      contentUpdatedAt: meta.updatedAt, // which version of the note the cached content is
      hasContent: true,
      bytes: contentStoredBytes(content),
      lockedTitle: lockedTitle === undefined ? (existing ? existing.lockedTitle : undefined) : lockedTitle,
      vault: existing ? existing.vault : undefined,
      vaultUpdatedAt: existing ? existing.vaultUpdatedAt : undefined,
      cachedAt: Date.now(),
    };
    await idbPutMany(db, [[NOTE_CACHE_STORE, light], [NOTE_CONTENT_STORE, { id: meta.id, content }]]);
  } catch (e) { /* best-effort — a failed cache write just means this one note won't be available offline yet */ }
}

// Used when only fresh *metadata* is on hand (the list endpoint doesn't
// return content). The cached content stays exactly where it is; its
// contentUpdatedAt is deliberately left alone, so a newer meta.updatedAt
// shows up as "cached content is out of date" to prefetchOfflineData and to
// fetchNoteContent.
async function cacheNoteMetaOnly(meta) {
  try {
    const db = await openKeepsakeDB();
    const existing = await idbGet(db, NOTE_CACHE_STORE, meta.id);
    if (existing && JSON.stringify(existing.meta) === JSON.stringify(meta)) return; // nothing new to write
    await idbPut(db, NOTE_CACHE_STORE, {
      id: meta.id,
      meta,
      contentUpdatedAt: existing ? existing.contentUpdatedAt : undefined,
      hasContent: !!(existing && existing.hasContent),
      bytes: existing ? existing.bytes : undefined,
      lockedTitle: existing ? existing.lockedTitle : undefined,
      vault: existing ? existing.vault : undefined,
      vaultUpdatedAt: existing ? existing.vaultUpdatedAt : undefined,
      cachedAt: Date.now(),
    });
  } catch (e) { /* best-effort */ }
}

// Remembers a locked note's title once it's been seen decrypted on this
// device (after unlocking it). No-op if the note isn't cached yet.
async function setLockedTitle(id, title) {
  try {
    const db = await openKeepsakeDB();
    const existing = await idbGet(db, NOTE_CACHE_STORE, id);
    if (!existing || existing.lockedTitle === title) return;
    await idbPut(db, NOTE_CACHE_STORE, { ...existing, lockedTitle: title });
    await rerenderFromLocal();
  } catch (e) { /* best-effort */ }
}

// Older Workers return title:null for locked notes. Once any response shows
// a string there, we know the Worker has been redeployed and it's worth
// re-saving old locked notes (when they're next opened) to give them a title.
function learnServerTitleSupport(metas) {
  if (metas.some((m) => m && m.lockType !== 'none' && typeof m.title === 'string')) {
    try { localStorage.setItem('ks_titlesOnServer', '1'); } catch (e) { /* private mode — harmless */ }
  }
}

// `forUpdatedAt` is the version of the note this second password belongs to,
// so a copy from before the note was re-locked elsewhere is never trusted.
async function cacheVault(id, password2, forUpdatedAt) {
  try {
    const db = await openKeepsakeDB();
    const existing = await idbGet(db, NOTE_CACHE_STORE, id);
    if (!existing) return; // no meta for this note yet — nothing to attach it to
    await idbPut(db, NOTE_CACHE_STORE, {
      ...existing,
      vault: password2,
      vaultUpdatedAt: forUpdatedAt != null ? forUpdatedAt : (existing.meta ? existing.meta.updatedAt : undefined),
      cachedAt: Date.now(),
    });
  } catch (e) { /* best-effort */ }
}

// Light record only (no content) — cheap.
async function getCachedMeta(id) {
  try {
    const db = await openKeepsakeDB();
    return await idbGet(db, NOTE_CACHE_STORE, id);
  } catch (e) { return null; }
}

async function getCachedContent(id) {
  try {
    const db = await openKeepsakeDB();
    const rec = await idbGet(db, NOTE_CONTENT_STORE, id);
    return rec ? rec.content : null;
  } catch (e) { return null; }
}

// Light record + content, joined (downloads and offline fallbacks).
async function getCachedNote(id) {
  try {
    const [light, content] = await Promise.all([getCachedMeta(id), getCachedContent(id)]);
    return light ? { ...light, content } : null;
  } catch (e) { return null; }
}

// Light records only — never loads any note's content.
async function getAllCachedNotes() {
  try {
    const db = await openKeepsakeDB();
    return await idbGetAll(db, NOTE_CACHE_STORE);
  } catch (e) { return []; }
}

async function removeCachedNote(id) {
  try {
    const db = await openKeepsakeDB();
    await idbDeleteMany(db, [[NOTE_CACHE_STORE, id], [NOTE_CONTENT_STORE, id]]);
  } catch (e) { /* best-effort */ }
  if (window.KSMedia) { try { await KSMedia.dropNote(id); } catch (e) { /* best-effort */ } }
}

// The list the grid actually renders: every cached note's metadata, flagged
// _pending when it has a queued-but-not-yet-synced change, with the size we
// know for it (from the server if it says, else measured from the cached copy).
async function buildNotesCacheFromLocal() {
  const [cached, outboxIds] = await Promise.all([getAllCachedNotes(), getOutboxIds()]);
  const pending = new Set(outboxIds);
  const metas = cached.map((c) => ({
    ...c.meta,
    _pending: pending.has(c.id),
    _lockedTitle: c.lockedTitle || '',
    _bytes: typeof c.meta.size === 'number' ? c.meta.size : (typeof c.bytes === 'number' ? c.bytes : null),
    _media: typeof c.meta.mediaSize === 'number' ? c.meta.mediaSize : 0, // photos + audio held in Backblaze
  }));
  metas.sort((x, y) => (y.updatedAt || 0) - (x.updatedAt || 0));
  return metas;
}

/* ---------------------------------------------------------------------
 * Outbox — notes with a save or delete the server hasn't seen yet.
 * ------------------------------------------------------------------- */

async function queueOutbox(id, op, payload) {
  try {
    const db = await openKeepsakeDB();
    await idbRun(db, [OUTBOX_STORE, OUTBOX_PAYLOAD_STORE], 'readwrite', (tx) => {
      tx.objectStore(OUTBOX_STORE).put({ id, op, queuedAt: Date.now() });
      const payloads = tx.objectStore(OUTBOX_PAYLOAD_STORE);
      if (op === 'save' && payload) payloads.put({ id, payload }); else payloads.delete(id);
    });
  } catch (e) { /* best-effort */ }
  await refreshOutboxCount();
}

async function clearOutbox(id) {
  try {
    const db = await openKeepsakeDB();
    await idbDeleteMany(db, [[OUTBOX_STORE, id], [OUTBOX_PAYLOAD_STORE, id]]);
  } catch (e) { /* best-effort */ }
  await refreshOutboxCount();
}

async function getOutbox() { // light entries only: { id, op, queuedAt }
  try {
    const db = await openKeepsakeDB();
    return await idbGetAll(db, OUTBOX_STORE);
  } catch (e) { return []; }
}

async function getOutboxIds() {
  try {
    const db = await openKeepsakeDB();
    return await idbGetAllKeys(db, OUTBOX_STORE);
  } catch (e) { return []; }
}

async function getOutboxItem(id) {
  try {
    const db = await openKeepsakeDB();
    return await idbGet(db, OUTBOX_STORE, id);
  } catch (e) { return null; }
}

async function getOutboxPayload(id) {
  try {
    const db = await openKeepsakeDB();
    const rec = await idbGet(db, OUTBOX_PAYLOAD_STORE, id);
    return rec ? rec.payload : null;
  } catch (e) { return null; }
}

/* ---------------------------------------------------------------------
 * Small helpers
 * ------------------------------------------------------------------- */

function escapeHTML(str) {
  return String(str || '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function fmtDate(ts) {
  if (!ts) return '';
  return new Date(ts).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

function fmtDateTime(ts) {
  if (!ts) return '';
  return new Date(ts).toLocaleString(undefined, {
    month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit',
  });
}

function fmtCountdown(unlockAt) {
  let diff = unlockAt - Date.now();
  if (diff <= 0) return null;
  const days = Math.floor(diff / 86400000); diff -= days * 86400000;
  const hours = Math.floor(diff / 3600000); diff -= hours * 3600000;
  const mins = Math.floor(diff / 60000);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${Math.max(mins, 1)}m`;
}

function makePreview(body) {
  return String(body || '').replace(/\s+/g, ' ').trim().slice(0, 180);
}

function localDatetimeInputMin() {
  const d = new Date(Date.now() + 60000);
  d.setSeconds(0, 0);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

let toastTimer;
function toast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 2400);
}

function show(id) {
  const el = document.getElementById(id);
  enhancePasswordInputs(el); // also covers the unlock dialog, whose fields are built fresh each time
  el.classList.remove('hidden');
  applyViewportFix();
}
function hide(id) {
  const el = document.getElementById(id);
  el.classList.add('hidden');
  if (id === 'overlay-record') recorderTeardown();
  if (id === 'overlay-clip') pauseClipPreview();
  if (id === 'overlay-editor') { clearAudioUrls(); clearThumbUrls(); }
  setPasswordsHidden(el); // never leave a password showing behind a closed dialog
  applyViewportFix();
}

/* ---------------------------------------------------------------------
 * Show/hide password (eye button)
 *
 * Every <input type="password"> gets an eye button the first time its
 * dialog opens. Dialogs re-hide their passwords when they close.
 * ------------------------------------------------------------------- */

const EYE_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>';
const EYE_OFF_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9.9 5.2A10 10 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-3.2 4M6.6 6.6A16.5 16.5 0 0 0 2 12s3.6 7 10 7a9.7 9.7 0 0 0 4.4-1"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/><path d="M3 3l18 18"/></svg>';

function setPasswordVisible(input, btn, visible) {
  input.type = visible ? 'text' : 'password';
  btn.setAttribute('aria-pressed', String(visible));
  btn.setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
  btn.title = visible ? 'Hide password' : 'Show password';
  btn.innerHTML = visible ? EYE_OFF_ICON : EYE_ICON;
}

function enhancePasswordInputs(root) {
  root.querySelectorAll('input[type="password"]:not([data-pw-enhanced])').forEach((input) => {
    input.dataset.pwEnhanced = '1';
    // A revealed password shouldn't be autocorrected, capitalised or spell-checked.
    input.setAttribute('autocapitalize', 'off');
    input.setAttribute('autocorrect', 'off');
    input.setAttribute('spellcheck', 'false');
    const wrap = document.createElement('div');
    wrap.className = 'pw-field';
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'pw-toggle';
    setPasswordVisible(input, btn, false);
    // Keep focus (and the on-screen keyboard) in the field while toggling.
    btn.addEventListener('mousedown', (e) => e.preventDefault());
    btn.addEventListener('click', () => setPasswordVisible(input, btn, input.type === 'password'));
    wrap.appendChild(btn);
  });
}

function setPasswordsHidden(root) {
  root.querySelectorAll('input[data-pw-enhanced]').forEach((input) => {
    const btn = input.parentNode.querySelector('.pw-toggle');
    if (btn && input.type !== 'password') setPasswordVisible(input, btn, false);
  });
}

/* ---------------------------------------------------------------------
 * Keyboard viewport fix
 *
 * Mobile browsers (iOS Safari/standalone in particular, and Android
 * Chrome) resize the *visual* viewport when the keyboard opens but leave
 * the *layout* viewport — the box `position: fixed` elements are pinned
 * to — alone. The full-screen editor and the centred dialogs are all
 * `inset: 0`, so they'd keep sizing themselves to the old, taller box:
 * the editor would leave a dark gap behind the keyboard, and a centred
 * dialog would be centred on a screen that's half hidden by the keyboard,
 * putting its password fields under it. Keeping their height and offset
 * in sync with `visualViewport` fixes both — the toolbar sits right above
 * the keyboard, and dialogs re-centre in the space that's actually left.
 * ------------------------------------------------------------------- */

function applyViewportFix() {
  const vv = window.visualViewport;
  document.querySelectorAll('#overlay-editor, .overlay').forEach((el) => {
    if (!vv || el.classList.contains('hidden')) {
      el.style.top = '';
      el.style.height = '';
      return;
    }
    el.style.top = vv.offsetTop + 'px';
    el.style.height = vv.height + 'px';
  });
}

function setupKeyboardViewportFix() {
  if (window.visualViewport) {
    window.visualViewport.addEventListener('resize', applyViewportFix);
    window.visualViewport.addEventListener('scroll', applyViewportFix);
  }
  // A focused field inside a dialog scrolls into the middle of what's left
  // once the keyboard has finished animating in.
  document.addEventListener('focusin', (e) => {
    const t = e.target;
    if (!t.closest || !t.closest('.modal') || !t.matches('input, textarea, select')) return;
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    setTimeout(() => t.scrollIntoView({ block: 'center', behavior: reduce ? 'auto' : 'smooth' }), 250);
  });
}

/* ---------------------------------------------------------------------
 * Sync bar — one status strip used for every kind of background progress:
 * autosave, the background upload after Save/close, and client-side photo
 * processing. Centralizing it here (rather than a bar inside the editor)
 * is what keeps it visible no matter what's on screen — it can't end up
 * scrolled below a stretched textarea or hidden behind a full-screen
 * overlay, which is what made the old photo-upload progress bar invisible.
 * ------------------------------------------------------------------- */

let syncBarHideTimer = null;

function syncBarSet(label, fraction /* number 0..1, or null for indeterminate */) {
  clearTimeout(syncBarHideTimer);
  const bar = document.getElementById('sync-bar');
  bar.classList.remove('error', 'done');
  bar.classList.add('show');
  document.getElementById('sync-bar-label').textContent = label;
  document.getElementById('sync-bar-retry').classList.add('hidden');
  const track = document.getElementById('sync-bar-track');
  const fill = document.getElementById('sync-bar-fill');
  if (fraction == null) {
    track.classList.add('indeterminate');
  } else {
    track.classList.remove('indeterminate');
    fill.style.width = (Math.max(0, Math.min(1, fraction)) * 100) + '%';
  }
}

function syncBarHideSoon(delay = 1100) {
  clearTimeout(syncBarHideTimer);
  syncBarHideTimer = setTimeout(() => {
    document.getElementById('sync-bar').classList.remove('show');
  }, delay);
}

function syncBarSuccess(label = 'Saved') {
  syncBarSet(label, 1);
  document.getElementById('sync-bar').classList.add('done'); // finished — stop the spinner
  syncBarHideSoon();
}

function syncBarError(label, onRetry) {
  clearTimeout(syncBarHideTimer);
  const bar = document.getElementById('sync-bar');
  bar.classList.remove('done');
  bar.classList.add('show', 'error');
  document.getElementById('sync-bar-label').textContent = label;
  const retryBtn = document.getElementById('sync-bar-retry');
  // Rebuilt fresh each time so repeated failures never stack up duplicate
  // click listeners on the same button.
  const freshRetry = retryBtn.cloneNode(true);
  freshRetry.classList.remove('hidden');
  retryBtn.parentNode.replaceChild(freshRetry, retryBtn);
  freshRetry.addEventListener('click', () => { bar.classList.remove('error'); onRetry(); });
}

/* ---------------------------------------------------------------------
 * Connection + sync status
 *
 * isOnline blends the browser's own online/offline events with what
 * actual requests report (navigator.onLine can say "online" on a dead
 * wifi network), and outboxCount is how many notes have a local change
 * the server hasn't seen yet. Together they drive the small pill in the
 * header, which is the one place "not synced" is shown.
 * ------------------------------------------------------------------- */

let isOnline = navigator.onLine;
let outboxCount = 0;
let isFlushing = false;

function updateSyncStatusUI() {
  const badge = document.getElementById('sync-status');
  if (!badge) return;
  if (!isOnline) {
    badge.textContent = outboxCount ? `Offline · ${outboxCount} not synced` : 'Offline';
    badge.className = 'sync-status';
  } else if (outboxCount > 0) {
    badge.textContent = outboxCount === 1 ? 'Not synced' : `${outboxCount} not synced`;
    badge.className = 'sync-status';
  } else {
    badge.textContent = '';
    badge.className = 'sync-status hidden';
  }
}

function setOnline(value) {
  if (isOnline === value) return;
  isOnline = value;
  updateSyncStatusUI();
}

async function refreshOutboxCount() {
  outboxCount = (await getOutboxIds()).length;
  updateSyncStatusUI();
}

async function rerenderFromLocal() {
  notesCache = await buildNotesCacheFromLocal();
  renderNotes();
  renderLocked();
  updateStoragePill();
  renderStorageSection();
}

// Pushes every queued save/delete to the server, oldest first. Stops at the
// first connection failure (the rest stay queued for next time); a real
// server error on one note leaves just that note queued and carries on.
async function flushOutbox() {
  if (isFlushing || !navigator.onLine) return;
  const items = (await getOutbox()).sort((a, b) => a.queuedAt - b.queuedAt);
  if (!items.length) return;
  isFlushing = true;
  try {
    for (const item of items) {
      // A live editor/background save is already handling this note — let it.
      const st = syncStateByNote.get(item.id);
      if (st && st.inFlight) continue;
      try {
        let result = null;
        let payload = null;
        if (item.op === 'delete') {
          try {
            await API.deleteNote(item.id);
          } catch (delErr) {
            // 404 = the server never had this note (or it's already gone),
            // which is exactly the outcome a delete wants. Treating it as a
            // failure left the delete queued forever — that was the
            // permanent "Not synced" pill.
            if (delErr.status !== 404) throw delErr;
          }
        } else {
          payload = await getOutboxPayload(item.id);
          if (!payload) { await clearOutbox(item.id); continue; } // nothing left to send
          result = await API.saveNote(item.id, payload);
        }
        setOnline(true);
        // If the note was edited again while this request was in flight, a
        // newer entry replaced this one in the outbox — leave that newer
        // one (and its cached copy) alone; the next flush sends it.
        const latest = await getOutboxItem(item.id);
        if (latest && latest.queuedAt !== item.queuedAt) continue;
        if (item.op === 'delete') {
          await removeCachedNote(item.id);
        } else {
          await cacheNote(result.note, payload.content);
          if (payload.lockType === 'time' && payload.password2) {
            await cacheVault(item.id, payload.password2, result.note.updatedAt);
          }
        }
        await clearOutbox(item.id);
      } catch (e) {
        if (e.isNetworkError) { setOnline(false); break; }
        // Real server error for this one item — leave it queued, keep going.
        // (Deletes of missing notes are handled above and never land here.)
      }
    }
  } finally {
    isFlushing = false;
    await rerenderFromLocal();
  }
}

/* ---------------------------------------------------------------------
 * Icons (inline SVG strings, reused across cards)
 * ------------------------------------------------------------------- */

const lockGlyph = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>';
const downloadGlyph = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 4v11m0 0-4-4m4 4 4-4"/><path d="M4 18v1a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-1"/></svg>';
const trashGlyph = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 7h16M9 7V5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2m1 0-.8 12.2a2 2 0 0 1-2 1.8H8.8a2 2 0 0 1-2-1.8L6 7"/></svg>';

/* ---------------------------------------------------------------------
 * State
 * ------------------------------------------------------------------- */

let notesCache = [];
let notesLoaded = false;         // becomes true after the first successful list fetch
let currentView = 'notes';
// Locked cards whose download/delete buttons have been revealed by a tap
// this session (see handleOpenCard) — in-memory only, resets on reload,
// which is fine: it's meant as light friction, not a saved preference.
// A locked card's download/delete buttons appear on the first tap and tuck
// themselves away again: after a few seconds, when you tap anywhere else,
// switch tabs, or press Escape. (They used to stay out until the page reloaded.)
const REVEAL_MS = 5000;
const revealedLockedCards = new Set();
const revealTimers = new Map();

function cardElFor(id) {
  const open = document.querySelector(`.card-open[data-id="${CSS.escape(id)}"]`);
  return open ? open.closest('.card') : null;
}

function keepRevealed(id) { // (re)starts the countdown — touching the buttons keeps them around
  clearTimeout(revealTimers.get(id));
  revealTimers.set(id, setTimeout(() => unrevealCard(id), REVEAL_MS));
}

function unrevealCard(id) {
  clearTimeout(revealTimers.get(id));
  revealTimers.delete(id);
  revealedLockedCards.delete(id);
  const el = cardElFor(id);
  if (!el) return;
  el.classList.remove('revealed');
  // After a tap, the button you pressed keeps focus, and :focus-within then
  // holds the row open forever. Let go of it — unless it's keyboard focus,
  // where staying visible is the whole point of that rule.
  const ae = document.activeElement;
  if (ae && ae !== document.body && el.contains(ae) && !ae.matches(':focus-visible')) ae.blur();
}

function hideRevealedCards(exceptId) {
  for (const id of [...revealedLockedCards]) if (id !== exceptId) unrevealCard(id);
}

function revealLockedCard(id) {
  hideRevealedCards(id);
  revealedLockedCards.add(id);
  const el = cardElFor(id);
  if (el) el.classList.add('revealed');
  keepRevealed(id);
}
let editingNoteId = null;        // generated client-side the moment the editor opens — see openEditorWithContent
let noteExistsOnServer = false;  // false until this note's first background save actually succeeds
let editorImages = [];
let editorAudio = {};            // clip id -> { data (audio data: URL), dur (seconds), name }
let lightboxIndex = 0;
let pendingLock = null;          // { type: 'quick'|'time', password?, password2?, unlockAt?, existing? }
let currentUnlockCreds = null;   // { password, password2? } — kept only for this editing session

// Autosave for whichever note is currently open: a throttled local cache
// (~1s, IndexedDB) plus a debounced background sync to the server, with a
// periodic safety net so a long unbroken typing session still reaches the
// server every so often instead of waiting indefinitely for a pause.
let lastAutosavedJSON = null;    // snapshot key already saved (or in flight) for the open note
let localDraftThrottle = null;
let serverSyncDebounce = null;
let serverSyncSafetyInterval = null;

// Per-note in-flight/queued sync state, keyed by note id — deliberately a
// Map rather than one flag, because a background save for a note you just
// closed can still be running while you open and start editing a
// *different* note; keying by id is what stops the two from colliding.
const syncStateByNote = new Map(); // id -> { inFlight: bool, queued: snapshot|null }

/* ---------------------------------------------------------------------
 * Rendering
 * ------------------------------------------------------------------- */

function emptyStateHTML(title, body) {
  return `<div class="empty-state"><h2>${escapeHTML(title)}</h2><p>${escapeHTML(body)}</p></div>`;
}

function cardHTML(meta) {
  const isLocked = meta.lockType !== 'none';
  const typeClass = meta.lockType === 'quick' ? 'type-quick' : meta.lockType === 'time' ? 'type-time' : '';
  const revealedClass = revealedLockedCards.has(meta.id) ? ' revealed' : '';

  let pill = '';
  if (meta.lockType === 'quick') {
    pill = `<span class="lock-pill quick">${lockGlyph}Quick lock</span>`;
  } else if (meta.lockType === 'time') {
    const left = fmtCountdown(meta.unlockAt);
    pill = `<span class="lock-pill time">${lockGlyph}${left ? left + ' left' : 'Ready to open'}</span>`;
  }

  // Saved on this device but not yet pushed to the server (offline, or a
  // save that failed to reach it) — see queueOutbox/buildNotesCacheFromLocal.
  const pendingBadge = meta._pending
    ? `<span class="pending-pill" title="Saved on this device — will sync once you\u2019re back online">Not synced</span>`
    : '';

  // Normal notes keep Download / Delete inside the note (editor toolbar).
  // Locked notes must keep them on the card: Download is the only way into
  // a time-locked note before its date, and that has to work while sealed.
  const actions = isLocked ? `
        <div class="card-actions">
          <button class="icon-btn" data-action="download" data-id="${escapeHTML(meta.id)}" title="Download" aria-label="Download">${downloadGlyph}</button>
          <button class="icon-btn" data-action="delete" data-id="${escapeHTML(meta.id)}" title="Delete" aria-label="Delete">${trashGlyph}</button>
        </div>` : '';

  // The title comes from the server (stored in plain text, even for locked
  // notes). Notes locked before titles were stored there fall back to a copy
  // remembered on this device, then to a generic label.
  const lockedTitle = isLocked ? (meta.title || meta._lockedTitle || '') : '';
  const titleText = isLocked ? (lockedTitle || 'Locked note') : (meta.title || 'Untitled');
  const titleClass = isLocked && !lockedTitle ? 'card-title is-placeholder' : 'card-title';
  let snippet = meta.preview || '';
  if (isLocked) {
    snippet = meta.lockType === 'time' && !fmtCountdown(meta.unlockAt)
      ? 'Its time lock has ended — open it with your password.'
      : 'Contents hidden until unlocked.';
  }

  return `
    <article class="card ${typeClass}${revealedClass}">
      <div class="card-open" data-action="open" data-id="${escapeHTML(meta.id)}" role="button" tabindex="0">
        ${pill}${pendingBadge}
        <div class="${titleClass}">${escapeHTML(titleText)}</div>
        <div class="card-snippet">${escapeHTML(snippet)}</div>
      </div>
      <div class="card-footer">
        <span class="card-meta">${fmtDate(meta.updatedAt || meta.createdAt)}${typeof meta._bytes === 'number' ? ' \u00b7 ' + formatBytes(meta._bytes + (meta._media || 0)) : ''}</span>
        ${actions}
      </div>
    </article>`;
}

function renderNotes() {
  const list = notesCache.filter((m) => m.lockType === 'none');
  const grid = document.getElementById('grid-notes');
  grid.innerHTML = list.length
    ? list.map(cardHTML).join('')
    : emptyStateHTML('No notes yet', 'Tap "Write something…" above to add your first one.');
}

function renderLocked() {
  const list = notesCache.filter((m) => m.lockType !== 'none');
  const grid = document.getElementById('grid-locked');
  grid.innerHTML = list.length
    ? list.map(cardHTML).join('')
    : emptyStateHTML('Nothing locked', 'Lock a note from its editor and it shows up here.');
}

// Locked cards show a live countdown — cheap to just re-render locked view periodically.
setInterval(() => { if (notesCache.some((m) => m.lockType === 'time')) renderLocked(); }, 60000);

// Records a note that just reached the server: refreshes its cached copy
// (metadata + content, and the vault password for time locks), drops any
// queued entry it supersedes, and redraws the grid — straight from the
// response already in hand rather than re-fetching the whole list. This is
// what makes a save actually feel instant in the list, not just the editor.
async function applySavedNote(noteId, note, payload, title) {
  const pending = await getOutboxItem(noteId);
  // Deleted while this save was in flight — leave the queued delete alone
  // (it'll clear the server copy this request just wrote) instead of
  // resurrecting the note in the cache.
  if (pending && pending.op === 'delete') return;
  await clearOutbox(noteId);
  await cacheNote(note, payload.content, lockedTitleFor(payload, title));
  if (payload.lockType === 'time' && payload.password2) await cacheVault(noteId, payload.password2, note.updatedAt);
  // Forget this device's copies of photos/audio the saved note no longer refers to.
  if (payload.mediaKeep && window.KSMedia) { try { await KSMedia.reconcile(noteId, payload.mediaKeep); } catch (e) { /* best-effort */ } }
  await rerenderFromLocal();
}

// The offline counterpart: no server response exists, so the metadata is
// built here exactly the way worker.js's metaFromBody would build it, the
// note is cached + queued for the next flush, and the grid shows it as a
// normal card marked "Not synced". Queueing is a plain put keyed by note
// id, so a later edit while still offline simply replaces this entry.
function lockedTitleFor(payload, title) {
  return payload.lockType === 'none' ? null : String(title || '');
}

function synthesizeMeta(id, payload) {
  const existing = notesCache.find((m) => m.id === id);
  const now = Date.now();
  return {
    id,
    createdAt: existing ? existing.createdAt : now,
    updatedAt: now,
    lockType: payload.lockType,
    unlockAt: payload.lockType === 'time' ? (payload.unlockAt || null) : null,
    title: String(payload.title || ''),
    preview: payload.lockType === 'none' ? String(payload.preview || '') : null,
    size: contentStoredBytes(payload.content),
    mediaSize: payload.mediaBytes > 0 ? payload.mediaBytes : undefined,
  };
}

async function applyOfflineSavedNote(noteId, payload, title) {
  const pending = await getOutboxItem(noteId);
  if (pending && pending.op === 'delete') return; // deleted meanwhile — don't resurrect it
  const meta = synthesizeMeta(noteId, payload);
  await cacheNote(meta, payload.content, lockedTitleFor(payload, title));
  if (payload.lockType === 'time' && payload.password2) await cacheVault(noteId, payload.password2, meta.updatedAt);
  await queueOutbox(noteId, 'save', payload);
  if (payload.mediaKeep && window.KSMedia) { try { await KSMedia.reconcile(noteId, payload.mediaKeep); } catch (e) { /* best-effort */ } }
  // The outbox is now the durable local copy of this exact content, so the
  // abrupt-close draft would just be a duplicate of it.
  clearLocalDraft(noteId);
  await rerenderFromLocal();
}

let lastListErrorMessage = null;
let lastServerSyncAt = 0;

// Refreshes the local cache from the server (when reachable), then pushes
// anything queued. Never throws and never blanks the grid: whatever is
// cached stays on screen if the request fails.
async function syncFromServer() {
  if (!navigator.onLine) { setOnline(false); return; }
  let notes;
  try {
    ({ notes } = await API.listNotes());
  } catch (e) {
    if (e.isNetworkError) {
      setOnline(false);
    } else {
      lastListErrorMessage = e.message;
      if (!notesLoaded) toast('Could not load notes: ' + e.message);
    }
    return;
  }
  lastListErrorMessage = null;
  lastServerSyncAt = Date.now();
  setOnline(true);
  learnServerTitleSupport(notes);
  if (window.KSMedia) KSMedia.refreshConfig(); // learns whether the Worker has Backblaze set up (not awaited)

  const outboxIds = new Set(await getOutboxIds());
  const serverIds = new Set(notes.map((n) => n.id));
  // A note with a queued local change keeps its local version — a possibly
  // stale server copy must not overwrite work the server hasn't seen yet.
  for (const meta of notes) {
    if (!outboxIds.has(meta.id)) await cacheNoteMetaOnly(meta);
  }
  // Cached but gone from the server (and not a local creation still waiting
  // to upload) means it was deleted from another device.
  for (const c of await getAllCachedNotes()) {
    if (!serverIds.has(c.id) && !outboxIds.has(c.id)) await removeCachedNote(c.id);
  }

  notesLoaded = true;
  await rerenderFromLocal();
  await flushOutbox();
  prefetchOfflineData(notes.filter((m) => !outboxIds.has(m.id)));
}

// Quietly downloads the content of every note whose cached copy is missing
// or older than the server's — this is what makes *all* notes, locked and
// unlocked, open offline rather than just the ones opened before. Locked
// notes are cached still-encrypted, exactly as the server holds them.
// A time-locked note past its unlock date also gets its released second
// password cached; before that date the server withholds it, so a note
// whose date passes while you're offline has to wait for a connection.
async function prefetchOfflineData(metas) {
  for (const meta of metas) {
    if (!navigator.onLine) return;
    try {
      const cached = await getCachedMeta(meta.id);
      const needContent = !cached || !cached.hasContent || cached.contentUpdatedAt !== meta.updatedAt;
      if (needContent) {
        const { content } = await API.getNote(meta.id);
        await cacheNote(meta, content);
      }
      const unlocked = meta.lockType === 'time' && meta.unlockAt && Date.now() >= meta.unlockAt;
      const vaultFresh = !!(cached && cached.vault && cached.vaultUpdatedAt === meta.updatedAt);
      if (unlocked && !vaultFresh) {
        try {
          const { password2 } = await API.getVault(meta.id);
          if (password2) await cacheVault(meta.id, password2, meta.updatedAt);
        } catch (e) { if (e.isNetworkError) return; }
      }
      // Photos and audio kept in Backblaze: bring them along too (while there's room on this
      // device), so the note opens offline like every other.
      if (meta.mediaSize > 0 && window.KSMedia) await KSMedia.prefetchNote(meta.id, meta.mediaSize);
    } catch (e) {
      if (e.isNetworkError) { setOnline(false); return; }
      // Anything else (e.g. one note's content missing server-side) —
      // skip it and keep going with the rest.
    }
  }
}

async function refreshNotes() {
  // Cards come from the local cache first — instant, and the only source
  // when there's no connection. The server fetch below just refreshes it.
  notesCache = await buildNotesCacheFromLocal();
  await refreshOutboxCount();
  if (notesCache.length) {
    notesLoaded = true;
    renderNotes();
    renderLocked();
  } else if (!notesLoaded) {
    const loading = emptyStateHTML('Loading…', 'Fetching your notes.');
    document.getElementById('grid-notes').innerHTML = loading;
    document.getElementById('grid-locked').innerHTML = loading;
  }

  await syncFromServer();

  // Only reachable on a genuinely empty start: nothing cached yet AND the
  // server couldn't be reached. (A successful fetch of zero notes sets
  // notesLoaded and renders the normal "No notes yet" state instead.)
  if (!notesLoaded && !notesCache.length) {
    const offline = !navigator.onLine || !isOnline;
    const empty = emptyStateHTML(
      offline ? 'You\u2019re offline' : 'Could not load notes',
      offline
        ? 'Your notes will appear here once you\u2019ve connected at least once.'
        : (lastListErrorMessage || 'Check your connection and try again.')
    );
    document.getElementById('grid-notes').innerHTML = empty;
    document.getElementById('grid-locked').innerHTML = empty;
  }
}

function switchView(view) {
  hideRevealedCards();
  currentView = view;
  document.getElementById('tab-notes').setAttribute('aria-selected', String(view === 'notes'));
  document.getElementById('tab-locked').setAttribute('aria-selected', String(view === 'locked'));
  document.getElementById('grid-notes').classList.toggle('hidden', view !== 'notes');
  document.getElementById('grid-locked').classList.toggle('hidden', view !== 'locked');
}

/* ---------------------------------------------------------------------
 * Editor
 * ------------------------------------------------------------------- */

// A 72px thumbnail used to be the full-size photo scaled down by CSS — so a
// note with a few "Original"-quality photos made the browser decode several
// 12-megapixel images just to draw a thumbnail strip. Draw from a small
// decoded copy instead (made once per photo, kept only while the editor is open).
const thumbUrls = new Map(); // fingerprint -> object URL

function clearThumbUrls() {
  for (const url of thumbUrls.values()) if (url.startsWith('blob:')) URL.revokeObjectURL(url);
  thumbUrls.clear();
}

async function makeThumbURL(src) {
  const sig = mediaSig(src);
  if (thumbUrls.has(sig)) return thumbUrls.get(sig);
  let url = src; // fallback: the photo itself
  try {
    const blob = await (await fetch(src)).blob();
    let bitmap;
    try { bitmap = await createImageBitmap(blob, { resizeWidth: 160, resizeQuality: 'medium' }); }
    catch (e) { bitmap = await createImageBitmap(blob); }
    const scale = Math.min(1, 160 / Math.max(bitmap.width, bitmap.height));
    const canvas = document.createElement('canvas');
    canvas.width = Math.max(1, Math.round(bitmap.width * scale));
    canvas.height = Math.max(1, Math.round(bitmap.height * scale));
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    if (bitmap.close) bitmap.close();
    const small = await new Promise((resolve) => canvas.toBlob(resolve, 'image/jpeg', 0.8));
    if (small) url = URL.createObjectURL(small);
  } catch (e) { /* keep the fallback */ }
  thumbUrls.set(sig, url);
  return url;
}

function renderEditorThumbs() {
  const wrap = document.getElementById('editor-thumbs');
  wrap.textContent = '';
  editorImages.forEach((src, i) => {
    const thumb = document.createElement('div');
    thumb.className = 'thumb';
    const img = document.createElement('img');
    img.alt = '';
    img.dataset.idx = String(i);
    const cached = thumbUrls.get(mediaSig(src));
    if (cached) img.src = cached;
    else makeThumbURL(src).then((url) => { if (img.isConnected && editorImages[Number(img.dataset.idx)] === src) img.src = url; });
    img.addEventListener('click', () => openLightbox(Number(img.dataset.idx)));
    const size = document.createElement('span');
    size.className = 'thumb-size';
    size.textContent = formatBytes(estimateImageBytes(src));
    const remove = document.createElement('button');
    remove.className = 'thumb-remove';
    remove.setAttribute('aria-label', 'Remove image');
    remove.textContent = '\u00d7';
    remove.addEventListener('click', (e) => {
      e.stopPropagation();
      editorImages.splice(Number(img.dataset.idx), 1);
      renderEditorThumbs();
      updateSizeMeter();
      onEditorContentChanged();
    });
    thumb.append(img, size, remove);
    wrap.appendChild(thumb);
  });
}

/* ---------------------------------------------------------------------
 * Lightbox — full-screen photo viewer with left/right paging, opened by
 * tapping any thumbnail in the editor.
 * ------------------------------------------------------------------- */

function openLightbox(index) {
  if (!editorImages.length) return;
  lightboxIndex = index;
  renderLightbox();
  show('overlay-lightbox');
}

function closeLightbox() { hide('overlay-lightbox'); }

function lightboxStep(delta) {
  const total = editorImages.length;
  if (!total) return;
  lightboxIndex = (lightboxIndex + delta + total) % total;
  renderLightbox();
}

function renderLightbox() {
  const total = editorImages.length;
  if (!total) { closeLightbox(); return; }
  if (lightboxIndex >= total) lightboxIndex = total - 1;
  if (lightboxIndex < 0) lightboxIndex = 0;
  const src = editorImages[lightboxIndex];
  document.getElementById('lightbox-img').src = src;
  document.getElementById('lightbox-caption').textContent =
    total > 1
      ? `${lightboxIndex + 1} of ${total} — ${formatBytes(estimateImageBytes(src))}`
      : formatBytes(estimateImageBytes(src));
  const showNav = total > 1;
  document.getElementById('btn-lightbox-prev').style.visibility = showNav ? 'visible' : 'hidden';
  document.getElementById('btn-lightbox-next').style.visibility = showNav ? 'visible' : 'hidden';
}

function setupLightbox() {
  document.getElementById('btn-lightbox-close').addEventListener('click', closeLightbox);
  document.getElementById('btn-lightbox-prev').addEventListener('click', () => lightboxStep(-1));
  document.getElementById('btn-lightbox-next').addEventListener('click', () => lightboxStep(1));

  // Tapping the dark backdrop (but not the photo itself) closes, same as
  // most native photo viewers.
  document.getElementById('overlay-lightbox').addEventListener('click', (e) => {
    if (e.target.id === 'overlay-lightbox') closeLightbox();
  });

  document.addEventListener('keydown', (e) => {
    if (document.getElementById('overlay-lightbox').classList.contains('hidden')) return;
    if (e.key === 'Escape') closeLightbox();
    else if (e.key === 'ArrowLeft') lightboxStep(-1);
    else if (e.key === 'ArrowRight') lightboxStep(1);
  });

  // Swipe left/right to page between photos on touch devices.
  let touchStartX = null;
  const lightbox = document.getElementById('overlay-lightbox');
  lightbox.addEventListener('touchstart', (e) => {
    touchStartX = e.changedTouches[0].clientX;
  }, { passive: true });
  lightbox.addEventListener('touchend', (e) => {
    if (touchStartX === null) return;
    const dx = e.changedTouches[0].clientX - touchStartX;
    touchStartX = null;
    if (Math.abs(dx) < 40) return; // not a deliberate swipe
    lightboxStep(dx < 0 ? 1 : -1);
  }, { passive: true });
}

function lockIsActive() { return !!(pendingLock && pendingLock.type !== 'none'); }

function renderLockSummary() {
  const el = document.getElementById('editor-lock-summary');
  const removeBtn = document.getElementById('btn-remove-lock');
  const lockBtn = document.getElementById('btn-open-lock-chooser');
  const active = lockIsActive();
  if (removeBtn) removeBtn.style.display = active ? '' : 'none';
  // The padlock is the way back into the lock settings, so it says so — and
  // lights up while a lock is on, instead of looking identical either way.
  if (lockBtn) {
    const label = active ? 'Change lock' : 'Lock this note';
    lockBtn.title = label;
    lockBtn.setAttribute('aria-label', label);
    lockBtn.setAttribute('aria-pressed', String(active));
  }
  if (!active) { el.innerHTML = ''; return; }
  let text;
  if (pendingLock.type === 'quick') {
    text = 'Quick lock on \u2014 tap the padlock to change it.';
  } else if (!pendingLock.unlockAt) {
    text = 'Time lock on \u2014 tap the padlock to change it.';
  } else if (pendingLock.unlockAt > Date.now()) {
    text = `Time-locked until ${fmtDateTime(pendingLock.unlockAt)}. Tap the padlock to change it.`;
  } else {
    text = `Time lock ended ${fmtDateTime(pendingLock.unlockAt)} \u2014 this note opens with your password.`;
  }
  el.innerHTML = `<p class="hint">${escapeHTML(text)}</p>`;
}

function noteHasContent() {
  const title = document.getElementById('editor-title').value.trim();
  const body = document.getElementById('editor-body').textContent.trim();
  return !!(title || body || editorImages.length || Ink.strokes.length
    || document.getElementById('editor-body').querySelector('ks-audio'));
}

// The Download / Delete buttons in the editor only make sense once the
// note exists (has been saved at least once).
function setExistingNoteButtons(exists) {
  document.getElementById('btn-delete-note').style.display = exists ? '' : 'none';
  document.getElementById('btn-download-note').style.display = exists ? '' : 'none';
}

// Fills every editor field from a stored content object. Old notes only
// have plain `body` text; newer ones also carry `html` and `drawing`.
function setEditorContent(content) {
  document.getElementById('editor-title').value = content.title || '';
  clearAudioUrls();
  editorAudio = sanitizeAudioMap(content.audio);
  const bodyEl = document.getElementById('editor-body');
  bodyEl.innerHTML = content.html ? sanitizeHTML(content.html) : textToHTML(content.body);
  hydrateAudioChips(bodyEl);
  // Only real data: URLs ever reach the <img> markup.
  editorImages = (content.images || []).filter((s) => typeof s === 'string' && /^data:image\//.test(s));
  renderEditorThumbs();
  inkLoad(content.drawing);
  updateSizeMeter();
}

function openEditorWithContent(meta, content) {
  const isExisting = !!(meta && meta.id);
  // A fresh note gets its id right now, up front, rather than whenever it
  // first gets saved. Every save — the Save button, autosave, a retry —
  // then PUTs to this same id, which is what makes them all idempotent:
  // there's no "create" request that a double-tap or a network retry
  // could ever fire twice into two different notes.
  editingNoteId = isExisting ? meta.id : crypto.randomUUID();
  noteExistsOnServer = isExisting;
  stopAutosaveTimers();

  document.getElementById('editor-heading').textContent = isExisting ? 'Edit note' : 'New note';
  setDrawMode(false);
  setEditorContent(content);
  if (isExisting && meta.lockType && meta.lockType !== 'none') setLockedTitle(meta.id, String(content.title || ''));
  setExistingNoteButtons(noteExistsOnServer);

  pendingLock = (meta && meta.lockType && meta.lockType !== 'none')
    ? { type: meta.lockType, unlockAt: meta.unlockAt, existing: true }
    : null;
  renderLockSummary();
  // Baseline must be built the same way later snapshots are (captureSnapshot,
  // which carries the resolved lock passwords) or a locked note would always
  // look "changed" and get re-encrypted and re-uploaded just for being opened.
  const openedSnapshot = captureSnapshot();
  lastAutosavedJSON = snapshotKey(openedSnapshot);
  // A note locked before titles were stored on the server has none there.
  // Once the Worker supports it, make closing this note re-save it once so
  // every device gets the title — no edit needed.
  if (isExisting && meta.lockType !== 'none' && meta.title == null
      && localStorage.getItem('ks_titlesOnServer') === '1') {
    lastAutosavedJSON = null;
  }
  seedSyncStateImages(editingNoteId, openedSnapshot);
  show('overlay-editor');
  // No auto-focus here on purpose — opening a note (new or existing)
  // should never force the keyboard open by itself. It comes up only
  // once the person actually taps into the title or body.

  // If an earlier session ended abruptly (crash, dead battery, a
  // swiped-away tab) before its background save could finish, offer to
  // bring those changes back rather than silently showing the older,
  // already-saved version underneath them.
  maybeOfferDraftRestore(editingNoteId, content);
}

async function maybeOfferDraftRestore(noteId, serverContent) {
  const draft = await loadLocalDraft(noteId);
  if (!draft) return;
  const contentKey = (c) => JSON.stringify({
    title: c.title || '',
    html: sanitizeHTML(c.html || textToHTML(c.body)),
    images: (c.images || []).map(mediaSig),
    audio: Object.keys(c.audio || {}).sort(),
    drawing: (c.drawing && c.drawing.strokes && c.drawing.strokes.length) ? c.drawing.strokes : null,
  });
  const draftKey = contentKey(draft);
  const serverKey = contentKey(serverContent);
  if (draftKey === serverKey) { clearLocalDraft(noteId); return; }
  if (editingNoteId !== noteId) return; // the user has already moved on

  openConfirm(
    'Restore unsaved draft?',
    'This note has changes from an earlier session that never made it to the server. Restore them?',
    async () => {
      if (editingNoteId !== noteId) return;
      setEditorContent(draft);
      onEditorContentChanged();
      toast('Draft restored');
    },
    'Restore'
  );
}

/* ---------------------------------------------------------------------
 * Save payload building — shared by the Save button, autosave, and retries
 * ------------------------------------------------------------------- */

// Resolves pendingLock (plus any unlock-session password) into a plain,
// self-contained description with the actual password strings baked in.
// Doing this synchronously, the moment a save is triggered, means the
// result can be safely used by an async save later even if the user has
// since closed this note and opened a different one — it no longer
// depends on any live, mutable state.
function resolveLockForSnapshot() {
  if (!pendingLock || pendingLock.type === 'none') return null;
  const password = pendingLock.password || (currentUnlockCreds && currentUnlockCreds.password) || null;
  if (pendingLock.type === 'quick') {
    return { type: 'quick', password };
  }
  if (pendingLock.type === 'time') {
    let password2 = pendingLock.password2 || (currentUnlockCreds && currentUnlockCreds.password2) || null;
    if (!password2) {
      // Generated once and cached on pendingLock so a later autosave tick
      // (or a retry) reuses this exact value instead of silently rotating
      // it out from under a copy the note owner may already have.
      password2 = generateSecondPassword();
      pendingLock.password2 = password2;
    }
    return { type: 'time', password, password2, unlockAt: pendingLock.unlockAt };
  }
  return null;
}

function captureSnapshot() {
  const html = sanitizeHTML(document.getElementById('editor-body').innerHTML);
  return {
    title: document.getElementById('editor-title').value.trim(),
    body: htmlToText(html), // plain-text copy: previews, search, and readers that predate formatting
    html,
    images: editorImages.slice(),
    audio: snapshotAudio(html),
    drawing: inkGetData(),
    lock: resolveLockForSnapshot(),
  };
}

// Only clips that are still in the text get saved — a clip you deleted (or
// undid) doesn't linger in the note's data.
function snapshotAudio(html) {
  const out = {};
  for (const m of html.matchAll(/<ks-audio data-id="([a-z0-9]+)"><\/ks-audio>/g)) {
    if (editorAudio[m[1]]) out[m[1]] = editorAudio[m[1]];
  }
  return out;
}

// Same, for the local-draft safety net.
function saveDraftNow(noteId) {
  const html = sanitizeHTML(document.getElementById('editor-body').innerHTML);
  saveLocalDraft(noteId, document.getElementById('editor-title').value, htmlToText(html),
    editorImages.slice(), html, inkGetData(), snapshotAudio(html));
}

async function buildSavePayload(snapshot, noteId) {
  const { title, body, html, images, drawing, lock } = snapshot;
  const audio = snapshot.audio || {};
  const content = { title, body, html, images };
  if (Object.keys(audio).length) content.audio = audio;
  if (drawing) content.drawing = drawing;

  // With Backblaze set up, photos and audio leave the note here \u2014 before any locking, so a
  // locked note's media is encrypted too. `stored` is what actually gets saved (and encrypted).
  let stored = content;
  let mediaKeep = null;
  let mediaBytes = 0;
  if (noteId && window.KSMedia && KSMedia.available()) {
    try {
      const ext = await KSMedia.externalize(noteId, content, !!(lock && lock.type !== 'none'));
      stored = ext.content;
      mediaKeep = ext.keep;
      mediaBytes = ext.bytes;
    } catch (e) {
      if (e && e.tooBig) throw e;
      // Couldn't move the media out (say this browser won't keep it locally): fall back to
      // keeping it inside the note, exactly as before.
      stored = content; mediaKeep = null; mediaBytes = 0;
    }
  }
  let payload;

  if (!lock || lock.type === 'none') {
    payload = { lockType: 'none', title, preview: makePreview(body) || (drawing ? 'Drawing' : ''), content: stored };
  } else if (lock.type === 'quick') {
    if (!lock.password) throw new Error('missing password for quick lock');
    const record = await encryptNote(lock.password, stored);
    payload = { lockType: 'quick', title, content: record };
  } else if (lock.type === 'time') {
    if (!lock.password) throw new Error('missing password for time lock');
    const record = await encryptNote(combine(lock.password, lock.password2), stored);
    payload = { lockType: 'time', title, unlockAt: lock.unlockAt, password2: lock.password2, content: record };
  }
  if (mediaKeep) { payload.mediaKeep = mediaKeep; payload.mediaBytes = mediaBytes; }

  const hasAudio = Object.keys(audio).length > 0;
  const mediaWhat = hasAudio ? (images.length ? 'photos & audio' : 'audio') : 'photos';
  return { payload, hasImages: images.length > 0 || hasAudio, mediaWhat };
}

/* ---------------------------------------------------------------------
 * Background save — used by both the Save button and autosave. Always a
 * PUT to a note id generated client-side (see worker.js's upsertNote), so
 * it's idempotent: saving the same content twice — a double-tap, a
 * retried request after a flaky connection, autosave racing the Save
 * button — just overwrites the same note instead of ever creating a
 * duplicate.
 * ------------------------------------------------------------------- */

// Called once, right when a note is opened, so the "have the photos
// actually changed since the server last saw them?" check below has a
// real baseline from the start — otherwise the very first autosave of an
// existing, already-synced note would look like a fresh photo upload.
function seedSyncStateImages(noteId, snapshot) {
  let state = syncStateByNote.get(noteId);
  if (!state) { state = { inFlight: false, queued: null }; syncStateByNote.set(noteId, state); }
  state.lastSyncedImagesJSON = mediaKey(snapshot);
}

function runSync(noteId, snapshot) {
  let state = syncStateByNote.get(noteId);
  if (!state) { state = { inFlight: false, queued: null }; syncStateByNote.set(noteId, state); }

  if (state.inFlight) {
    state.queued = snapshot; // latest wins — no point sending a stale mid-typing snapshot
    return;
  }
  state.inFlight = true;
  syncRunOne(noteId, snapshot, state);
}

async function syncRunOne(noteId, snapshot, state) {
  // Only the note currently open in the editor (or just closed from it)
  // gets to talk in the sync bar — a background save finishing for some
  // *other* note shouldn't interrupt whatever the person is looking at now.
  const showInBar = () => noteId === editingNoteId;

  let built;
  try {
    built = await buildSavePayload(snapshot, noteId);
  } catch (e) {
    state.inFlight = false;
    const tooBig = !!(e && e.tooBig);
    toast(tooBig ? e.message : 'Could not lock note — try setting the lock again.');
    if (showInBar()) syncBarError(tooBig ? 'Couldn\u2019t save — a file is too big' : 'Couldn\u2019t save — check the lock', () => runSync(noteId, snapshot));
    maybeContinueQueued(noteId, state);
    return;
  }

  const { payload, hasImages, mediaWhat } = built;

  // The note's photos are stored together with its text in one blob (see
  // worker.js), so every save necessarily re-sends all of it — but that's
  // only worth calling out as "saving photos" when photos are actually
  // part of what changed. Otherwise a plain text edit on a photo-heavy
  // note would misleadingly claim to be re-saving pictures on every
  // autosave tick.
  const imagesJSON = mediaKey(snapshot);
  const imagesChanged = hasImages && imagesJSON !== state.lastSyncedImagesJSON;

  const onProgress = imagesChanged && showInBar()
    ? (fraction) => syncBarSet(`Saving ${mediaWhat}… ${Math.round(fraction * 100)}%`, fraction)
    : null;
  if (showInBar()) syncBarSet(imagesChanged ? `Saving ${mediaWhat}… 0%` : 'Saving…', imagesChanged ? 0 : null);

  try {
    if (!navigator.onLine) {
      // No point attempting a request that can't leave the device — go
      // straight to the offline path below.
      const offlineErr = new Error('Offline');
      offlineErr.isNetworkError = true;
      throw offlineErr;
    }
    const { note } = await API.saveNote(noteId, payload, onProgress);
    setOnline(true);
    learnServerTitleSupport([note]);
    if (noteId === editingNoteId) {
      noteExistsOnServer = true;
      setExistingNoteButtons(true);
      document.getElementById('editor-heading').textContent = 'Edit note';
      lastAutosavedJSON = snapshotKey(snapshot);
    }
    state.lastSyncedImagesJSON = imagesJSON;
    clearLocalDraft(noteId);
    await applySavedNote(noteId, note, payload, snapshot.title);
    if (showInBar()) syncBarSuccess('Saved');
    flushOutbox(); // a working connection is the moment to drain anything else that's queued
  } catch (e) {
    if (e.isNetworkError) {
      // Offline (or the connection dropped mid-save). That's not a failure:
      // the note is cached locally as if it had saved, queued for the next
      // flush, and marked "Not synced" — no error toast, no retry prompt.
      setOnline(false);
      await applyOfflineSavedNote(noteId, payload, snapshot.title);
      if (noteId === editingNoteId) {
        noteExistsOnServer = true;
        setExistingNoteButtons(true);
        document.getElementById('editor-heading').textContent = 'Edit note';
        lastAutosavedJSON = snapshotKey(snapshot);
      }
      state.lastSyncedImagesJSON = imagesJSON;
      if (showInBar()) syncBarSuccess('Saved on this device — will sync later');
    } else if (showInBar()) {
      syncBarError('Couldn\u2019t save — tap to retry', () => runSync(noteId, snapshot));
    } else {
      toast('Couldn\u2019t save "' + (snapshot.title || 'Untitled') + '" — it\u2019s still cached on this device.');
    }
  } finally {
    state.inFlight = false;
    maybeContinueQueued(noteId, state);
  }
}

function maybeContinueQueued(noteId, state) {
  if (state.queued) {
    const next = state.queued;
    state.queued = null;
    state.inFlight = true;
    syncRunOne(noteId, next, state);
  }
}

/* ---------------------------------------------------------------------
 * Autosave scheduling — local cache is aggressive (~1s) since it's free
 * and instant; the server sync is debounced so ordinary typing doesn't
 * hit the Worker on every keystroke, with a periodic safety net so a long
 * unbroken typing session still gets flushed to the server periodically
 * rather than waiting indefinitely for a pause.
 * ------------------------------------------------------------------- */

function onEditorContentChanged() {
  if (!editingNoteId) return;
  scheduleSizeMeter();

  if (!localDraftThrottle) {
    localDraftThrottle = setTimeout(() => {
      localDraftThrottle = null;
      // Never write a locked note's text to the device in plain form. Its
      // encrypted copy reaches the outbox/server seconds later anyway.
      if (editingNoteId && noteHasContent() && !lockIsActive()) saveDraftNow(editingNoteId);
    }, 1000);
  }

  // Every save re-sends the whole note, so a heavy note waits a little
  // longer between autosaves (it also saves Workers KV's 1,000-writes-a-day
  // allowance on the Free plan).
  const delay = Math.min(10000, 2000 + Math.floor(lastNoteBytes / 1048576) * 1000);
  clearTimeout(serverSyncDebounce);
  serverSyncDebounce = setTimeout(triggerAutosave, delay);

  if (!serverSyncSafetyInterval) {
    serverSyncSafetyInterval = setInterval(triggerAutosave, 15000);
  }
}

function triggerAutosave() {
  if (!editingNoteId || (!noteHasContent() && !noteExistsOnServer)) return;
  const snapshot = captureSnapshot();
  const key = snapshotKey(snapshot);
  if (key === lastAutosavedJSON) return; // nothing's changed since the last successful save
  runSync(editingNoteId, snapshot);
}

function stopAutosaveTimers() {
  clearTimeout(localDraftThrottle); localDraftThrottle = null;
  clearTimeout(serverSyncDebounce); serverSyncDebounce = null;
  clearInterval(serverSyncSafetyInterval); serverSyncSafetyInterval = null;
}

/* ---------------------------------------------------------------------
 * Closing the editor — Save and the ✕/Escape close path do the same
 * thing: hand off to the background and close immediately, so the app
 * never sits there with a spinner while a photo uploads. There's no
 * separate "discard changes?" prompt anymore, because with autosave
 * running there's essentially never anything un-cached to lose — closing
 * just triggers one final sync of whatever's changed in the last moment.
 * ------------------------------------------------------------------- */

function closeEditorAndSync(isExplicitSave) {
  const noteId = editingNoteId;
  const overLimit = noteSizeBreakdown().total > NOTE_SIZE_LIMIT;

  if (overLimit && isExplicitSave) {
    toast('This note is over the 25 MB limit — remove a photo or an audio clip before saving.');
    return;
  }

  stopAutosaveTimers();
  setDrawMode(false);

  // A brand-new, still-empty note is simply dropped. A note that already
  // exists is different: emptying it is a real edit and must be saved, not
  // silently thrown away (it used to pop back with its old text).
  if (!noteHasContent() && !noteExistsOnServer) {
    clearLocalDraft(noteId);
    hide('overlay-editor');
    currentUnlockCreds = null;
    return;
  }

  if (overLimit) {
    // Closing (not explicitly saving) with an oversized note: the local
    // draft cache already has it, so nothing is lost — just skip sending a
    // request to the server that KV would reject anyway.
    // Nothing else holds this version (it can't be sent), so keep a local
    // draft now \u2014 even for a locked note, since the alternative is losing it.
    saveDraftNow(noteId);
    hide('overlay-editor');
    currentUnlockCreds = null;
    toast('Kept on this device only — this note is over the 25 MB limit. Remove a photo or clip to sync it.');
    return;
  }

  const snapshot = captureSnapshot();
  const key = snapshotKey(snapshot);
  hide('overlay-editor'); // instant — the real work continues below, in the background
  currentUnlockCreds = null;

  if (key === lastAutosavedJSON) return; // autosave already has this exact version covered
  runSync(noteId, snapshot);
}

function saveNote() { closeEditorAndSync(true); }
function attemptCloseEditor() { closeEditorAndSync(false); }

function confirmDelete(id, fromEditor) {
  openConfirm('Delete this note?', 'This can\u2019t be undone.', async () => {
    // Cancel anything still waiting to autosave this note \u2014 otherwise a save
    // queued a moment ago lands after the delete and brings the note back.
    if (fromEditor && editingNoteId === id) {
      stopAutosaveTimers();
      setDrawMode(false);
      editingNoteId = null;
      lastAutosavedJSON = null;
    }
    const doomed = syncStateByNote.get(id);
    if (doomed) doomed.queued = null;
    // Local-first: it disappears from the cache and grid right away, and the
    // server delete is queued in the outbox so it still happens if there's
    // no connection right now (or the request fails).
    await removeCachedNote(id);
    clearLocalDraft(id);
    unrevealCard(id);
    if (fromEditor) hide('overlay-editor');
    await queueOutbox(id, 'delete', null);
    await rerenderFromLocal();

    if (!navigator.onLine) {
      setOnline(false);
      toast('Deleted — will sync once you\u2019re back online.');
      return;
    }
    try {
      try {
        await API.deleteNote(id);
      } catch (delErr) {
        if (delErr.status !== 404) throw delErr; // already gone server-side = success
      }
      setOnline(true);
      await clearOutbox(id);
      toast('Deleted');
    } catch (e) {
      if (e.isNetworkError) {
        setOnline(false);
        toast('Deleted — will sync once you\u2019re back online.');
      } else {
        toast('Deleted here, but the server said: ' + e.message);
      }
    }
  });
}

/* ---------------------------------------------------------------------
 * Lock chooser
 * ------------------------------------------------------------------- */

function resetLockChooser() {
  document.getElementById('choice-quick').classList.remove('selected');
  document.getElementById('choice-time').classList.remove('selected');
  document.getElementById('quick-lock-fields').style.display = 'none';
  document.getElementById('time-lock-fields').style.display = 'none';
  ['quick-password', 'quick-password-confirm', 'time-password', 'time-password-confirm', 'time-unlock-at']
    .forEach((id) => { document.getElementById(id).value = ''; });
  document.getElementById('quick-lock-error').classList.add('visually-hidden');
  document.getElementById('time-lock-error').classList.add('visually-hidden');
  document.getElementById('time-unlock-at').min = localDatetimeInputMin();
  document.getElementById('btn-confirm-quick-lock').textContent = 'Set quick lock';
  document.getElementById('btn-confirm-time-lock').textContent = 'Set time lock';
  document.getElementById('choice-quick').setAttribute('aria-pressed', 'false');
  document.getElementById('choice-time').setAttribute('aria-pressed', 'false');
  const status = document.getElementById('time-lock-status');
  status.textContent = '';
  status.hidden = true;
}

// <input type="datetime-local"> wants local "YYYY-MM-DDTHH:mm", not a timestamp.
function toLocalDatetimeInput(ts) {
  const d = new Date(ts);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// Reopening the dialog on a note that already has a lock shows that lock
// (kind, password, date) instead of a blank form.
function prefillLockChooser() {
  const lock = pendingLock;
  if (!lock || lock.type === 'none') return;
  const kind = lock.type; // 'quick' | 'time'
  // A lock set moments ago holds its password; one from unlocking an existing
  // note has it in the unlock session instead.
  const pw = lock.password || (currentUnlockCreds && currentUnlockCreds.password) || '';
  document.getElementById('choice-' + kind).click(); // selects it and reveals its fields
  document.getElementById(kind + '-password').value = pw;
  document.getElementById(kind + '-password-confirm').value = pw;
  if (kind === 'time' && lock.unlockAt) {
    // Show the date that is actually set \u2014 including one that has already
    // passed (the usual case when reopening a note after its time lock ended;
    // it used to come up blank, and "Update" then demanded a new date).
    document.getElementById('time-unlock-at').value = toLocalDatetimeInput(lock.unlockAt);
    const status = document.getElementById('time-lock-status');
    status.textContent = lock.unlockAt > Date.now()
      ? `Currently set to unlock ${fmtDateTime(lock.unlockAt)}.`
      : `This lock\u2019s date (${fmtDateTime(lock.unlockAt)}) has passed, so the note opens with just your password. Pick a new future date to seal it again, or keep it as it is.`;
    status.hidden = false;
  }
  document.getElementById('btn-confirm-' + kind + '-lock').textContent = 'Update ' + kind + ' lock';
}

function openLockChooser() {
  resetLockChooser();
  prefillLockChooser();
  show('overlay-lock-chooser');
}

/* ---------------------------------------------------------------------
 * Unlock flow
 * ------------------------------------------------------------------- */

function openUnlockFlow(meta) {
  document.getElementById('unlock-heading').textContent =
    meta.lockType === 'quick' ? 'Quick-locked note' : 'Time-locked note';
  const body = document.getElementById('unlock-body');

  if (meta.lockType === 'quick') {
    body.innerHTML = `
      <div class="field">
        <label for="unlock-password">Password</label>
        <input type="password" id="unlock-password" autocomplete="current-password">
      </div>
      <p class="field error" id="unlock-error" style="display:none;"></p>
      <div class="btn-row">
        <button class="btn btn-primary" id="btn-do-unlock">Open</button>
        <button class="btn btn-ghost" data-close="overlay-unlock">Cancel</button>
      </div>`;
    show('overlay-unlock');
    document.getElementById('unlock-password').focus();
    document.getElementById('btn-do-unlock').addEventListener('click', async (ev) => {
      const btn = ev.currentTarget;
      if (btn.disabled) return;
      const pw = document.getElementById('unlock-password').value;
      const err = document.getElementById('unlock-error');
      err.style.display = 'none';
      setBusy(btn, true, 'Opening\u2026');
      try {
        const record = await fetchNoteContent(meta);
        const content = await inflateForOpen(meta, await decryptNote(pw, record));
        currentUnlockCreds = { password: pw };
        hide('overlay-unlock');
        openEditorWithContent(meta, content);
      } catch (e) {
        err.textContent = unlockErrorText(e, 'Wrong password.');
        err.style.display = '';
      } finally {
        setBusy(btn, false);
      }
    });
    return;
  }

  // time lock
  const remaining = fmtCountdown(meta.unlockAt);

  if (!remaining) {
    body.innerHTML = `
      <p class="hint" style="margin-bottom:14px;">This note's lock period has ended — enter your password to open it.</p>
      <div class="field">
        <label for="unlock-password">Password</label>
        <input type="password" id="unlock-password" autocomplete="current-password">
      </div>
      <p class="field error" id="unlock-error" style="display:none;"></p>
      <div class="btn-row">
        <button class="btn btn-primary" id="btn-do-unlock">Open</button>
        <button class="btn btn-ghost" data-close="overlay-unlock">Cancel</button>
      </div>`;
    show('overlay-unlock');
    document.getElementById('unlock-password').focus();
    document.getElementById('btn-do-unlock').addEventListener('click', async (ev) => {
      const btn = ev.currentTarget;
      if (btn.disabled) return;
      const pw = document.getElementById('unlock-password').value;
      const err = document.getElementById('unlock-error');
      err.style.display = 'none';
      setBusy(btn, true, 'Opening\u2026');
      try {
        const [password2, record] = await Promise.all([fetchVaultPassword2(meta), fetchNoteContent(meta)]);
        const content = await inflateForOpen(meta, await decryptNote(combine(pw, password2), record));
        currentUnlockCreds = { password: pw, password2 };
        hide('overlay-unlock');
        openEditorWithContent(meta, content);
      } catch (e) {
        err.textContent = unlockErrorText(e, 'Wrong password.');
        err.style.display = '';
      } finally {
        setBusy(btn, false);
      }
    });
    return;
  }

  body.innerHTML = `
    <div class="countdown-box"><strong>${remaining} left</strong>Sealed until ${fmtDateTime(meta.unlockAt)}.</div>
    <button class="divider-link" id="btn-show-early-fields">I have both passwords</button>
    <div id="early-fields" style="display:none;">
      <div class="field">
        <label for="unlock-password">Password 1</label>
        <input type="password" id="unlock-password" autocomplete="current-password">
      </div>
      <div class="field">
        <label for="unlock-password2">Password 2</label>
        <input type="password" id="unlock-password2" autocomplete="off">
      </div>
      <p class="field error" id="unlock-error" style="display:none;"></p>
      <button class="btn btn-primary" id="btn-do-unlock">Open early</button>
    </div>
    <div class="btn-row" style="margin-top: 10px;">
      <button class="btn btn-ghost" data-close="overlay-unlock">Close</button>
    </div>`;
  show('overlay-unlock');

  document.getElementById('btn-show-early-fields').addEventListener('click', (e) => {
    document.getElementById('early-fields').style.display = '';
    e.target.style.display = 'none';
    document.getElementById('unlock-password').focus();
  });

  document.getElementById('btn-do-unlock').addEventListener('click', async (ev) => {
    const btn = ev.currentTarget;
    if (btn.disabled) return;
    const pw = document.getElementById('unlock-password').value;
    const pw2 = document.getElementById('unlock-password2').value;
    const err = document.getElementById('unlock-error');
    err.style.display = 'none';
    setBusy(btn, true, 'Opening\u2026');
    try {
      const record = await fetchNoteContent(meta);
      const content = await inflateForOpen(meta, await decryptNote(combine(pw, pw2), record));
      currentUnlockCreds = { password: pw, password2: pw2 };
      hide('overlay-unlock');
      openEditorWithContent(meta, content);
    } catch (e) {
      err.textContent = unlockErrorText(e, 'Couldn\u2019t unlock \u2014 check both passwords.');
      err.style.display = '';
    } finally {
      setBusy(btn, false);
    }
  });
}

// A wrong password is a failed decrypt. Anything else (server down, bad
// token, clock skew) used to be reported as \"Wrong password.\" too.
function unlockErrorText(e, wrongPasswordText) {
  if (e && e.notCached) return e.message;
  if (e && e.status === 403) return 'The server says this note is still sealed \u2014 check this device\u2019s date and time.';
  if (e && e.status === 401) return 'The server rejected your access token \u2014 check Settings.';
  if (e && (e.status || e.isNetworkError)) return e.message;
  return wrongPasswordText;
}

// Key derivation takes a moment on a phone; show it, and ignore a second tap.
function setBusy(btn, busy, label) {
  if (busy) { btn.dataset.label = btn.textContent; btn.textContent = label; } else if (btn.dataset.label) { btn.textContent = btn.dataset.label; }
  btn.disabled = busy;
}

function notCachedError() {
  const err = new Error('Not available offline yet — open it once while connected.');
  err.notCached = true;
  return err;
}

// Reads a note's stored content: live from the server when reachable (which
// also refreshes the local copy), otherwise from the local cache. This is
// what lets any note — locked (still encrypted) or not — open with no
// connection at all.
// True while this note has a save/delete the server hasn't acknowledged. The
// local copy is then the newest version, and the server's must not replace it.
async function hasPendingChange(id) {
  return !!(await getOutboxItem(id));
}

// Opens from this device's copy whenever that copy is known to be current —
// it matches the version the note list reports, or it holds an edit the
// server hasn't received yet. Re-downloading the whole note (photos, audio
// and all) on every tap, even though an identical copy was already sitting in
// IndexedDB, was the slow part of opening a note. The list is refreshed on
// launch, after saves and whenever the app comes back to the foreground, so a
// note edited elsewhere still shows up as out-of-date here and is fetched.
async function fetchNoteContent(meta) {
  const [light, pending] = await Promise.all([getCachedMeta(meta.id), hasPendingChange(meta.id)]);
  const cacheIsCurrent = !!(light && light.hasContent && light.contentUpdatedAt === meta.updatedAt);
  if (cacheIsCurrent || pending) {
    const cached = await getCachedContent(meta.id);
    if (cached) return cached;
  }
  if (navigator.onLine && !pending) {
    try {
      const { content } = await API.getNote(meta.id);
      setOnline(true);
      cacheNote(meta, content); // not awaited — writing it to disk shouldn't hold up opening the note
      return content;
    } catch (e) {
      if (!e.isNetworkError) throw e;
      setOnline(false);
    }
  }
  const cached = await getCachedContent(meta.id);
  if (!cached) throw notCachedError();
  return cached;
}

// Brings a note's photos and audio back from Backblaze (media.js) once its content is readable.
// A note that keeps its media inline passes straight through. Throws, rather than opening
// a note with something missing, if a file can't be fetched \u2014 saving that would lose it.
function inflateForOpen(meta, content) {
  if (!window.KSMedia) return content;
  return KSMedia.inflate(meta.id, content, { onDownload: () => toast('Loading photos and audio\u2026') });
}

// Same idea for the released second password of a time-locked note.
async function fetchVaultPassword2(meta) {
  const light = await getCachedMeta(meta.id);
  if (light && light.vault && light.vaultUpdatedAt === meta.updatedAt) return light.vault;
  if (navigator.onLine) {
    try {
      const { password2 } = await API.getVault(meta.id);
      setOnline(true);
      cacheVault(meta.id, password2, meta.updatedAt);
      return password2;
    } catch (e) {
      if (!e.isNetworkError) throw e;
      setOnline(false);
    }
  }
  if (!light || !light.vault) {
    const err = new Error('Needs a connection — the second password is released by the server.');
    err.notCached = true;
    throw err;
  }
  return light.vault;
}

async function handleOpenCard(id) {
  const meta = notesCache.find((m) => m.id === id);
  if (!meta) return;
  if (meta.lockType === 'none') {
    try {
      const content = await inflateForOpen(meta, await fetchNoteContent(meta));
      currentUnlockCreds = null;
      openEditorWithContent(meta, content);
    } catch (e) {
      toast('Could not open note: ' + e.message);
    }
    return;
  }
  // Locked card: the first tap only reveals its download/delete buttons;
  // a tap once they're showing goes on to the unlock prompt as usual.
  if (!revealedLockedCards.has(id)) {
    revealLockedCard(id);
    return;
  }
  unrevealCard(id);
  currentUnlockCreds = null;
  openUnlockFlow(meta);
}

async function downloadNote(id) {
  try {
    let bundle = null;
    if (navigator.onLine && !(await hasPendingChange(id))) {
      try {
        bundle = await API.exportNote(id);
        setOnline(true);
        await cacheNote(bundle.meta, bundle.content);
        if (bundle.password2) await cacheVault(id, bundle.password2, bundle.meta.updatedAt);
      } catch (e) {
        if (!e.isNetworkError) throw e;
        setOnline(false);
      }
    }
    if (!bundle) {
      // Offline: build the same export from the local copy.
      const cached = await getCachedNote(id);
      if (!cached || !cached.content) throw notCachedError();
      bundle = { meta: cached.meta, content: cached.content, password2: cached.vault || null };
    }
    // Photos and audio kept in Backblaze are added to the file, so it is still a complete copy.
    if (window.KSMedia && bundle.meta && bundle.meta.mediaSize > 0) {
      bundle = await KSMedia.attachToBundle(id, bundle, { onDownload: () => toast('Gathering photos and audio\u2026') });
    }
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `keepsake-note-${id}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    toast('Downloaded');
  } catch (e) {
    toast('Could not download: ' + e.message);
  }
}

/* ---------------------------------------------------------------------
 * Confirm modal
 * ------------------------------------------------------------------- */

function openConfirm(title, message, onYes, yesLabel = 'Delete') {
  document.getElementById('confirm-title').textContent = title;
  document.getElementById('confirm-message').textContent = message;
  const yesBtn = document.getElementById('btn-confirm-yes');
  const freshYes = yesBtn.cloneNode(true);
  freshYes.textContent = yesLabel;
  yesBtn.parentNode.replaceChild(freshYes, yesBtn);
  freshYes.addEventListener('click', async () => {
    hide('overlay-confirm');
    await onYes();
  });
  show('overlay-confirm');
}

/* ---------------------------------------------------------------------
 * Settings
 * ------------------------------------------------------------------- */

// Mirrors sw.js's SHELL_FILES — kept as a separate list because sw.js runs
// in its own worker scope and can't be imported from here. Keep the two in
// sync if the shell's file list ever changes.
const FORCE_REFRESH_SHELL_FILES = [
  './index.html',
  './app.js',
  './media.js',
  './manifest.json',
  './icon-192.png',
  './icon-512.png',
];

function openSettings() {
  document.getElementById('settings-api-base').value = Config.base();
  document.getElementById('settings-token').value = Config.token();
  document.getElementById('settings-version').textContent = window.KEEPSAKE_VERSION || '1.6.0';
  fillQualitySettings();
  fillMediaSettings();
  show('overlay-settings');
  renderStorageSection();
  if (window.KSMedia && Config.configured()) KSMedia.refreshConfig().then(() => { fillMediaSettings(); renderStorageSection(); });
}

// The Backblaze row in Settings: whether the Worker has it set up, and a switch.
function fillMediaSettings() {
  const box = document.getElementById('settings-media-on');
  const status = document.getElementById('settings-media-status');
  if (!box || !status) return;
  const avail = !!(window.KSMedia && KSMedia.available());
  box.disabled = !avail;
  box.checked = avail && KSMedia.enabled();
  status.textContent = avail
    ? (box.checked
        ? 'On. New and edited notes keep their photos and audio in your Backblaze bucket (up to about 90 MB a file), so they no longer count toward the 25 MB note limit. Locked notes\u2019 media is encrypted first. Notes saved before this keep theirs inside until you next save them.'
        : 'Off. Photos and audio stay inside each note (25 MB limit per note).')
    : 'Not set up on your Worker, so photos and audio stay inside each note (25 MB limit per note). See the README to connect a Backblaze bucket.';
}

// Clears the installed service worker + its cached app shell, then reloads.
// Needed because sw.js only re-fetches the shell when the browser notices
// sw.js itself changed byte-for-byte — a deploy that only touches
// index.html/app.js can otherwise leave people stuck on an old cached shell
// indefinitely. This button is the manual escape hatch for that.
async function forceRefresh() {
  const btn = document.getElementById('btn-force-refresh');
  btn.disabled = true;
  btn.textContent = 'Refreshing…';
  try {
    if ('serviceWorker' in navigator) {
      const regs = await navigator.serviceWorker.getRegistrations();
      await Promise.all(regs.map((r) => r.unregister()));
    }
    if (window.caches) {
      const keys = await caches.keys();
      await Promise.all(keys.map((k) => caches.delete(k)));
    }
    // The two steps above only clear the Service Worker's own Cache
    // Storage — a separate layer from the browser's plain HTTP cache,
    // which can still serve an old app.js with no network request at
    // all. Re-fetching every shell file with `cache: 'reload'` forces a
    // real round trip and overwrites that HTTP cache entry, so the
    // reload below loads current code, not just an updated version
    // number in index.html.
    await Promise.all(FORCE_REFRESH_SHELL_FILES.map((f) =>
      fetch(f, { cache: 'reload' }).catch(() => {})
    ));
  } catch (e) {
    // best-effort — fall through to reload regardless
  }
  // Cache-bust the navigation itself so the browser's own HTTP cache can't
  // hand back a stale index.html either, now that no service worker is
  // left to intercept the request.
  const url = new URL(location.href);
  url.searchParams.set('_r', Date.now());
  location.replace(url.toString());
}

function saveSettings() {
  const base = document.getElementById('settings-api-base').value.trim();
  const token = document.getElementById('settings-token').value.trim();
  if (!base || !token) { toast('Both fields are needed'); return; }
  if (!/^https?:\/\//i.test(base)) { toast('Worker URL should start with https://'); return; }
  Config.setBase(base);
  Config.setToken(token);
  hide('overlay-settings');
  refreshNotes();
}

/* ---------------------------------------------------------------------
 * Wiring
 * ------------------------------------------------------------------- */

function wireStaticEvents() {
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-close]');
    if (btn) hide(btn.dataset.close);
  });
  document.querySelectorAll('.overlay').forEach((ov) => {
    ov.addEventListener('click', (e) => { if (e.target === ov && !overlayIsProtected(ov.id)) hide(ov.id); });
  });
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    hideRevealedCards();
    // The photo viewer handles its own Escape (see setupLightbox) \u2014 don't let
    // the same keypress also close the editor behind it.
    if (!document.getElementById('overlay-lightbox').classList.contains('hidden')) return;
    const openModals = document.querySelectorAll('.overlay:not(.hidden)');
    if (openModals.length) {
      // A modal (settings, lock chooser, unlock, confirm) is on top — close
      // just that, and leave the full-screen editor underneath it alone. A
      // recording in progress is protected: it ends only through its own buttons.
      openModals.forEach((ov) => { if (!overlayIsProtected(ov.id)) hide(ov.id); });
      return;
    }
    if (!document.getElementById('overlay-editor').classList.contains('hidden')) {
      if (Ink.mode) { setDrawMode(false); return; }
      attemptCloseEditor();
    }
  });

  document.addEventListener('click', (e) => {
    // Any tap outside the card whose buttons are showing tucks them away;
    // a tap on that card (or its buttons) just restarts the countdown.
    // (Only real taps count: the hidden link the download starts by
    // clicking is a script-made click and must not dismiss the card.)
    if (e.isTrusted) {
      const revealedCard = e.target.closest('.card.revealed');
      if (revealedCard) {
        const openEl = revealedCard.querySelector('.card-open');
        if (openEl) keepRevealed(openEl.dataset.id);
      } else {
        hideRevealedCards();
      }
    }
    const el = e.target.closest('[data-action]');
    if (!el) return;
    const { action, id } = el.dataset;
    if (action === 'open') handleOpenCard(id);
    if (action === 'download') downloadNote(id);
    if (action === 'delete') confirmDelete(id, false);
  });

  // Enter in a dialog field presses that dialog's primary button (there are no
  // <form>s here, so it did nothing before \u2014 on a phone keyboard too).
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' || e.isComposing || !e.target.matches || !e.target.matches('.modal input')) return;
    const scope = e.target.closest('#early-fields, #quick-lock-fields, #time-lock-fields, #unlock-body, .modal-body');
    const primary = scope && scope.querySelector('.btn-primary:not(:disabled)');
    if (primary) { e.preventDefault(); primary.click(); }
  });

  document.addEventListener('keydown', (e) => {
    if ((e.key === 'Enter' || e.key === ' ') && e.target.classList.contains('card-open')) {
      e.preventDefault();
      handleOpenCard(e.target.dataset.id);
    }
  });

  document.getElementById('tab-notes').addEventListener('click', () => switchView('notes'));
  document.getElementById('tab-locked').addEventListener('click', () => switchView('locked'));

  document.getElementById('btn-settings').addEventListener('click', openSettings);
  document.getElementById('btn-save-settings').addEventListener('click', saveSettings);
  document.getElementById('btn-force-refresh').addEventListener('click', forceRefresh);
  document.getElementById('btn-close-editor').addEventListener('click', attemptCloseEditor);

  document.getElementById('btn-new-note').addEventListener('click', () => {
    currentUnlockCreds = null;
    openEditorWithContent(null, { title: '', body: '', images: [] });
  });

  document.getElementById('btn-save-note').addEventListener('click', saveNote);
  document.getElementById('btn-delete-note').addEventListener('click', () => {
    if (editingNoteId) confirmDelete(editingNoteId, true);
  });

  document.getElementById('editor-title').addEventListener('input', onEditorContentChanged);
  document.getElementById('btn-download-note').addEventListener('click', () => {
    if (editingNoteId) downloadNote(editingNoteId);
  });

  document.getElementById('btn-attach-image').addEventListener('click', () => {
    document.getElementById('input-image').click();
  });
  document.getElementById('input-image').addEventListener('change', async (e) => {
    const files = Array.from(e.target.files || []);
    if (!files.length) return;

    const attachBtn = document.getElementById('btn-attach-image');
    attachBtn.disabled = true;
    let failed = 0;
    let dropped = 0;
    let refused = 0;
    const targetNoteId = editingNoteId; // photos belong to the note they were picked for

    for (let i = 0; i < files.length; i++) {
      syncBarSet(`Adding photo ${i + 1} of ${files.length}…`, i / files.length);
      try {
        const dataUrl = await fileToStoredDataURL(files[i]);
        // Compression is slow; if you've since opened a different note, these
        // must not be attached to it.
        if (editingNoteId !== targetNoteId) { dropped++; continue; }
        if (!canFitMedia(dataUrl.length + 4).ok) { refused++; continue; }
        editorImages.push(dataUrl);
        renderEditorThumbs(); // show each photo as soon as it's ready, not all at once at the end
        updateSizeMeter();
        onEditorContentChanged();
      } catch (err) {
        failed++;
      }
      syncBarSet(`Adding photo ${i + 1} of ${files.length}…`, (i + 1) / files.length);
    }

    syncBarHideSoon(700);
    attachBtn.disabled = false;
    e.target.value = '';

    if (dropped) {
      toast(dropped === 1 ? 'A photo wasn\u2019t added \u2014 you left that note first' : `${dropped} photos weren\u2019t added \u2014 you left that note first`);
    }
    if (failed) {
      toast(failed === 1 ? 'Couldn\u2019t read one of those photos' : `Couldn\u2019t read ${failed} of those photos`);
    }
    if (refused) {
      toast(refused === 1 ? `A photo wasn\u2019t added \u2014 it would push this note over ${limitWord()}` : `${refused} photos weren\u2019t added \u2014 they would push this note over ${limitWord()}`);
    } else {
      warnIfHeavy();
    }
  });

  document.getElementById('btn-open-lock-chooser').addEventListener('click', openLockChooser);

  document.getElementById('choice-quick').addEventListener('click', () => {
    document.getElementById('choice-quick').classList.add('selected');
    document.getElementById('choice-time').classList.remove('selected');
    document.getElementById('choice-quick').setAttribute('aria-pressed', 'true');
    document.getElementById('choice-time').setAttribute('aria-pressed', 'false');
    document.getElementById('quick-lock-fields').style.display = '';
    document.getElementById('time-lock-fields').style.display = 'none';
  });
  document.getElementById('choice-time').addEventListener('click', () => {
    document.getElementById('choice-time').classList.add('selected');
    document.getElementById('choice-quick').classList.remove('selected');
    document.getElementById('choice-time').setAttribute('aria-pressed', 'true');
    document.getElementById('choice-quick').setAttribute('aria-pressed', 'false');
    document.getElementById('time-lock-fields').style.display = '';
    document.getElementById('quick-lock-fields').style.display = 'none';
  });

  document.getElementById('btn-confirm-quick-lock').addEventListener('click', () => {
    const pw = document.getElementById('quick-password').value;
    const confirmPw = document.getElementById('quick-password-confirm').value;
    const err = document.getElementById('quick-lock-error');
    if (!pw || pw.length < 4) { err.textContent = 'Choose a password (4+ characters).'; err.classList.remove('visually-hidden'); return; }
    if (pw !== confirmPw) { err.textContent = 'Passwords don\u2019t match.'; err.classList.remove('visually-hidden'); return; }
    pendingLock = { type: 'quick', password: pw, existing: false };
    hide('overlay-lock-chooser');
    renderLockSummary();
    onEditorContentChanged();
  });

  document.getElementById('btn-confirm-time-lock').addEventListener('click', () => {
    const pw = document.getElementById('time-password').value;
    const confirmPw = document.getElementById('time-password-confirm').value;
    const unlockVal = document.getElementById('time-unlock-at').value;
    const err = document.getElementById('time-lock-error');
    if (!pw || pw.length < 4) { err.textContent = 'Choose a password (4+ characters).'; err.classList.remove('visually-hidden'); return; }
    if (pw !== confirmPw) { err.textContent = 'Passwords don\u2019t match.'; err.classList.remove('visually-hidden'); return; }
    if (!unlockVal) { err.textContent = 'Pick a date and time.'; err.classList.remove('visually-hidden'); return; }
    const unlockAt = new Date(unlockVal).getTime();
    // Leaving an existing lock's date untouched is fine even if it has passed
    // (the note just stays \"ready to open\"); any *changed* date must be in the future.
    const keepsDate = !!(pendingLock && pendingLock.type === 'time' && pendingLock.unlockAt
      && Math.floor(pendingLock.unlockAt / 60000) === Math.floor(unlockAt / 60000));
    if (unlockAt <= Date.now() && !keepsDate) { err.textContent = 'Pick a time in the future.'; err.classList.remove('visually-hidden'); return; }
    pendingLock = { type: 'time', password: pw, unlockAt: keepsDate ? pendingLock.unlockAt : unlockAt, existing: false };
    hide('overlay-lock-chooser');
    renderLockSummary();
    onEditorContentChanged();
  });

  document.getElementById('btn-remove-lock').addEventListener('click', () => {
    const doRemove = () => { pendingLock = null; renderLockSummary(); onEditorContentChanged(); };
    // One stray tap used to strip the lock and autosave the note unencrypted
    // two seconds later. If the server already holds an encrypted copy, ask first.
    if (pendingLock && (pendingLock.existing || noteExistsOnServer)) {
      openConfirm('Remove this lock?', 'The note will be saved without a password, and its text, photos and drawing will no longer be encrypted.', doRemove, 'Remove lock');
    } else {
      doRemove();
    }
  });
}

/* ---------------------------------------------------------------------
 * Init
 * ------------------------------------------------------------------- */

/* ---------------------------------------------------------------------
 * Rich text — bold / italic / underline, headings, lists
 *
 * The note body is a contenteditable element. What's *stored* is sanitized
 * HTML (only the handful of tags below, no attributes at all) in
 * `content.html`, plus a plain-text copy in `content.body` that previews
 * and older copies of the app keep using. Notes written before formatting
 * existed only have `body`; they're turned into paragraphs on open.
 * ------------------------------------------------------------------- */

const RICH_ALLOWED_TAGS = new Set([
  'P', 'DIV', 'BR', 'STRONG', 'B', 'EM', 'I', 'U',
  'H1', 'H2', 'H3', 'UL', 'OL', 'LI', 'BLOCKQUOTE',
]);
// Dropped along with everything inside them. Any other unknown tag
// (span, font, a, …) is unwrapped: its text stays, the tag goes.
const RICH_DROP_TAGS = new Set([
  'SCRIPT', 'STYLE', 'IFRAME', 'OBJECT', 'EMBED', 'LINK', 'META', 'TEMPLATE', 'NOSCRIPT',
  'SVG', 'MATH', 'FORM', 'INPUT', 'TEXTAREA', 'SELECT', 'BUTTON', 'IMG', 'VIDEO', 'AUDIO', 'CANVAS',
]);
const RICH_BLOCK_TAGS = new Set(['P', 'DIV', 'H1', 'H2', 'H3', 'LI', 'BLOCKQUOTE']);

function sanitizeHTML(html) {
  // DOMParser documents are inert: nothing in them runs or loads.
  const doc = new DOMParser().parseFromString('<!doctype html><body>' + String(html || ''), 'text/html');
  const walk = (node) => {
    let out = '';
    node.childNodes.forEach((child) => {
      if (child.nodeType === 3) { out += escapeHTML(child.nodeValue); return; }
      if (child.nodeType !== 1) return;
      const tag = child.tagName.toUpperCase();
      if (tag === 'KS-AUDIO') { // an inline audio clip: only its id survives (see ks-audio in the editor)
        const clipId = child.getAttribute('data-id') || '';
        if (AUDIO_ID_RE.test(clipId)) out += '<ks-audio data-id="' + clipId + '"></ks-audio>';
        return;
      }
      if (RICH_DROP_TAGS.has(tag)) return;
      if (tag === 'BR') { out += '<br>'; return; }
      const inner = walk(child);
      if (RICH_ALLOWED_TAGS.has(tag)) {
        const t = tag.toLowerCase();
        out += '<' + t + '>' + inner + '</' + t + '>';
      } else {
        out += inner;
      }
    });
    return out;
  };
  return walk(doc.body);
}

function textToHTML(text) {
  const t = String(text || '');
  if (!t) return '';
  return t.split('\n').map((line) => (line ? '<div>' + escapeHTML(line) + '</div>' : '<div><br></div>')).join('');
}

function htmlToText(html) {
  const doc = new DOMParser().parseFromString('<!doctype html><body>' + String(html || ''), 'text/html');
  const lines = [];
  let cur = '';
  const flush = () => { if (cur) { lines.push(cur); cur = ''; } };
  const walk = (node) => {
    node.childNodes.forEach((child) => {
      if (child.nodeType === 3) { cur += child.nodeValue; return; }
      if (child.nodeType !== 1) return;
      const tag = child.tagName.toUpperCase();
      if (tag === 'KS-AUDIO') { // shows in previews and plain-text readers as a marker
        const clip = editorAudio[child.getAttribute('data-id')];
        if (cur && !/\s$/.test(cur)) cur += ' ';
        cur += '\u{1F399} ' + (clip && clip.dur > 0 ? mmss(clip.dur) : 'audio');
        return;
      }
      if (tag === 'BR') {
        // A <br> that just holds an otherwise-empty block open (<div><br></div>) is a blank line.
        lines.push(cur); cur = ''; return;
      }
      if (RICH_BLOCK_TAGS.has(tag)) {
        flush();
        if (tag === 'LI') cur = '\u2022 ';
        walk(child);
        flush();
      } else {
        walk(child);
      }
    });
  };
  walk(doc.body);
  flush();
  return lines.join('\n').replace(/\u00a0/g, ' ').replace(/\n+$/, '');
}

let savedBodyRange = null;

function selectionInBody() {
  const body = document.getElementById('editor-body');
  const sel = window.getSelection();
  return !!(sel && sel.rangeCount && body.contains(sel.anchorNode));
}

function currentBlockTag() {
  const body = document.getElementById('editor-body');
  const sel = window.getSelection();
  let node = sel && sel.anchorNode;
  while (node && node !== body) {
    if (node.nodeType === 1 && RICH_BLOCK_TAGS.has(node.tagName.toUpperCase())) {
      const tag = node.tagName.toLowerCase();
      if (tag !== 'li') return tag;
    }
    node = node.parentNode;
  }
  return 'div';
}

function updateFormatState() {
  if (!selectionInBody()) return;
  const block = currentBlockTag();
  const state = {
    bold: document.queryCommandState('bold'),
    italic: document.queryCommandState('italic'),
    underline: document.queryCommandState('underline'),
    h1: block === 'h1',
    h2: block === 'h2',
    ul: document.queryCommandState('insertUnorderedList'),
    ol: document.queryCommandState('insertOrderedList'),
  };
  document.querySelectorAll('[data-fmt]').forEach((btn) => {
    btn.setAttribute('aria-pressed', String(!!state[btn.dataset.fmt]));
  });
}

function runFormat(cmd) {
  const body = document.getElementById('editor-body');
  if (!selectionInBody()) {
    body.focus();
    if (savedBodyRange) {
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(savedBodyRange);
    }
  }
  if (cmd === 'bold' || cmd === 'italic' || cmd === 'underline') {
    document.execCommand(cmd);
  } else if (cmd === 'h1' || cmd === 'h2') {
    // Tapping the active heading again turns it back into a normal paragraph.
    document.execCommand('formatBlock', false, currentBlockTag() === cmd ? '<div>' : '<' + cmd + '>');
  } else if (cmd === 'ul') {
    document.execCommand('insertUnorderedList');
  } else if (cmd === 'ol') {
    document.execCommand('insertOrderedList');
  }
  updateFormatState();
  onEditorContentChanged();
}

/* ---------------------------------------------------------------------
 * Size meter — how big this note is against the limits, with warnings.
 * Each level has its own icon shape and a word, so it never relies on colour.
 * ------------------------------------------------------------------- */

const ZONE_ICON = {
  ok: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M8 12.5l2.7 2.7L16 9.5"/></svg>',
  heavy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3.5l9.5 16.5h-19z"/><path d="M12 10v4.5M12 17.4v.1"/></svg>',
  danger: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8.2 3h7.6L21 8.2v7.6L15.8 21H8.2L3 15.8V8.2z"/><path d="M12 8v5M12 16.4v.1"/></svg>',
  over: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/></svg>',
};
const ZONE_WORD = { ok: 'Comfortable', heavy: 'Getting heavy', danger: 'Close to the limit', over: 'Over the limit' };

let lastNoteBytes = 0;
let sizeMeterTimer = null;
let lastWarnedZone = 'ok';

function mb1(bytes) { return (bytes / 1048576).toFixed(1); }

function scheduleSizeMeter() {
  clearTimeout(sizeMeterTimer);
  sizeMeterTimer = setTimeout(updateSizeMeter, 300);
}

function updateSizeMeter() {
  clearTimeout(sizeMeterTimer);
  const btn = document.getElementById('btn-size');
  if (!btn) return;
  const b = noteSizeBreakdown();
  lastNoteBytes = b.total;
  const zone = noteSizeZone(b.total);
  btn.dataset.zone = zone;
  document.getElementById('size-icon').innerHTML = ZONE_ICON[zone];
  document.getElementById('size-text').textContent = `${mb1(b.total)} / 25 MB`;
  document.getElementById('size-fill').style.transform = `scaleX(${Math.min(1, b.total / NOTE_SIZE_LIMIT).toFixed(4)})`;
  btn.setAttribute('aria-label', `Note size: ${mb1(b.total)} of 25 megabytes. ${ZONE_WORD[zone]}. Open details.`);
  if (!document.getElementById('overlay-size').classList.contains('hidden')) renderSizeDialog(b);
}

// A toast only when a note first crosses into a worse level — not on every keystroke.
function warnIfHeavy() {
  const zone = noteSizeZone(noteSizeBreakdown().total);
  const order = ['ok', 'heavy', 'danger', 'over'];
  if (order.indexOf(zone) > order.indexOf(lastWarnedZone)) {
    if (zone === 'heavy') toast('This note is getting heavy \u2014 see the size indicator at the top.');
    if (zone === 'danger') toast('This note is close to the size limit. Saving may fail \u2014 consider moving some media elsewhere.');
    if (zone === 'over') toast('This note is over the 25 MB limit and can\u2019t be saved until you remove something.');
  }
  lastWarnedZone = zone;
}

function renderSizeDialog(b) {
  b = b || noteSizeBreakdown();
  const zone = noteSizeZone(b.total);
  document.getElementById('size-status').innerHTML =
    `<span class="size-badge" data-zone="${zone}">${ZONE_ICON[zone]}<span>${ZONE_WORD[zone]}</span></span>` +
    `<span class="size-figure">${mb1(b.total)} MB of 25 MB</span>`;
  const meter = document.getElementById('size-dialog-meter');
  meter.dataset.zone = zone;
  meter.setAttribute('aria-valuenow', String(Math.round(b.total / 1048576 * 10) / 10));
  document.getElementById('size-dialog-fill').style.transform = `scaleX(${Math.min(1, b.total / NOTE_SIZE_LIMIT).toFixed(4)})`;

  const rows = [['Text', b.text]];
  if (b.offload) {
    if (b.photoCount || b.clips) rows.push([`Photos & audio (${b.photoCount + b.clips}) \u2014 in Backblaze`, b.offloaded, true]);
  } else {
    if (b.photoCount) rows.push([`Photos (${b.photoCount})`, b.photos]);
    if (b.clips) rows.push([`Audio (${b.clips} clip${b.clips === 1 ? '' : 's'})`, b.audio]);
  }
  if (b.drawing) rows.push(['Drawing', b.drawing]);
  if (b.locked) rows.push(['Lock encryption', b.lockExtra]);
  document.getElementById('size-rows').innerHTML = rows.map(([label, bytes, noBar]) =>
    `<li><span class="size-row-label">${escapeHTML(label)}</span>` +
    `<span class="size-row-bar" aria-hidden="true"><span style="transform:scaleX(${noBar ? '0' : Math.min(1, bytes / Math.max(1, b.total)).toFixed(3)})"></span></span>` +
    `<span class="size-row-value">${formatBytes(bytes)}</span></li>`).join('');

  const advice = {
    ok: 'Plenty of room.',
    heavy: 'This note is getting heavy. It will be slower to open and to sync, especially on mobile data. Moving some photos or recordings into another note keeps each one quick.',
    danger: 'This note is close to the limit. Above about 20 MB the Worker is more likely to run out of memory or time while saving it, and the free plan is the first to struggle. Remove or split some media before adding more.',
    over: 'This note is over the 25 MB limit and can\u2019t be saved. Remove a photo or audio clip \u2014 or lower the quality in Settings and add them again.',
  };
  let text = advice[zone];
  if (b.offload && b.offloaded) text += ` ${mb1(b.offloaded)} MB of photos and audio is stored in Backblaze and doesn\u2019t count toward this limit.`;
  if (b.locked) text += ' Locked notes are about a third bigger than their contents, because encrypted data is stored as text.';
  document.getElementById('size-advice').textContent = text;
  document.getElementById('size-advice-icon').innerHTML = ZONE_ICON[zone];
  document.getElementById('size-advice-box').dataset.zone = zone;
}

/* ---------------------------------------------------------------------
 * Storage — every note against the account's total allowance.
 * ------------------------------------------------------------------- */

function storageUsage() {
  const limit = Config.storageLimitMB() * 1024 * 1024;
  let used = 0;
  let unknown = 0;
  let media = 0;
  const sized = [];
  for (const m of notesCache) {
    media += m._media || 0;
    if (typeof m._bytes === 'number') {
      used += m._bytes;
      sized.push({ title: m.title || m._lockedTitle || 'Untitled', bytes: m._bytes, locked: m.lockType !== 'none' });
    } else unknown++;
  }
  sized.sort((x, y) => y.bytes - x.bytes);
  const ratio = limit ? used / limit : 0;
  const zone = ratio > 1 ? 'over' : ratio >= STORAGE_DANGER_RATIO ? 'danger' : ratio >= STORAGE_WARN_RATIO ? 'heavy' : 'ok';
  return { used, limit, ratio, zone, unknown, media, count: notesCache.length, top: sized.slice(0, 3) };
}

function renderStorageSection() {
  const card = document.getElementById('storage-card');
  if (!card || document.getElementById('overlay-settings').classList.contains('hidden')) return;
  const u = storageUsage();
  const pct = Math.round(u.ratio * 100);
  card.dataset.zone = u.zone;
  const badgeWord = { ok: 'Plenty of room', heavy: 'Filling up', danger: 'Almost full', over: 'Over the limit' }[u.zone];
  document.getElementById('storage-badge').dataset.zone = u.zone;
  document.getElementById('storage-badge').innerHTML = `${ZONE_ICON[u.zone]}<span>${badgeWord}</span>`;
  document.getElementById('storage-figures').textContent = `${formatBytes(u.used)} of ${Config.storageLimitMB().toLocaleString()} MB (${pct}%)`;
  const meter = document.getElementById('storage-meter');
  meter.dataset.zone = u.zone;
  meter.setAttribute('aria-valuenow', String(Math.min(100, pct)));
  document.getElementById('storage-fill').style.transform = `scaleX(${Math.min(1, u.ratio).toFixed(4)})`;
  const msg = {
    ok: '',
    heavy: 'You\u2019ve used over 70% of your storage. Consider downloading and deleting notes you no longer need.',
    danger: 'You\u2019ve used over 90% of your storage. Once it\u2019s full, saving will fail. Free up space by deleting or downloading big notes.',
    over: 'Storage is over the limit you set. Saving may fail until you free up space.',
  }[u.zone];
  let extra = `${u.count} note${u.count === 1 ? '' : 's'}`;
  if (u.unknown) extra += ` \u00b7 ${u.unknown} not measured yet (counted once they\u2019ve synced to this device)`;
  document.getElementById('storage-message').textContent = (msg ? msg + ' ' : '') + extra + '.';
  document.getElementById('storage-top').innerHTML = u.top.length
    ? u.top.map((t) => `<li><span class="storage-top-title">${escapeHTML(t.title)}</span><span>${formatBytes(t.bytes)}</span></li>`).join('')
    : '';
  document.getElementById('storage-top-label').hidden = !u.top.length;
  const mediaLine = document.getElementById('storage-media');
  if (mediaLine) {
    mediaLine.hidden = !(u.media > 0 || (window.KSMedia && KSMedia.available()));
    mediaLine.textContent = `Photos and audio in Backblaze: ${formatBytes(u.media)} of the 10 GB its free plan includes.`;
  }
}

function updateStoragePill() {
  const pill = document.getElementById('storage-pill');
  if (!pill) return;
  const u = storageUsage();
  if (u.ratio < STORAGE_WARN_RATIO) { pill.hidden = true; return; }
  pill.hidden = false;
  pill.dataset.zone = u.zone;
  document.getElementById('storage-pill-icon').innerHTML = ZONE_ICON[u.zone];
  document.getElementById('storage-pill-text').textContent = `Storage ${Math.round(u.ratio * 100)}%`;
  pill.setAttribute('aria-label', `Storage ${Math.round(u.ratio * 100)} percent full. Open settings for details.`);
}

function fillQualitySettings() {
  const photo = document.getElementById('settings-photo-quality');
  const audio = document.getElementById('settings-audio-quality');
  photo.value = Config.photoQuality();
  audio.value = Config.audioQuality();
  document.getElementById('settings-photo-hint').textContent = PHOTO_QUALITY[photo.value].hint;
  document.getElementById('settings-audio-hint').textContent = AUDIO_QUALITY[audio.value].hint;
  document.getElementById('settings-storage-limit').value = Config.storageLimitMB();
}

/* ---------------------------------------------------------------------
 * Audio clips — recorded in the app or attached from a file, placed in the
 * text wherever the caret was (between sentences, or between two words).
 * Each clip lives in content.audio[id]; the text holds <ks-audio data-id>
 * where it belongs. Everything is encrypted along with the note if it's locked.
 * ------------------------------------------------------------------- */

const AUDIO_ID_RE = /^[a-z0-9]{6,32}$/;
const AUDIO_EXT = {
  'audio/webm': 'webm', 'video/webm': 'webm', 'audio/ogg': 'ogg', 'audio/opus': 'opus', 'audio/mp4': 'm4a',
  'audio/x-m4a': 'm4a', 'audio/m4a': 'm4a', 'audio/aac': 'aac', 'audio/mpeg': 'mp3', 'audio/mp3': 'mp3',
  'audio/wav': 'wav', 'audio/x-wav': 'wav', 'audio/wave': 'wav', 'audio/flac': 'flac', 'audio/x-flac': 'flac',
};
const EXT_MIME = {
  mp3: 'audio/mpeg', m4a: 'audio/mp4', aac: 'audio/aac', wav: 'audio/wav', ogg: 'audio/ogg', oga: 'audio/ogg',
  opus: 'audio/ogg', flac: 'audio/flac', webm: 'audio/webm', weba: 'audio/webm',
};

function newAudioId() {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  return 'a' + Array.from(bytes, (x) => x.toString(16).padStart(2, '0')).join('');
}

function mmss(sec) {
  sec = Math.max(0, Math.round(Number(sec) || 0));
  return Math.floor(sec / 60) + ':' + String(sec % 60).padStart(2, '0');
}

function fmtDur(sec) { return Number(sec) > 0 ? mmss(sec) : '\u2013:\u2013\u2013'; }

function audioMime(dataUrl) {
  const m = /^data:([^;,]+)/.exec(dataUrl || '');
  return m ? m[1].toLowerCase() : '';
}

function audioExtFor(clip) {
  const byMime = AUDIO_EXT[audioMime(clip.data)];
  if (byMime) return byMime;
  const m = /\.([a-z0-9]{2,5})$/i.exec(clip.name || '');
  return m ? m[1].toLowerCase() : 'audio';
}

// Only well-formed clips with audio data: URLs are ever loaded.
function sanitizeAudioMap(map) {
  const out = {};
  if (!map || typeof map !== 'object') return out;
  for (const id of Object.keys(map)) {
    const a = map[id];
    if (!AUDIO_ID_RE.test(id) || !a || typeof a.data !== 'string' || !/^data:audio\//.test(a.data)) continue;
    out[id] = {
      data: a.data,
      dur: Math.min(Math.max(Number(a.dur) || 0, 0), 86400),
      name: typeof a.name === 'string' ? a.name.slice(0, 120) : '',
    };
  }
  return out;
}

function clipIndex(id) {
  const ids = Array.from(document.querySelectorAll('#editor-body ks-audio')).map((el) => el.getAttribute('data-id'));
  const i = ids.indexOf(id);
  return i < 0 ? 1 : i + 1;
}

// ---- the chip in the text ----

function audioChipHTML(id) {
  const clip = editorAudio[id];
  if (!clip) return '<span class="audio-chip is-missing" role="img" aria-label="Audio clip missing">Clip missing</span>';
  const t = fmtDur(clip.dur);
  const label = clip.dur > 0 ? `Play audio clip, ${t}` : 'Play audio clip';
  return `<span class="audio-chip" data-id="${id}">` +
    `<button type="button" class="audio-play" aria-label="${label}" aria-pressed="false"></button>` +
    `<span class="audio-time" aria-hidden="true">${t}</span>` +
    `<button type="button" class="audio-more" aria-label="Clip options" aria-haspopup="dialog"></button></span>`;
}

function hydrateAudioChips(root) {
  root.querySelectorAll('ks-audio').forEach((el) => {
    el.setAttribute('contenteditable', 'false');
    el.innerHTML = audioChipHTML(el.getAttribute('data-id'));
  });
}

function insertAudioChip(id) {
  const body = document.getElementById('editor-body');
  const chip = document.createElement('ks-audio');
  chip.setAttribute('data-id', id);
  chip.setAttribute('contenteditable', 'false');
  chip.innerHTML = audioChipHTML(id);
  const space = document.createTextNode('\u00a0'); // somewhere for the caret to land after the clip
  let range = null;
  if (savedBodyRange && body.contains(savedBodyRange.startContainer) && body.contains(savedBodyRange.endContainer)) {
    range = savedBodyRange.cloneRange();
  } else {
    range = document.createRange();
    range.selectNodeContents(body);
    range.collapse(false);
  }
  range.deleteContents();
  range.insertNode(space);
  space.parentNode.insertBefore(chip, space);
  const sel = window.getSelection();
  const after = document.createRange();
  after.setStartAfter(space);
  after.collapse(true);
  sel.removeAllRanges();
  sel.addRange(after);
  savedBodyRange = after.cloneRange();
  if (chip.scrollIntoView) chip.scrollIntoView({ block: 'nearest' });
  body.dispatchEvent(new Event('input', { bubbles: true }));
}

function addAudioClip(clip) {
  const id = newAudioId();
  editorAudio[id] = { data: clip.data, dur: Math.max(0, Number(clip.dur) || 0), name: clip.name || '' };
  insertAudioChip(id);
  updateSizeMeter();
  warnIfHeavy();
  return id;
}

// Would this much more stored data still fit in the note?
function canFitMedia(storedLen) {
  const b = noteSizeBreakdown();
  if (b.offload) {
    const itemOk = storedLen <= MEDIA_ITEM_MAX_CHARS;
    return {
      ok: itemOk && b.mediaChars + storedLen <= MEDIA_NOTE_MAX_CHARS,
      projected: b.total + 300,
      message: itemOk ? 'That would make this note\u2019s photos and audio more than 150 MB.' : 'That file is over the 90 MB limit.',
    };
  }
  const projected = b.total + Math.ceil(storedLen * (b.locked ? 4 / 3 : 1));
  return {
    ok: projected <= NOTE_SIZE_LIMIT,
    projected,
    message: `That would make this note ${mb1(projected)} MB \u2014 over the 25 MB limit.`,
  };
}

// ---- playback ----

const Player = { el: null, id: null };
const audioUrls = new Map(); // clip id -> blob: URL

function ensurePlayer() {
  if (Player.el) return Player.el;
  const el = new Audio();
  el.preload = 'auto';
  ['play', 'pause', 'ended', 'timeupdate'].forEach((ev) => el.addEventListener(ev, syncChipStates));
  Player.el = el;
  return el;
}

async function audioUrl(id) {
  if (audioUrls.has(id)) return audioUrls.get(id);
  const clip = editorAudio[id];
  if (!clip) return null;
  const blob = await (await fetch(clip.data)).blob();
  const url = URL.createObjectURL(blob);
  audioUrls.set(id, url);
  return url;
}

function clearAudioUrls() {
  if (Player.el) { Player.el.pause(); Player.el.removeAttribute('src'); Player.el.load(); }
  Player.id = null;
  for (const url of audioUrls.values()) URL.revokeObjectURL(url);
  audioUrls.clear();
  const clipEl = document.getElementById('clip-audio');
  if (clipEl) { clipEl.pause(); clipEl.removeAttribute('src'); }
}

function syncChipStates() {
  const el = Player.el;
  document.querySelectorAll('#editor-body .audio-chip').forEach((chip) => {
    const mine = chip.dataset.id === Player.id;
    const playing = !!(mine && el && !el.paused && !el.ended);
    chip.classList.toggle('is-playing', playing);
    const btn = chip.querySelector('.audio-play');
    if (btn) btn.setAttribute('aria-pressed', String(playing));
    const d = el && el.duration;
    chip.style.setProperty('--p', mine && d && isFinite(d) ? Math.min(1, el.currentTime / d).toFixed(3) : '0');
  });
}

async function toggleClipPlayback(id) {
  const el = ensurePlayer();
  if (Player.id === id && !el.paused) { el.pause(); return; }
  try {
    const url = await audioUrl(id);
    if (!url) return;
    if (Player.id !== id || !el.src) { el.src = url; Player.id = id; }
    else if (el.ended) el.currentTime = 0;
    await el.play();
  } catch (e) {
    toast('Couldn\u2019t play this clip');
  }
}

// ---- clip options dialog ----

let clipDialogId = null;

async function openClipDialog(id) {
  const clip = editorAudio[id];
  if (!clip) return;
  if (Player.el) Player.el.pause();
  clipDialogId = id;
  document.getElementById('clip-heading').textContent = `Audio clip ${clipIndex(id)}`;
  document.getElementById('clip-meta').textContent = [
    fmtDur(clip.dur), formatBytes(estimateImageBytes(clip.data)), audioExtFor(clip).toUpperCase(), clip.name,
  ].filter(Boolean).join(' \u00b7 ');
  const url = await audioUrl(id);
  document.getElementById('clip-audio').src = url || '';
  show('overlay-clip');
}

function pauseClipPreview() {
  const el = document.getElementById('clip-audio');
  if (el) el.pause();
}

function clipFileName(id) {
  const clip = editorAudio[id];
  const ext = audioExtFor(clip);
  const cleanName = (clip.name || '').replace(/\.[a-z0-9]{2,5}$/i, '').replace(/[^\w\- ]+/g, '').trim();
  const title = (document.getElementById('editor-title').value || 'note').replace(/[^\w\- ]+/g, '').trim().slice(0, 40) || 'note';
  return `${cleanName || `${title} - clip ${clipIndex(id)}`}.${ext}`.replace(/\s+/g, '-');
}

async function downloadClip(id) {
  try {
    const url = await audioUrl(id);
    if (!url) throw new Error('missing');
    const a = document.createElement('a');
    a.href = url;
    a.download = clipFileName(id);
    document.body.appendChild(a);
    a.click();
    a.remove();
    toast('Downloaded');
  } catch (e) {
    toast('Couldn\u2019t download this clip');
  }
}

function deleteClip(id) {
  document.querySelectorAll(`#editor-body ks-audio[data-id="${id}"]`).forEach((el) => el.remove());
  if (Player.id === id && Player.el) { Player.el.pause(); Player.id = null; }
  hide('overlay-clip');
  updateSizeMeter();
  onEditorContentChanged();
}

// ---- attaching audio files ----

function probeAudioDuration(url) {
  return new Promise((resolve) => {
    const a = new Audio();
    a.preload = 'metadata';
    let done = false;
    const finish = (d) => { if (done) return; done = true; a.removeAttribute('src'); resolve(isFinite(d) && d > 0 ? d : 0); };
    a.onloadedmetadata = () => {
      if (isFinite(a.duration)) { finish(a.duration); return; }
      a.currentTime = 1e101; // some webm files report Infinity until you seek to the end
      a.ontimeupdate = () => { a.ontimeupdate = null; finish(a.duration); };
    };
    a.onerror = () => finish(0);
    setTimeout(() => finish(0), 8000);
    a.src = url;
  });
}

async function attachAudioFiles(files) {
  const targetNoteId = editingNoteId;
  let added = 0;
  let refused = 0;
  let unreadable = 0;
  for (const file of files) {
    const ext = ((/\.([a-z0-9]+)$/i.exec(file.name) || [])[1] || '').toLowerCase();
    if (!/^audio\//.test(file.type) && !EXT_MIME[ext]) { unreadable++; continue; }
    if (!canFitMedia(Math.ceil(file.size * 4 / 3) + 40).ok) { refused++; continue; }
    try {
      let data = await readFileAsDataURL(file);
      if (!/^data:audio\//.test(data)) data = data.replace(/^data:[^;,]*/, 'data:' + (EXT_MIME[ext] || 'audio/mpeg'));
      if (editingNoteId !== targetNoteId) break;
      const url = URL.createObjectURL(file);
      const dur = await probeAudioDuration(url);
      URL.revokeObjectURL(url);
      if (editingNoteId !== targetNoteId) break;
      if (!canFitMedia(data.length + 4).ok) { refused++; continue; }
      addAudioClip({ data, dur, name: file.name });
      added++;
    } catch (e) { unreadable++; }
  }
  if (refused) toast(refused === 1 ? `A file wasn\u2019t added \u2014 it would push this note over ${limitWord()}` : `${refused} files weren\u2019t added \u2014 they would push this note over ${limitWord()}`);
  else if (unreadable) toast(unreadable === 1 ? 'Couldn\u2019t read that file as audio' : `Couldn\u2019t read ${unreadable} of those files as audio`);
  return added;
}

// ---- recording ----

const Rec = {
  state: 'idle', stream: null, recorder: null, chunks: [], bytes: 0, t0: 0, stopAt: 0, tick: 0,
  ctx: null, analyser: null, buf: null, blob: null, dur: 0, previewUrl: null, discard: false,
  baseBytes: 0, autoStopped: false,
};

function recorderSupported() {
  return !!(window.isSecureContext && navigator.mediaDevices && navigator.mediaDevices.getUserMedia && window.MediaRecorder);
}

function setRecState(state) {
  Rec.state = state;
  document.querySelectorAll('#overlay-record .rec-panel').forEach((p) => { p.hidden = p.dataset.panel !== state; });
}

function showRecError(msg) { const el = document.getElementById('record-error'); el.textContent = msg; el.hidden = !msg; }

function micErrorText(e) {
  const n = e && e.name;
  if (n === 'NotAllowedError' || n === 'SecurityError') return 'Microphone access is blocked. Allow it in your browser\u2019s site settings and try again \u2014 or attach an audio file instead.';
  if (n === 'NotFoundError' || n === 'OverconstrainedError') return 'No microphone was found on this device.';
  if (n === 'NotReadableError') return 'The microphone is being used by another app.';
  return 'Couldn\u2019t start the microphone.';
}

function overlayIsProtected(id) { return id === 'overlay-record' && Rec.state !== 'idle'; }

function openRecorder() {
  recorderTeardown();
  setRecState('idle');
  const q = AUDIO_QUALITY[Config.audioQuality()];
  document.getElementById('record-quality').textContent = `Quality: ${q.label}. ${q.hint} Change it in Settings.`;
  showRecError('');
  const ok = recorderSupported();
  document.getElementById('btn-record-start').disabled = !ok;
  if (!ok) showRecError(window.isSecureContext
    ? 'Recording isn\u2019t supported in this browser. You can still attach an audio file.'
    : 'Recording needs a secure (https) connection. You can still attach an audio file.');
  show('overlay-record');
}

function pickRecorderMime() {
  const candidates = ['audio/webm;codecs=opus', 'audio/mp4', 'audio/webm', 'audio/ogg;codecs=opus'];
  return candidates.find((t) => MediaRecorder.isTypeSupported(t)) || '';
}

function stopMicAndMeter() {
  if (Rec.stream) { Rec.stream.getTracks().forEach((t) => { t.onended = null; t.stop(); }); Rec.stream = null; }
  if (Rec.ctx) { try { Rec.ctx.close(); } catch (e) { /* already closed */ } Rec.ctx = null; }
  Rec.analyser = null;
}

function recorderTeardown() {
  clearInterval(Rec.tick);
  if (Rec.recorder && Rec.recorder.state !== 'inactive') {
    Rec.discard = true;
    try { Rec.recorder.stop(); } catch (e) { /* already stopped */ }
  }
  Rec.recorder = null;
  stopMicAndMeter();
  if (Rec.previewUrl) { URL.revokeObjectURL(Rec.previewUrl); Rec.previewUrl = null; }
  const prev = document.getElementById('record-preview');
  if (prev) { prev.pause(); prev.removeAttribute('src'); }
  Rec.chunks = []; Rec.blob = null; Rec.bytes = 0; Rec.autoStopped = false;
  Rec.state = 'idle';
}

function startMeter(stream) {
  try {
    const AC = window.AudioContext || window.webkitAudioContext;
    if (!AC) return;
    Rec.ctx = new AC();
    const src = Rec.ctx.createMediaStreamSource(stream);
    Rec.analyser = Rec.ctx.createAnalyser();
    Rec.analyser.fftSize = 512;
    src.connect(Rec.analyser);
    Rec.buf = new Uint8Array(Rec.analyser.fftSize);
  } catch (e) { Rec.analyser = null; }
}

function readLevel() {
  if (!Rec.analyser) return 0;
  Rec.analyser.getByteTimeDomainData(Rec.buf);
  let sum = 0;
  for (let i = 0; i < Rec.buf.length; i++) { const d = (Rec.buf[i] - 128) / 128; sum += d * d; }
  return Math.min(1, Math.sqrt(sum / Rec.buf.length) * 3);
}

function projectedStored(bytesSoFar) { // what a clip of this many raw bytes adds to the note
  if (mediaOffloadOn()) return Math.ceil(bytesSoFar * 4 / 3); // stored in Backblaze: just its base64 length, locked or not
  return Math.ceil(bytesSoFar * 4 / 3 * (lockIsActive() ? 4 / 3 : 1));
}

function updateRecUI() {
  if (Rec.state !== 'recording') return;
  const q = AUDIO_QUALITY[Config.audioQuality()];
  const elapsed = (performance.now() - Rec.t0) / 1000;
  document.getElementById('record-timer').textContent = mmss(elapsed);
  document.getElementById('record-level').style.setProperty('--level', readLevel().toFixed(2));
  const clipBytes = projectedStored(Math.max(Rec.bytes, q.bps / 8 * elapsed));
  const projected = Rec.baseBytes + clipBytes;
  const off = mediaOffloadOn();
  const zone = off ? mediaZone(projected) : noteSizeZone(projected);
  const box = document.getElementById('record-projection');
  box.dataset.zone = zone;
  box.innerHTML = off
    ? `${ZONE_ICON[zone]}<span>This clip \u2248 ${formatBytes(Math.round(clipBytes * 3 / 4))} \u00b7 photos and audio would be ${mb1(projected * 3 / 4)} / 150 MB</span>`
    : `${ZONE_ICON[zone]}<span>This clip \u2248 ${formatBytes(clipBytes)} \u00b7 note would be ${mb1(projected)} / 25 MB</span>`;
}

function guardRecordingSize() {
  if (Rec.baseBytes + projectedStored(Rec.bytes) > (mediaOffloadOn() ? MEDIA_NOTE_MAX_CHARS : NOTE_SIZE_LIMIT) - 256 * 1024) {
    Rec.autoStopped = true;
    stopRecording();
  }
}

async function startRecording() {
  showRecError('');
  if (!recorderSupported()) { showRecError('Recording isn\u2019t available here. You can still attach an audio file.'); return; }
  let stream;
  try { stream = await navigator.mediaDevices.getUserMedia({ audio: true }); }
  catch (e) { showRecError(micErrorText(e)); return; }
  if (document.getElementById('overlay-record').classList.contains('hidden')) { stream.getTracks().forEach((t) => t.stop()); return; }
  const mime = pickRecorderMime();
  const q = AUDIO_QUALITY[Config.audioQuality()];
  let recorder;
  try { recorder = new MediaRecorder(stream, { ...(mime ? { mimeType: mime } : {}), audioBitsPerSecond: q.bps }); }
  catch (e) { try { recorder = new MediaRecorder(stream); } catch (e2) { stream.getTracks().forEach((t) => t.stop()); showRecError('Couldn\u2019t start recording in this browser.'); return; } }
  Rec.stream = stream;
  Rec.recorder = recorder;
  Rec.chunks = [];
  Rec.bytes = 0;
  Rec.discard = false;
  Rec.autoStopped = false;
  { const b0 = noteSizeBreakdown(); Rec.baseBytes = b0.offload ? b0.mediaChars : b0.total; }
  recorder.ondataavailable = (ev) => {
    if (!ev.data || !ev.data.size) return;
    Rec.chunks.push(ev.data);
    Rec.bytes += ev.data.size;
    guardRecordingSize();
  };
  recorder.onstop = finishRecording;
  recorder.onerror = () => { showRecError('The recording stopped unexpectedly.'); stopRecording(); };
  stream.getAudioTracks().forEach((t) => { t.onended = () => stopRecording(); });
  startMeter(stream);
  Rec.t0 = performance.now();
  recorder.start(1000);
  setRecState('recording');
  clearInterval(Rec.tick);
  Rec.tick = setInterval(updateRecUI, 150);
  updateRecUI();
}

function stopRecording() {
  if (Rec.state !== 'recording' || !Rec.recorder || Rec.recorder.state === 'inactive') return;
  Rec.stopAt = performance.now();
  try { Rec.recorder.stop(); } catch (e) { /* onstop still follows */ }
}

function finishRecording() {
  clearInterval(Rec.tick);
  stopMicAndMeter();
  if (Rec.discard) { Rec.discard = false; return; }
  const type = (Rec.recorder && Rec.recorder.mimeType) || 'audio/webm';
  const blob = new Blob(Rec.chunks, { type });
  Rec.chunks = [];
  if (!blob.size) { showRecError('Nothing was recorded \u2014 check that your microphone is working.'); setRecState('idle'); return; }
  Rec.blob = blob;
  Rec.dur = ((Rec.stopAt || performance.now()) - Rec.t0) / 1000;
  if (Rec.previewUrl) URL.revokeObjectURL(Rec.previewUrl);
  Rec.previewUrl = URL.createObjectURL(blob);
  document.getElementById('record-preview').src = Rec.previewUrl;
  document.getElementById('record-result').textContent =
    `${mmss(Rec.dur)} \u00b7 ${formatBytes(blob.size)}${Rec.autoStopped ? ' \u00b7 stopped at the size limit' : ''}`;
  const fit = canFitMedia(Math.ceil(blob.size * 4 / 3) + 40);
  const off = mediaOffloadOn();
  const zone = off ? (fit.ok ? 'ok' : 'over') : noteSizeZone(fit.projected);
  const box = document.getElementById('record-review-note');
  box.dataset.zone = zone;
  box.innerHTML = `${ZONE_ICON[zone]}<span>${fit.ok ? (off ? `This clip will be stored in Backblaze, so it doesn\u2019t count toward the note\u2019s 25 MB.` : `Adding this makes the note ${mb1(fit.projected)} / 25 MB.`) : fit.message + ' Discard it, or record something shorter.'}</span>`;
  document.getElementById('btn-record-add').disabled = !fit.ok;
  showRecError('');
  setRecState('review');
}

async function addRecordingToNote() {
  if (!Rec.blob) return;
  const btn = document.getElementById('btn-record-add');
  setBusy(btn, true, 'Adding\u2026');
  try {
    const data = await readFileAsDataURL(Rec.blob);
    const fit = canFitMedia(data.length + 4);
    if (!fit.ok) { showRecError(fit.message); return; }
    addAudioClip({ data, dur: Rec.dur, name: '' });
    hide('overlay-record');
  } catch (e) {
    showRecError('Couldn\u2019t add the recording.');
  } finally {
    setBusy(btn, false);
  }
}

function requestCloseRecorder() {
  if (Rec.state === 'idle') { hide('overlay-record'); return; }
  openConfirm('Discard this recording?',
    Rec.state === 'recording' ? 'The audio recorded so far will be thrown away.' : 'This recording hasn\u2019t been added to the note yet.',
    () => hide('overlay-record'), 'Discard');
}

/* ---------------------------------------------------------------------
 * Wiring for everything above.
 * ------------------------------------------------------------------- */

function setupMedia() {
  document.querySelectorAll('[data-zone-icon]').forEach((el) => { el.innerHTML = ZONE_ICON[el.dataset.zoneIcon]; });
  const body = document.getElementById('editor-body');
  body.addEventListener('mousedown', (e) => { if (e.target.closest('.audio-chip button')) e.preventDefault(); }); // keep the caret where it was
  body.addEventListener('click', (e) => {
    const chip = e.target.closest('.audio-chip');
    if (!chip || !chip.dataset.id) return;
    e.preventDefault();
    if (e.target.closest('.audio-more')) openClipDialog(chip.dataset.id);
    else if (e.target.closest('.audio-play, .audio-time')) toggleClipPlayback(chip.dataset.id);
  });

  document.getElementById('btn-size').addEventListener('click', () => { renderSizeDialog(); show('overlay-size'); });
  document.getElementById('btn-add-audio').addEventListener('click', openRecorder);
  document.getElementById('btn-record-start').addEventListener('click', startRecording);
  document.getElementById('btn-record-stop').addEventListener('click', stopRecording);
  document.getElementById('btn-record-cancel').addEventListener('click', requestCloseRecorder);
  document.getElementById('btn-record-close').addEventListener('click', requestCloseRecorder);
  document.getElementById('btn-record-again').addEventListener('click', () => { recorderTeardown(); openRecorder(); });
  document.getElementById('btn-record-discard').addEventListener('click', requestCloseRecorder);
  document.getElementById('btn-record-add').addEventListener('click', addRecordingToNote);
  document.getElementById('btn-record-attach').addEventListener('click', () => document.getElementById('input-audio').click());
  document.getElementById('input-audio').addEventListener('change', async (e) => {
    const files = Array.from(e.target.files || []);
    e.target.value = '';
    if (!files.length) return;
    const added = await attachAudioFiles(files);
    if (added && !document.getElementById('overlay-record').classList.contains('hidden')) hide('overlay-record');
  });

  document.getElementById('btn-clip-download').addEventListener('click', () => { if (clipDialogId) downloadClip(clipDialogId); });
  document.getElementById('btn-clip-delete').addEventListener('click', () => {
    const id = clipDialogId;
    if (!id) return;
    openConfirm('Delete this clip?', 'It will be removed from the note.', () => deleteClip(id), 'Delete clip');
  });

  document.getElementById('storage-pill').addEventListener('click', openSettings);
  const photoSel = document.getElementById('settings-photo-quality');
  const audioSel = document.getElementById('settings-audio-quality');
  photoSel.addEventListener('change', () => { Config.setPhotoQuality(photoSel.value); document.getElementById('settings-photo-hint').textContent = PHOTO_QUALITY[photoSel.value].hint; });
  audioSel.addEventListener('change', () => { Config.setAudioQuality(audioSel.value); document.getElementById('settings-audio-hint').textContent = AUDIO_QUALITY[audioSel.value].hint; });
  document.getElementById('settings-media-on').addEventListener('change', (e) => {
    if (window.KSMedia) KSMedia.setUserEnabled(e.target.checked);
    fillMediaSettings();
    if (!document.getElementById('overlay-editor').classList.contains('hidden')) updateSizeMeter();
  });
  document.getElementById('settings-storage-limit').addEventListener('change', (e) => {
    const n = Number(e.target.value);
    if (n >= 50) Config.setStorageLimitMB(n);
    e.target.value = Config.storageLimitMB();
    renderStorageSection();
    updateStoragePill();
  });

  // Coming back to the app after a while: refresh the list so a note edited
  // on another device is noticed (opening notes now trusts this device's copy
  // whenever it matches the list).
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && Config.configured() && Date.now() - lastServerSyncAt > 60000) refreshNotes();
  });
}

function setupRichText() {
  const body = document.getElementById('editor-body');
  try {
    document.execCommand('defaultParagraphSeparator', false, 'div'); // <div> lines nest cleanly with lists/headings; <p> doesn't
    document.execCommand('styleWithCSS', false, false); // <b>/<i>/<u> tags, not inline styles
  } catch (e) { /* older engines — formatting still works, tags may differ and get sanitized */ }

  body.addEventListener('input', () => {
    // Browsers leave a lone <br>/empty block behind after deleting
    // everything, which would hide the placeholder — reset it.
    const h = body.innerHTML.trim();
    if (h === '<br>' || h === '<p><br></p>' || h === '<div><br></div>') body.innerHTML = '';
    onEditorContentChanged();
  });

  // Paste as plain text so formatting from other apps can't sneak in.
  body.addEventListener('paste', (e) => {
    e.preventDefault();
    const text = (e.clipboardData || window.clipboardData).getData('text/plain');
    if (text) document.execCommand('insertText', false, text);
  });
  body.addEventListener('drop', (e) => e.preventDefault());

  document.addEventListener('selectionchange', () => {
    const sel = window.getSelection();
    if (selectionInBody() && sel.rangeCount) savedBodyRange = sel.getRangeAt(0).cloneRange();
    updateFormatState();
  });

  document.querySelectorAll('[data-fmt]').forEach((btn) => {
    // Keep focus + selection in the note while a formatting button is tapped.
    btn.addEventListener('mousedown', (e) => e.preventDefault());
    btn.addEventListener('click', () => runFormat(btn.dataset.fmt));
  });
}

/* ---------------------------------------------------------------------
 * Ink — draw directly over a note
 *
 * Two canvases sit on top of the note's title/body/photos (see
 * .editor-sheet in index.html): one for finished strokes, one for the
 * stroke being drawn right now. Strokes are stored as vectors, not a
 * bitmap, so they stay sharp, can be erased/undone, and stay small.
 * Every coordinate and width is a fraction of the sheet's *width*, so a
 * drawing scales with the note on a different screen. (The text still
 * reflows, so ink sits over the same words on the same width, and drifts
 * a little if the width changes a lot — the usual limit of ink over
 * reflowing text.)
 *
 * Saved in content.drawing = { v: 1, strokes: [{ t, c, w, p }] }
 *   t: 'p' pen | 'h' highlighter     c: '#rrggbb'
 *   w: line width     p: [x0, y0, x1, y1, …]
 * ------------------------------------------------------------------- */

const INK_PEN_PX = { s: 1.5, m: 3, l: 6 };   // at a ~360px-wide note
const INK_HIGHLIGHT_FACTOR = 5;
const INK_HIGHLIGHT_ALPHA = 0.35;
const INK_ERASER_PX = 12;
const INK_MAX_UNDO = 100;
const INK_MAX_CANVAS_PIXELS = 16e6;

const Ink = {
  strokes: [], undoStack: [], redoStack: [],
  mode: false, tool: 'pen', color: '#23241F', size: 'm',
  W: 0, H: 0, dpr: 1,
  canvas: null, live: null, ctx: null, lctx: null, sheet: null,
  current: null,        // stroke being drawn
  gestureBefore: null,  // eraser: strokes as they were when the gesture began
  erased: false,
  raf: 0,
};

const inkBBoxCache = new WeakMap();
const inkR4 = (v) => Math.round(v * 10000) / 10000;

function inkEstimateBytes() {
  let n = 0;
  for (const s of Ink.strokes) n += s.p.length * 7 + 40;
  return n;
}

// A copy of the array (stroke objects are never mutated once committed),
// so an in-flight save can't be changed by drawing that happens meanwhile.
function inkGetData() {
  return Ink.strokes.length ? { v: 1, strokes: Ink.strokes.slice() } : null;
}

function inkLoad(data) {
  const ok = (s) => s && (s.t === 'p' || s.t === 'h') && /^#[0-9a-f]{6}$/i.test(s.c)
    && typeof s.w === 'number' && s.w > 0 && s.w < 1
    && Array.isArray(s.p) && s.p.length >= 2 && s.p.length % 2 === 0 && s.p.every(Number.isFinite);
  Ink.strokes = data && Array.isArray(data.strokes) ? data.strokes.filter(ok) : [];
  Ink.undoStack = [];
  Ink.redoStack = [];
  Ink.current = null;
  inkRender();
  inkUpdateButtons();
}

function inkResize() {
  const { sheet, canvas, live } = Ink;
  if (!sheet) return;
  const W = sheet.clientWidth, H = sheet.clientHeight;
  if (!W || !H) return;
  let dpr = Math.min(window.devicePixelRatio || 1, 3);
  if (W * H * dpr * dpr > INK_MAX_CANVAS_PIXELS) dpr = Math.sqrt(INK_MAX_CANVAS_PIXELS / (W * H));
  if (W === Ink.W && H === Ink.H && dpr === Ink.dpr) return;
  Ink.W = W; Ink.H = H; Ink.dpr = dpr;
  for (const c of [canvas, live]) {
    c.width = Math.round(W * dpr);
    c.height = Math.round(H * dpr);
  }
  inkRender();
}

function inkPaint(ctx, s) {
  const W = Ink.W, p = s.p, n = p.length / 2;
  ctx.save();
  ctx.lineCap = 'round';
  ctx.lineJoin = 'round';
  ctx.strokeStyle = s.c;
  ctx.fillStyle = s.c;
  ctx.lineWidth = s.w * W;
  ctx.globalAlpha = s.t === 'h' ? INK_HIGHLIGHT_ALPHA : 1;
  ctx.beginPath();
  if (n === 1) {
    ctx.arc(p[0] * W, p[1] * W, ctx.lineWidth / 2, 0, Math.PI * 2);
    ctx.fill();
  } else {
    ctx.moveTo(p[0] * W, p[1] * W);
    // Quadratic curves through the midpoints smooth out pointer jitter.
    for (let i = 1; i < n - 1; i++) {
      ctx.quadraticCurveTo(
        p[2 * i] * W, p[2 * i + 1] * W,
        (p[2 * i] + p[2 * i + 2]) / 2 * W, (p[2 * i + 1] + p[2 * i + 3]) / 2 * W
      );
    }
    ctx.lineTo(p[2 * (n - 1)] * W, p[2 * (n - 1) + 1] * W);
    ctx.stroke();
  }
  ctx.restore();
}

function inkRender() {
  if (!Ink.ctx || !Ink.W) return;
  const { ctx, canvas, dpr } = Ink;
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  for (const s of Ink.strokes) inkPaint(ctx, s);
}

function inkDrawLive() {
  Ink.raf = 0;
  if (!Ink.lctx || !Ink.W) return;
  const { lctx, live, dpr } = Ink;
  lctx.setTransform(1, 0, 0, 1, 0, 0);
  lctx.clearRect(0, 0, live.width, live.height);
  if (!Ink.current) return;
  lctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  inkPaint(lctx, Ink.current);
}

function inkChanged() {
  inkUpdateButtons();
  onEditorContentChanged();
}

function inkPushUndo(before) {
  Ink.undoStack.push(before);
  if (Ink.undoStack.length > INK_MAX_UNDO) Ink.undoStack.shift();
  Ink.redoStack = [];
}

function inkCommit(stroke) {
  inkPushUndo(Ink.strokes.slice());
  Ink.strokes.push(stroke);
  const { ctx, dpr } = Ink;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  inkPaint(ctx, stroke);
  inkChanged();
}

function inkUndo() {
  if (!Ink.undoStack.length) return;
  Ink.redoStack.push(Ink.strokes);
  Ink.strokes = Ink.undoStack.pop();
  inkRender();
  inkChanged();
}

function inkRedo() {
  if (!Ink.redoStack.length) return;
  Ink.undoStack.push(Ink.strokes);
  Ink.strokes = Ink.redoStack.pop();
  inkRender();
  inkChanged();
}

function inkClear() {
  if (!Ink.strokes.length) return;
  inkPushUndo(Ink.strokes.slice());
  Ink.strokes = [];
  inkRender();
  inkChanged();
  toast('Drawing cleared — tap Undo to bring it back');
}

/* Eraser: removes whole strokes the pointer touches. */

function inkBBox(s) {
  let bb = inkBBoxCache.get(s);
  if (!bb) {
    bb = [Infinity, Infinity, -Infinity, -Infinity];
    for (let i = 0; i < s.p.length; i += 2) {
      bb[0] = Math.min(bb[0], s.p[i]);     bb[2] = Math.max(bb[2], s.p[i]);
      bb[1] = Math.min(bb[1], s.p[i + 1]); bb[3] = Math.max(bb[3], s.p[i + 1]);
    }
    inkBBoxCache.set(s, bb);
  }
  return bb;
}

function inkSegDist(px, py, x1, y1, x2, y2) {
  const dx = x2 - x1, dy = y2 - y1;
  const len2 = dx * dx + dy * dy;
  let t = len2 ? ((px - x1) * dx + (py - y1) * dy) / len2 : 0;
  t = Math.max(0, Math.min(1, t));
  return Math.hypot(px - (x1 + t * dx), py - (y1 + t * dy));
}

function inkStrokeHit(s, pt, r) {
  const pad = r + s.w / 2;
  const bb = inkBBox(s);
  if (pt[0] < bb[0] - pad || pt[0] > bb[2] + pad || pt[1] < bb[1] - pad || pt[1] > bb[3] + pad) return false;
  const p = s.p, n = p.length / 2;
  if (n === 1) return Math.hypot(p[0] - pt[0], p[1] - pt[1]) <= pad;
  for (let i = 0; i < n - 1; i++) {
    if (inkSegDist(pt[0], pt[1], p[2 * i], p[2 * i + 1], p[2 * i + 2], p[2 * i + 3]) <= pad) return true;
  }
  return false;
}

function inkEraseAt(pt) {
  const r = INK_ERASER_PX / Ink.W;
  const keep = Ink.strokes.filter((s) => !inkStrokeHit(s, pt, r));
  if (keep.length !== Ink.strokes.length) {
    Ink.strokes = keep;
    Ink.erased = true;
    inkRender();
  }
}

/* Pointer input */

function inkPoint(e) {
  const r = Ink.live.getBoundingClientRect();
  return [inkR4((e.clientX - r.left) / Ink.W), inkR4((e.clientY - r.top) / Ink.W)];
}

function inkEvents(e) {
  const list = e.getCoalescedEvents ? e.getCoalescedEvents() : [];
  return list.length ? list : [e];
}

function inkPointerDown(e) {
  if (!Ink.mode || Ink.tool === 'scroll' || !e.isPrimary) return;
  if (e.pointerType === 'mouse' && e.button !== 0) return;
  e.preventDefault();
  Ink.live.setPointerCapture(e.pointerId);
  const pt = inkPoint(e);
  if (Ink.tool === 'eraser') {
    Ink.gestureBefore = Ink.strokes.slice();
    Ink.erased = false;
    inkEraseAt(pt);
    return;
  }
  const highlight = Ink.tool === 'highlighter';
  const px = INK_PEN_PX[Ink.size] * (highlight ? INK_HIGHLIGHT_FACTOR : 1);
  Ink.current = { t: highlight ? 'h' : 'p', c: Ink.color, w: inkR4(px / Ink.W), p: pt };
  if (!Ink.raf) Ink.raf = requestAnimationFrame(inkDrawLive);
}

function inkPointerMove(e) {
  if (!e.isPrimary) return;
  if (Ink.tool === 'eraser') {
    if (Ink.gestureBefore) for (const ev of inkEvents(e)) inkEraseAt(inkPoint(ev));
    return;
  }
  const cur = Ink.current;
  if (!cur) return;
  for (const ev of inkEvents(e)) {
    const pt = inkPoint(ev);
    const n = cur.p.length;
    // Skip points closer than ~1px to the last one — keeps saved data small.
    if (Math.hypot(pt[0] - cur.p[n - 2], pt[1] - cur.p[n - 1]) * Ink.W < 1) continue;
    cur.p.push(pt[0], pt[1]);
  }
  if (!Ink.raf) Ink.raf = requestAnimationFrame(inkDrawLive);
}

function inkPointerEnd(e) {
  if (!e.isPrimary) return;
  if (Ink.gestureBefore) {
    if (Ink.erased) { inkPushUndo(Ink.gestureBefore); inkChanged(); }
    Ink.gestureBefore = null;
    Ink.erased = false;
  }
  if (Ink.current) {
    const stroke = Ink.current;
    Ink.current = null;
    inkCommit(stroke);
    if (!Ink.raf) Ink.raf = requestAnimationFrame(inkDrawLive); // clears the live layer
  }
}

/* Toolbar + mode */

function inkUpdateButtons() {
  const undo = document.querySelector('[data-ink-action="undo"]');
  const redo = document.querySelector('[data-ink-action="redo"]');
  const clear = document.querySelector('[data-ink-action="clear"]');
  if (undo) undo.disabled = !Ink.undoStack.length;
  if (redo) redo.disabled = !Ink.redoStack.length;
  if (clear) clear.disabled = !Ink.strokes.length;
}

function inkSyncPressed() {
  document.querySelectorAll('[data-ink-tool]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.inkTool === Ink.tool)));
  document.querySelectorAll('[data-ink-color]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.inkColor === Ink.color)));
  document.querySelectorAll('[data-ink-size]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.inkSize === Ink.size)));
  Ink.live.classList.toggle('can-draw', Ink.tool !== 'scroll');
}

function setDrawMode(on) {
  if (!Ink.sheet) return;
  Ink.mode = on;
  Ink.sheet.classList.toggle('is-drawing', on);
  document.getElementById('draw-bar').hidden = !on;
  document.getElementById('format-bar').hidden = on;
  document.getElementById('btn-draw').setAttribute('aria-pressed', String(on));
  if (on && document.activeElement && document.activeElement.blur) document.activeElement.blur(); // drops the keyboard
  if (!on) { Ink.current = null; Ink.gestureBefore = null; }
  inkSyncPressed();
  inkUpdateButtons();
  requestAnimationFrame(inkResize);
}

function setupInk() {
  Ink.sheet = document.getElementById('editor-sheet');
  Ink.canvas = document.getElementById('ink-canvas');
  Ink.live = document.getElementById('ink-live');
  Ink.ctx = Ink.canvas.getContext('2d');
  Ink.lctx = Ink.live.getContext('2d');

  if (window.ResizeObserver) new ResizeObserver(inkResize).observe(Ink.sheet);
  window.addEventListener('resize', inkResize);

  Ink.live.addEventListener('pointerdown', inkPointerDown);
  Ink.live.addEventListener('pointermove', inkPointerMove);
  Ink.live.addEventListener('pointerup', inkPointerEnd);
  Ink.live.addEventListener('pointercancel', inkPointerEnd);

  document.getElementById('btn-draw').addEventListener('click', () => setDrawMode(!Ink.mode));

  document.querySelectorAll('[data-ink-tool]').forEach((b) => b.addEventListener('click', () => {
    Ink.tool = b.dataset.inkTool;
    // Highlighting in black is rarely what anyone wants — nudge to yellow
    // the first time the highlighter is picked while black is selected.
    if (Ink.tool === 'highlighter' && Ink.color === '#23241F') Ink.color = '#E5B417';
    inkSyncPressed();
  }));
  document.querySelectorAll('[data-ink-color]').forEach((b) => b.addEventListener('click', () => {
    Ink.color = b.dataset.inkColor;
    if (Ink.tool === 'eraser' || Ink.tool === 'scroll') Ink.tool = 'pen';
    inkSyncPressed();
  }));
  document.querySelectorAll('[data-ink-size]').forEach((b) => b.addEventListener('click', () => {
    Ink.size = b.dataset.inkSize;
    inkSyncPressed();
  }));
  document.querySelectorAll('[data-ink-action]').forEach((b) => b.addEventListener('click', () => {
    const a = b.dataset.inkAction;
    if (a === 'undo') inkUndo();
    else if (a === 'redo') inkRedo();
    else if (a === 'clear') inkClear();
  }));

  inkSyncPressed();
  inkUpdateButtons();
}

/* ---------------------------------------------------------------------
 * Draft recovery banner — surfaces a local draft that never made it to
 * the server (an abrupt close mid-typing, before the ~1s local cache even
 * had a version the last successful save doesn't already cover).
 * ------------------------------------------------------------------- */

async function checkForRecoverableDrafts() {
  const ids = await listLocalDraftIds();
  if (!ids.length) return;
  const id = ids[0]; // surface one at a time; picking another note re-checks
  const draft = await loadLocalDraft(id);
  if (!draft) return;

  const banner = document.getElementById('draft-banner');
  const label = draft.title ? `"${draft.title}"` : 'a note';
  document.getElementById('draft-banner-text').textContent =
    `You have unsaved changes to ${label} from an earlier session.`;
  banner.classList.remove('hidden');

  document.getElementById('draft-banner-resume').onclick = () => {
    banner.classList.add('hidden');
    const meta = notesCache.find((m) => m.id === id) || null;
    if (meta && meta.lockType !== 'none') {
      // A locked note's password isn't known here, so opening the draft directly
      // left a note that could never be saved. Unlock it the normal way; once it
      // opens, the usual "Restore unsaved draft?" prompt offers these changes.
      currentUnlockCreds = null;
      openUnlockFlow(meta);
      return;
    }
    openEditorWithContent(meta, { title: draft.title, body: draft.body, html: draft.html, images: draft.images || [], drawing: draft.drawing, audio: draft.audio });
    // If the note this draft belonged to no longer exists server-side,
    // openEditorWithContent treats it as a new note under a new id — so
    // this old entry is now orphaned and needs clearing explicitly, or
    // it would keep getting offered again on every future launch. (If the
    // note *does* still exist, openEditorWithContent reuses this exact id
    // and clears it the normal way once the restore is confirmed.)
    if (!meta) clearLocalDraft(id);
  };
  document.getElementById('draft-banner-dismiss').onclick = async () => {
    banner.classList.add('hidden');
    await clearLocalDraft(id);
  };
}

/* ---------------------------------------------------------------------
 * Init
 * ------------------------------------------------------------------- */

function init() {
  wireStaticEvents();
  setupKeyboardViewportFix();
  setupLightbox();
  setupRichText();
  setupMedia();
  setupInk();
  document.getElementById('version-badge').textContent = 'v' + (window.KEEPSAKE_VERSION || '1.6.0');

  // Connectivity: react the moment the browser notices, and keep retrying
  // on a timer since navigator.onLine can't see a connection that's up but
  // not actually reaching the Worker.
  window.addEventListener('online', () => { setOnline(true); flushOutbox(); });
  window.addEventListener('offline', () => setOnline(false));
  setInterval(() => { if (navigator.onLine && outboxCount > 0) flushOutbox(); }, 30000);
  updateSyncStatusUI();

  if (!Config.configured()) {
    openSettings();
    toast('Add your Worker URL and access token to get started');
  } else {
    refreshNotes().then(checkForRecoverableDrafts);
  }

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(() => { /* offline shell is a nice-to-have */ });
  }
}

document.addEventListener('DOMContentLoaded', init);
