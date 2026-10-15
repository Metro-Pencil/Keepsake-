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

// Every photo and audio you add is first offered as Original or Compressed (see askMediaQuality).
// These presets only decide how strong "Compressed" is (Settings -> Compressed quality). A locked
// note stores everything about a third larger again (encryption is kept as text).
const PHOTO_QUALITY = {
  standard: { label: 'Standard', maxDim: 1600, quality: 0.82, hint: 'Resized to 1600px. Roughly 0.3\u20130.7 MB per photo.' },
  high:     { label: 'High',     maxDim: 2560, quality: 0.92, hint: 'Resized to 2560px, light compression. Roughly 1\u20132.5 MB per photo.' },
};
const VIDEO_QUALITY = {
  standard: { label: 'Standard', maxDim: 720,  videoBps: 1200000, audioBps: 96000,  fps: 30, ratio: 0.36, hint: 'Resized to 720p (1.2 Mbps). Roughly 9 MB per minute.' },
  high:     { label: 'High',     maxDim: 1080, videoBps: 2500000, audioBps: 128000, fps: 30, ratio: 0.56, hint: 'Resized to 1080p (2.5 Mbps). Roughly 19 MB per minute.' },
};
const AUDIO_QUALITY = {
  standard: { label: 'Standard', bps: 64000,  hint: 'Clear for voice. About 0.5 MB per minute.' },
  high:     { label: 'High',     bps: 128000, hint: 'Good for voice and music. About 1 MB per minute.' },
  max:      { label: 'Original', bps: 256000, hint: 'Recorded with no mic processing at the highest quality the browser offers. About 2 MB per minute.' },
};

const appMemLS = new Map();
function appLsGet(k) { try { return window.localStorage.getItem(k) || appMemLS.get(k) || null; } catch (e) { return appMemLS.get(k) || null; } }
function appLsSet(k, v) { appMemLS.set(k, String(v)); try { window.localStorage.setItem(k, v); } catch (e) { /* private/sandboxed mode */ } }

const Config = {
  configured() { return !!(window.KSB2 && KSB2.config.configured()); },
  photoQuality() { const v = appLsGet('ks_photoQuality'); return v === 'standard' || v === 'high' ? v : 'high'; },
  setPhotoQuality(v) { appLsSet('ks_photoQuality', v); },
  videoQuality() { const v = appLsGet('ks_videoQuality'); return v === 'standard' || v === 'high' ? v : 'standard'; },
  setVideoQuality(v) { appLsSet('ks_videoQuality', v); },
  audioQuality() { const v = appLsGet('ks_audioQuality'); return v === 'standard' || v === 'high' ? v : 'high'; },
  setAudioQuality(v) { appLsSet('ks_audioQuality', v); },
  // Backblaze B2's free plan includes 10 GB. Change it in Settings if your plan is different.
  storageLimitMB() { const n = Number(appLsGet('ks_storageLimitMB')); return n >= 50 ? n : 10000; },
  setStorageLimitMB(n) { appLsSet('ks_storageLimitMB', String(Math.round(n))); },
};

// The app's whole view of storage. Everything lives in your Backblaze B2 bucket (see b2.js);
// photos and audio are separate files there (see media.js).
const API = {
  listNotes() { return KSB2.listNotes(); },
  getNote(id) { return KSB2.getNote(id); },
  // Always a save to a client-generated id. There's no separate "create" call: a note's first
  // save and every save after it go through the same idempotent path, so retrying a save that
  // looked like it failed can never create a duplicate note \u2014 it just overwrites the same one.
  // Photos and audio go up first; the note itself \u2014 by then just text and references \u2014 follows.
  // Both the editor's saves and the offline queue come through here, so a queued note uploads
  // its media too.
  // Photos and audio are sent one file at a time, each checked against the bucket before the next
  // starts. `report` (optional) hears about every step: onPlan, onFileStart, onFileProgress,
  // onFileDone, onText.
  async saveNote(id, payload, report) {
    const r = report || {};
    if (payload && payload.mediaKeep && payload.mediaKeep.length && window.KSMedia) {
      await KSMedia.uploadPending(id, payload.mediaKeep, {
        sizes: payload.mediaSizes,
        onPlan: r.onPlan, onFileStart: r.onFileStart, onFileProgress: r.onFileProgress, onPacketStatus: r.onPacketStatus, onFileDone: r.onFileDone,
      });
    }
    if (r.onText) r.onText('active', 0);
    const out = await KSB2.saveNote(id, payload, r.onText ? (f) => r.onText('active', f) : null);
    if (r.onText) r.onText('done', 1);
    return out;
  },
  deleteNote(id) { return KSB2.deleteNote(id); },
  getVault(id) { return KSB2.getVault(id); },
  exportNote(id) { return KSB2.exportNote(id); },
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

// Stores a photo the way the person chose in the Original / Compressed prompt. "Original" keeps
// the file's own bytes (after checking this browser can actually display it); "compressed"
// uses the strength set in Settings.
async function fileToStoredDataURL(file, mode) {
  if (mode === 'original') {
    await loadImageFromFile(file);
    let url = await readFileAsDataURL(file);
    // Some files arrive with no type at all; a note only reopens photos whose data: URL says image/...
    if (!/^data:image\//.test(url)) {
      const ext = ((/\.([a-z0-9]+)$/i.exec(file.name) || [])[1] || '').toLowerCase();
      const guess = { png: 'image/png', gif: 'image/gif', webp: 'image/webp', avif: 'image/avif', heic: 'image/heic', heif: 'image/heif', bmp: 'image/bmp' }[ext] || 'image/jpeg';
      url = url.replace(/^data:[^;,]*/, 'data:' + guess);
    }
    return url;
  }
  const q = PHOTO_QUALITY[Config.photoQuality()];
  return fileToCompressedDataURL(file, q.maxDim, q.quality);
}

/* ---------------------------------------------------------------------
 * Size limits. A note is its written part (text, formatting, drawing) plus its photos and audio,
 * which are separate files in the bucket (media.js). The figure shown at the top of the editor is
 * the WHOLE note \u2014 all of that added up \u2014 against the one limit that really applies to it.
 *   150 MB  the most one note may carry in total (photos and audio are held in memory while a
 *           note is open, so there has to be a ceiling).
 *    90 MB  the most one photo or clip may be.
 *    25 MB  the most the written part alone may take (it is saved as one file and re-sent whole).
 *    50 MB  from here a note is slower to open for the first time on a new device or on mobile data.
 *   100 MB  from here you are close to the limit.
 * ------------------------------------------------------------------- */
const MB = 1024 * 1024;
const NOTE_TOTAL_LIMIT = 150 * MB;
const NOTE_HEAVY_BYTES = 50 * MB;
const NOTE_DANGER_BYTES = 100 * MB;
const NOTE_TEXT_LIMIT = 25 * MB;
const MEDIA_ITEM_MAX_BYTES = 90 * MB;
const NOTE_LIMIT_LABEL = '150 MB';
function limitWord() { return 'the ' + NOTE_LIMIT_LABEL + ' limit'; }
const STORAGE_WARN_RATIO = 0.7;
const STORAGE_DANGER_RATIO = 0.9;

// `total` is everything in the note; `content` is just its written part as it will be stored.
function noteSizeZone(total, content) {
  if (total > NOTE_TOTAL_LIMIT || (content || 0) > NOTE_TEXT_LIMIT) return 'over';
  if (total >= NOTE_DANGER_BYTES) return 'danger';
  if (total >= NOTE_HEAVY_BYTES) return 'heavy';
  return 'ok';
}

// What the note open in the editor will take up once saved — from string
// lengths, so it is cheap enough to run as you type. A locked note is bigger
// than its contents: the encrypted bytes are stored as base64 text.
function noteSizeBreakdown() {
  const body = document.getElementById('editor-body');
  const text = utf8Len(document.getElementById('editor-title').value) + utf8Len(body.innerHTML) * 2; // html + its plain-text copy
  // Photos, videos and audio: their real size (what the bucket stores). Only a short reference to each stays in the note itself.
  let photos = 0;
  const photoIds = photoIdsInBody();
  for (const id of photoIds) photos += estimateImageBytes(editorPhotos[id]);
  let audio = 0;
  let clips = 0;
  const seen = new Set();
  body.querySelectorAll('ks-audio').forEach((el) => {
    const id = el.getAttribute('data-id');
    if (seen.has(id) || !editorAudio[id]) return;
    seen.add(id);
    audio += estimateImageBytes(editorAudio[id].data);
    clips++;
  });
  let videos = 0;
  let videoCount = 0;
  const seenVid = new Set();
  body.querySelectorAll('ks-video').forEach((el) => {
    const id = el.getAttribute('data-id');
    if (seenVid.has(id) || !editorVideos[id]) return;
    seenVid.add(id);
    videos += estimateImageBytes(editorVideos[id].data);
    videoCount++;
  });
  const drawing = inkEstimateBytes();
  const refs = photoIds.length * 200 + clips * 260 + videoCount * 420;
  let content = 160 + text + refs + drawing; // the written part, as the note file will hold it
  const locked = lockIsActive();
  let lockExtra = 0;
  if (locked) {
    const encrypted = Math.ceil((content + 16) * 4 / 3) + 80; // encrypted data is stored as text, about a third bigger
    lockExtra = encrypted - content;
    content = encrypted;
  }
  const media = photos + audio + videos;
  return { text, photos, photoCount: photoIds.length, audio, clips, videos, videoCount, drawing, lockExtra, locked, content, media, total: content + media };
}

// Cheap fingerprint of a big base64 string (length + 48 sampled characters),
// so "did the photos/audio change?" doesn't mean comparing megabytes of text.
function mediaSig(str) {
  str = String(str || '');
  let sig = str.length + ':';
  const step = Math.max(1, Math.floor(str.length / 48));
  for (let i = 0; i < str.length; i += step) sig += str[i];
  return sig + str.slice(-16);
}

// Identity of a snapshot's photos + videos + audio — what decides "Saving media…".
function mediaKey(snapshot) {
  const audio = snapshot.audio || {};
  const videos = snapshot.videos || {};
  return JSON.stringify([
    (snapshot.images || []).map(mediaSig),
    Object.keys(audio).sort().map((id) => id + mediaSig(audio[id].data)),
    Object.keys(videos).sort().map((id) => id + mediaSig(videos[id].data)),
  ]);
}

// Same as JSON.stringify(snapshot) for "has anything changed?" purposes, but
// with the big media fingerprinted instead of copied.
function snapshotKey(snapshot) {
  const audio = {};
  for (const id of Object.keys(snapshot.audio || {}).sort()) {
    audio[id] = mediaSig(snapshot.audio[id].data) + '|' + snapshot.audio[id].dur + '|' + snapshot.audio[id].name;
  }
  const videos = {};
  for (const id of Object.keys(snapshot.videos || {}).sort()) {
    const v = snapshot.videos[id];
    videos[id] = mediaSig(v.data) + '|' + (v.dur || 0) + '|' + (v.name || '') + '|' + (v.mode || '');
  }
  return JSON.stringify({ ...snapshot, images: (snapshot.images || []).map(mediaSig), audio, videos });
}

// Precise-enough byte size of one compressed photo, straight from its
// base64 data URL — used both for the per-photo size shown under each
// thumbnail/in the lightbox, and (summed) for the 25MB ceiling check above.
function estimateImageBytes(dataUrl) { // works for any base64 data: URL, audio included
  dataUrl = String(dataUrl || '');
  const len = dataUrl.length - (dataUrl.indexOf(',') + 1);
  const padding = dataUrl.endsWith('==') ? 2 : dataUrl.endsWith('=') ? 1 : 0;
  return Math.max(0, Math.round((len * 3) / 4) - padding);
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return Math.round(bytes / 1024) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

/* ---------------------------------------------------------------------
 * Size accounting — how many bytes a note takes up in the bucket. Measured
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

// The size of a content object as it is stored.
function contentStoredBytes(c) {
  if (!c) return 0;
  if (typeof c.ciphertext === 'string') {
    return c.ciphertext.length + String(c.salt || '').length + String(c.iv || '').length + 80;
  }
  let n = 160;
  n += utf8Len(c.title) + utf8Len(c.body) + utf8Len(c.html);
  for (const src of c.images || []) n += typeof src === 'string' ? src.length + 4 : 0;
  if (c.audio) for (const k in c.audio) n += (c.audio[k] && typeof c.audio[k].data === 'string' ? c.audio[k].data.length : 0) + 120;
  if (c.videos) for (const k in c.videos) n += (c.videos[k] && typeof c.videos[k].data === 'string' ? c.videos[k].data.length : 0) + 260;
  if (c.drawing && Array.isArray(c.drawing.strokes)) for (const s of c.drawing.strokes) n += (s.p ? s.p.length : 0) * 7 + 40;
  return n;
}

// Sum of externalized media bytes recorded in a content object's manifest (or inline data URLs if unexternalized).
function contentMediaBytes(c) {
  if (!c || typeof c !== 'object') return 0;
  let n = 0;
  if (c.media && typeof c.media === 'object') {
    for (const k of Object.keys(c.media)) {
      const e = c.media[k];
      if (e && typeof e.n === 'number' && e.n > 0) n += e.n;
    }
    if (n > 0) return n;
  }
  for (const src of c.images || []) {
    if (typeof src === 'string' && src.startsWith('data:')) n += estimateImageBytes(src);
  }
  if (c.audio && typeof c.audio === 'object') {
    for (const k of Object.keys(c.audio)) {
      const a = c.audio[k];
      if (a && typeof a.data === 'string' && a.data.startsWith('data:')) n += estimateImageBytes(a.data);
    }
  }
  if (c.videos && typeof c.videos === 'object') {
    for (const k of Object.keys(c.videos)) {
      const v = c.videos[k];
      if (v && typeof v.data === 'string' && v.data.startsWith('data:')) n += estimateImageBytes(v.data);
    }
  }
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

function createMemKeepsakeDB() {
  const stores = {
    [DRAFT_STORE]: new Map(),
    [NOTE_CACHE_STORE]: new Map(),
    [NOTE_CONTENT_STORE]: new Map(),
    [OUTBOX_STORE]: new Map(),
    [OUTBOX_PAYLOAD_STORE]: new Map(),
  };
  return {
    objectStoreNames: { contains: (n) => !!stores[n] },
    transaction(names, mode) {
      const tx = {
        oncomplete: null, onerror: null, onabort: null, error: null,
        abort() { if (this.onabort) this.onabort(); },
        objectStore(name) {
          const map = stores[name];
          const wrap = (fn) => {
            const r = { result: undefined, error: null, onsuccess: null, onerror: null };
            Promise.resolve().then(() => {
              try { r.result = fn(); if (r.onsuccess) r.onsuccess({ target: r }); }
              catch (e) { r.error = e; if (r.onerror) r.onerror(e); }
            });
            return r;
          };
          return {
            get: (k) => wrap(() => map.get(k)),
            getAll: () => wrap(() => Array.from(map.values())),
            getAllKeys: () => wrap(() => Array.from(map.keys())),
            put: (v) => wrap(() => { map.set(v.id, v); return v.id; }),
            delete: (k) => wrap(() => { map.delete(k); }),
          };
        },
      };
      Promise.resolve().then(() => Promise.resolve()).then(() => { if (tx.oncomplete) tx.oncomplete(); });
      return tx;
    },
  };
}

function openKeepsakeDB() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve) => {
    try {
      if (!window.indexedDB) { resolve(createMemKeepsakeDB()); return; }
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
      req.onerror = () => resolve(createMemKeepsakeDB());
    } catch (e) {
      resolve(createMemKeepsakeDB());
    }
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

// A draft is written about once a second while you type. Photos and audio can add up to 150 MB, and
// IndexedDB can only replace a record whole - so they live in a second record of their own
// ("<id>#media") that is rewritten only when the photos/audio themselves change. Typing then rewrites
// a few kilobytes, not the whole note's media.
const DRAFT_MEDIA_SUFFIX = '#media';
const draftMediaSigs = new Map(); // note id -> signature of the media last written

async function saveLocalDraft(id, title, body, images, imageIds, html, drawing, audio, videos) {
  if (!id) return;
  try {
    const db = await openKeepsakeDB();
    const sig = mediaKey({ images, audio, videos });
    const entries = [[DRAFT_STORE, { id, title, body, html, drawing, imageIds, mediaSig: sig, savedAt: Date.now() }]];
    if (draftMediaSigs.get(id) !== sig) entries.push([DRAFT_STORE, { id: id + DRAFT_MEDIA_SUFFIX, images, audio, videos }]);
    await idbPutMany(db, entries); // one transaction: the two records never disagree
    draftMediaSigs.set(id, sig);
  } catch (e) {
    // Best-effort only — local caching should never interrupt the editor.
  }
}

async function loadLocalDraft(id) {
  try {
    const db = await openKeepsakeDB();
    const rec = await idbGet(db, DRAFT_STORE, id);
    if (!rec) return null;
    if (rec.mediaSig !== undefined) { // newer layout: photos, videos and audio are in the companion record
      const media = await idbGet(db, DRAFT_STORE, id + DRAFT_MEDIA_SUFFIX);
      return {
        ...rec,
        images: media ? media.images || [] : [],
        audio: media ? media.audio : undefined,
        videos: media ? media.videos : undefined,
      };
    }
    return rec; // older drafts kept everything in one record
  } catch (e) { return null; }
}

async function clearLocalDraft(id) {
  if (!id) return;
  draftMediaSigs.delete(id);
  try {
    const db = await openKeepsakeDB();
    await idbDeleteMany(db, [[DRAFT_STORE, id], [DRAFT_STORE, id + DRAFT_MEDIA_SUFFIX]]);
  } catch (e) {
    // Worst case an orphaned draft lingers and gets offered for recovery
    // again later, which is harmless.
  }
}

async function listLocalDraftIds() {
  try {
    const db = await openKeepsakeDB();
    return (await idbGetAllKeys(db, DRAFT_STORE)).filter((k) => !String(k).endsWith(DRAFT_MEDIA_SUFFIX));
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
    const detectedMedia = contentMediaBytes(content);
    const mediaBytes = typeof meta.mediaSize === 'number' && meta.mediaSize > 0
      ? meta.mediaSize
      : (detectedMedia > 0 ? detectedMedia : (existing && typeof existing.mediaBytes === 'number' ? existing.mediaBytes : 0));
    const updatedMeta = mediaBytes > 0 && !(typeof meta.mediaSize === 'number' && meta.mediaSize > 0)
      ? { ...meta, mediaSize: mediaBytes }
      : meta;
    const light = {
      id: meta.id,
      meta: updatedMeta,
      contentUpdatedAt: meta.updatedAt, // which version of the note the cached content is
      hasContent: true,
      bytes: contentStoredBytes(content),
      mediaBytes,
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

// Notes locked long ago were stored with title:null. Once any listed note shows a
// string there, it's worth re-saving old locked notes (when they're next opened)
// to give them a title.
function learnServerTitleSupport(metas) {
  if (metas.some((m) => m && m.lockType !== 'none' && typeof m.title === 'string')) {
    try { appLsSet('ks_titlesOnServer', '1'); } catch (e) { /* private mode — harmless */ }
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
  const metas = await Promise.all(cached.map(async (c) => {
    let mediaBytes = typeof c.meta.mediaSize === 'number' && c.meta.mediaSize > 0
      ? c.meta.mediaSize
      : (typeof c.mediaBytes === 'number' && c.mediaBytes > 0 ? c.mediaBytes : 0);
    if (!mediaBytes && window.KSMedia && typeof KSMedia.noteBytes === 'function') {
      try { mediaBytes = await KSMedia.noteBytes(c.id); } catch (e) { /* ignore */ }
    }
    return {
      ...c.meta,
      mediaSize: mediaBytes || c.meta.mediaSize,
      _pending: pending.has(c.id),
      _lockedTitle: c.lockedTitle || '',
      _bytes: typeof c.meta.size === 'number' ? c.meta.size : (typeof c.bytes === 'number' ? c.bytes : null),
      _media: mediaBytes, // photos + videos + audio held in Backblaze / local media store
    };
  }));
  metas.sort((x, y) => (y.updatedAt || 0) - (x.updatedAt || 0));
  return metas;
}

/* ---------------------------------------------------------------------
 * Outbox — notes with a save or delete the server hasn't seen yet.
 * ------------------------------------------------------------------- */

// `info` (saves only) = { title, batch } where batch is { fileName: 'photo' | 'audio' } for the
// photos/audio that were still waiting to upload. It is carried over from an earlier queued save of
// the same note, so "43 of 100 photos" stays true across edits and across closing the app.
// Resolves with the queuedAt stamp of the entry it wrote (0 if it could not be written).
async function queueOutbox(id, op, payload, info) {
  const queuedAt = Date.now();
  try {
    const db = await openKeepsakeDB();
    let batch = {};
    if (op === 'save' && info && info.batch) {
      const prev = await idbGet(db, OUTBOX_STORE, id);
      const keep = new Set((payload && payload.mediaKeep) || []);
      if (prev && prev.batch) for (const name of Object.keys(prev.batch)) if (keep.has(name)) batch[name] = prev.batch[name];
      Object.assign(batch, info.batch);
    }
    await idbRun(db, [OUTBOX_STORE, OUTBOX_PAYLOAD_STORE], 'readwrite', (tx) => {
      const rec = { id, op, queuedAt };
      if (op === 'save' && info) { rec.title = String(info.title || '').slice(0, 120); rec.batch = batch; }
      tx.objectStore(OUTBOX_STORE).put(rec);
      const payloads = tx.objectStore(OUTBOX_PAYLOAD_STORE);
      if (op === 'save' && payload) payloads.put({ id, payload }); else payloads.delete(id);
    });
  } catch (e) { await refreshOutboxCount(); return 0; }
  await refreshOutboxCount();
  return queuedAt;
}

async function clearOutbox(id) {
  try {
    const db = await openKeepsakeDB();
    await idbDeleteMany(db, [[OUTBOX_STORE, id], [OUTBOX_PAYLOAD_STORE, id]]);
  } catch (e) { /* best-effort */ }
  await refreshOutboxCount();
}

// Clears the entry only if it is still the one this save wrote. A newer edit that replaced it
// in the meantime stays queued.
async function clearOutboxIfCurrent(id, queuedAt) {
  const cur = await getOutboxItem(id);
  if (cur && queuedAt && cur.queuedAt !== queuedAt) return false;
  await clearOutbox(id);
  return true;
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

// Time-locked notes are judged by Backblaze's clock (kept in step by b2.js); everything else
// in the app uses the phone's clock. Falls back to the phone's if the server was never reached.
function lockNow() { return window.KSB2 ? KSB2.clock.now() : Date.now(); }

function fmtCountdown(unlockAt) {
  let diff = unlockAt - lockNow();
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
  if (!el) return;
  el.classList.add('hidden');
  if (id === 'overlay-record') recorderTeardown();
  if (id === 'overlay-clip') pauseClipPreview();
  if (id === 'overlay-video') stopTheaterVideo();
  if (id === 'overlay-editor') { clearAudioUrls(); clearVideoUrls(); clearThumbUrls(); }
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
  root.querySelectorAll('input[type="password"]:not([data-pw-enhanced]):not([data-secret])').forEach((input) => {
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

// Fields marked data-secret (the application key, the old access token) are for typing a secret in,
// never for getting it back out: no copy, no cut, no drag, no context menu. (They are also never filled
// with the saved value - see openSettings.)
function setupSecretFields() {
  const isSecret = (t) => !!(t && t.closest && t.closest('[data-secret]'));
  const block = (e) => {
    if (!isSecret(e.target) && !isSecret(document.activeElement)) return;
    e.preventDefault();
    if (e.clipboardData) e.clipboardData.setData('text/plain', '');
  };
  ['copy', 'cut', 'dragstart', 'contextmenu'].forEach((ev) => document.addEventListener(ev, block, true));
  document.addEventListener('keydown', (e) => { // Ctrl/Cmd+C, Ctrl/Cmd+X, Ctrl+Insert on a secret field
    if (!isSecret(e.target)) return;
    const k = e.key.toLowerCase();
    if (((e.ctrlKey || e.metaKey) && (k === 'c' || k === 'x')) || (e.ctrlKey && k === 'insert')) e.preventDefault();
  }, true);
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

// `steps` (optional) = one row per kind of thing being sent - photos, audio, note text - each with
// its own bar; see renderSyncSteps. Left out, the rows are hidden.
function syncBarSet(label, fraction /* number 0..1, or null for indeterminate */, steps) {
  clearTimeout(syncBarHideTimer);
  const bar = document.getElementById('sync-bar');
  bar.classList.remove('error', 'done');
  bar.classList.add('show');
  renderSyncSteps(steps);
  document.getElementById('sync-bar-label').textContent = label;
  document.getElementById('sync-bar-retry').classList.add('hidden');
  const track = document.getElementById('sync-bar-track');
  const fill = document.getElementById('sync-bar-fill');
  if (fraction == null) {
    track.classList.add('indeterminate');
  } else {
    track.classList.remove('indeterminate');
    const clamped = Math.max(0, Math.min(1, fraction));
    fill.style.setProperty('--sync-frac', clamped.toFixed(4));
    fill.style.width = (clamped * 100) + '%';
  }
}

function syncBarHideSoon(delay = 1100) {
  clearTimeout(syncBarHideTimer);
  syncBarHideTimer = setTimeout(() => {
    document.getElementById('sync-bar').classList.remove('show');
  }, delay);
}

function syncBarSuccess(label = 'Saved', steps) {
  syncBarSet(label, 1, steps);
  document.getElementById('sync-bar').classList.add('done'); // finished: stop the spinner
  syncBarHideSoon(steps ? 2200 : 1100);
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

// One row per kind of thing being sent, each with its own bar and count:
//   Photos     [=====>    ]  3 / 60
//   Audio      [          ]  pending
//   Note text  [          ]  pending
function renderSyncSteps(steps) {
  const wrap = document.getElementById('sync-steps');
  if (!wrap) return;
  const bar = document.getElementById('sync-bar');
  if (bar) bar.classList.toggle('has-steps', !!(steps && steps.length)); // the rows carry the bars then
  if (!steps || !steps.length) { wrap.hidden = true; return; }
  wrap.hidden = false;
  const keep = new Set();
  steps.forEach((st, i) => {
    keep.add(st.key);
    let row = wrap.querySelector(`.sync-step[data-key="${st.key}"]`);
    if (!row) {
      row = document.createElement('div');
      row.className = 'sync-step';
      row.dataset.key = st.key;
      row.innerHTML = '<span class="sync-step-name"></span>'
        + '<span class="sync-step-track" role="progressbar" aria-valuemin="0" aria-valuemax="100"><span class="sync-step-fill"></span></span>'
        + '<span class="sync-step-count"></span>';
      wrap.appendChild(row);
    }
    if (wrap.children[i] !== row) wrap.insertBefore(row, wrap.children[i] || null);
    const f = Math.max(0, Math.min(1, st.frac || 0));
    row.dataset.state = st.state;
    row.style.setProperty('--f', f.toFixed(3));
    row.querySelector('.sync-step-name').textContent = st.label;
    row.querySelector('.sync-step-count').textContent = st.count;
    const track = row.querySelector('.sync-step-track');
    track.setAttribute('aria-valuenow', String(Math.round(f * 100)));
    track.setAttribute('aria-label', `${st.label}: ${st.aria || st.count}`);
  });
  wrap.querySelectorAll('.sync-step').forEach((r) => { if (!keep.has(r.dataset.key)) r.remove(); });
}

/* ---------------------------------------------------------------------
 * Upload progress model. Every note being sent is a "job": which photos and clips it still has to
 * send (each tagged photo / audio), which are done, the file in flight right now, and the state of
 * the note's text. The bar adds the jobs up, so a queue of several notes reads as one piece of work
 * instead of starting over for each.
 *
 * What counts as "this batch" lives in the outbox entry (see queueOutbox), not in memory - so after
 * the app is closed and reopened, "43 / 100 photos" is still 43 / 100.
 * ------------------------------------------------------------------- */

const SyncJobs = new Map(); // note id -> job
let syncRenderTimer = 0;
let syncSummaryShown = false; // the bar is showing the reopen summary, not a live upload

function newSyncJob(noteId, title) {
  return { noteId, title: title || '', files: {}, current: null, text: 'wait', textFraction: 0, prep: null };
}

// Fills a job's file list from what this device knows about them.
async function fillJobFiles(job, batch) {
  const names = Object.keys(batch || {});
  if (!names.length || !window.KSMedia) return job;
  try {
    const d = await KSMedia.describe(job.noteId, names, batch);
    for (const name of names) {
      const f = d[name];
      job.files[name] = {
        kind: f ? f.kind : batch[name],
        size: f ? f.size : 0,
        done: !(f && f.pending),
        packets: f && f.packets ? f.packets : null,
      };
    }
  } catch (e) { /* these numbers are only for display */ }
  return job;
}

async function syncJobBegin(noteId, title, batch, owner) {
  const job = newSyncJob(noteId, title);
  job.owner = owner || 'editor';
  SyncJobs.set(noteId, job);
  syncSummaryShown = false;
  await fillJobFiles(job, batch);
  scheduleSyncRender();
  return job;
}

function scheduleSyncRender() {
  if (syncRenderTimer) return;
  syncRenderTimer = setTimeout(() => { syncRenderTimer = 0; renderSyncJobs(); }, 80);
}

// What a job is told as its upload goes (passed to API.saveNote).
function jobReporter(noteId) {
  const job = () => SyncJobs.get(noteId);
  return {
    onPlan({ todo }) {
      const j = job(); if (!j) return;
      const sending = new Set(todo.map((t) => t.name));
      for (const name of Object.keys(j.files)) if (!sending.has(name)) j.files[name].done = true; // already in the bucket
      for (const t of todo) j.files[t.name] = { kind: t.kind, size: t.size, done: false, packets: t.packets || null };
      scheduleSyncRender();
    },
    onFileStart(f) {
      const j = job(); if (!j) return;
      j.current = {
        name: f.name, kind: f.kind, size: f.size, fraction: 0,
        index: f.index, count: f.count, packetIndex: 0, packetCount: f.packetCount || 1,
        tag: '', reupload: false,
      };
      j.prep = null;
      scheduleSyncRender();
    },
    onFileProgress(p) {
      const j = job(); if (!j || !j.current) return;
      j.current.fraction = p.total ? Math.min(1, p.loaded / p.total) : 0;
      if (typeof p.packetIndex === 'number') j.current.packetIndex = p.packetIndex;
      if (typeof p.packetCount === 'number') j.current.packetCount = p.packetCount;
      if (p.tag) j.current.tag = p.tag;
      if (p.reupload !== undefined) j.current.reupload = !!p.reupload;
      scheduleSyncRender();
    },
    onPacketStatus(ps) {
      const j = job();
      if (j && j.files[ps.name] && Array.isArray(j.files[ps.name].packets)) {
        const pkt = j.files[ps.name].packets[ps.packetIndex];
        if (pkt) {
          pkt.synced = ps.state === 'synced';
          pkt.uploading = ps.state === 'uploading' || ps.state === 'reuploading';
          pkt.lost = ps.state === 'reuploading';
        }
      }
      refreshVideoPacketUI(noteId, ps.name, ps);
      scheduleSyncRender();
    },
    onFileDone(f) {
      const j = job(); if (!j) return;
      const e = j.files[f.name];
      if (e) {
        e.done = true;
        if (Array.isArray(e.packets)) e.packets.forEach((p) => { p.synced = true; p.uploading = false; p.lost = false; });
      } else {
        j.files[f.name] = { kind: f.kind, size: f.size, done: true };
      }
      j.current = null;
      refreshVideoPacketUI(noteId, f.name, { state: 'synced' });
      scheduleSyncRender();
    },
    onText(state, frac) {
      const j = job(); if (!j) return;
      j.text = state; j.textFraction = frac;
      scheduleSyncRender();
    },
  };
}

// Adds jobs up into what the bar shows.
function summarizeJobs(jobs) {
  const sum = {
    photo: { total: 0, done: 0, bytes: 0, bytesDone: 0 },
    video: { total: 0, done: 0, bytes: 0, bytesDone: 0, packetsTotal: 0, packetsDone: 0 },
    audio: { total: 0, done: 0, bytes: 0, bytesDone: 0 },
    notes: 0, textDone: 0, textFrac: 0, current: null, preparing: null, titles: [],
  };
  const bucketFor = (kind) => (kind === 'video' ? sum.video : kind === 'audio' ? sum.audio : sum.photo);
  for (const j of jobs) {
    sum.notes++;
    sum.titles.push(j.title);
    for (const f of Object.values(j.files)) {
      const k = bucketFor(f.kind);
      k.total++; k.bytes += f.size || 0;
      if (f.done) { k.done++; k.bytesDone += f.size || 0; }
      if (f.kind === 'video') {
        const pCount = Array.isArray(f.packets) && f.packets.length ? f.packets.length : 1;
        const pDone = f.done ? pCount : (Array.isArray(f.packets) ? f.packets.filter((p) => p.synced).length : 0);
        sum.video.packetsTotal += pCount;
        sum.video.packetsDone += pDone;
      }
    }
    if (j.current) {
      const k = bucketFor(j.current.kind);
      k.bytesDone += (j.current.size || 0) * j.current.fraction;
      sum.current = j.current;
    }
    if (j.prep) sum.preparing = j.prep;
    if (j.text === 'done') { sum.textDone++; sum.textFrac += 1; } else if (j.text === 'active') sum.textFrac += j.textFraction || 0;
  }
  return sum;
}

function stepFromKind(key, label, k, active, current) {
  const frac = k.bytes > 0 ? k.bytesDone / k.bytes : (k.total ? k.done / k.total : 0);
  const finished = k.total > 0 && k.done >= k.total;
  const state = finished ? 'done' : (active || k.done > 0 || k.bytesDone > 0) ? 'active' : 'wait';
  let count = state === 'done' ? 'done' : state === 'wait' ? 'pending' : `${k.done} / ${k.total}`;
  if (key === 'video' && state === 'active' && k.packetsTotal > 1) {
    const activePkt = current && current.kind === 'video' && typeof current.packetIndex === 'number'
      ? Math.min(k.packetsTotal, k.packetsDone + 1)
      : k.packetsDone;
    count = `pkt ${activePkt}/${k.packetsTotal}`;
  }
  const noun = key === 'video'
    ? (k.total === 1 ? 'video' : 'videos')
    : key === 'audio'
      ? (k.total === 1 ? 'clip' : 'clips')
      : (k.total === 1 ? 'photo' : 'photos');
  return { key, label, frac: finished ? 1 : frac, state, count, aria: state === 'wait' ? `${k.total} ${noun} pending` : `${k.done} of ${k.total} ${noun} uploaded` };
}

function stepsFromSummary(sum) {
  if (sum.photo.total + sum.video.total + sum.audio.total === 0) return null; // a plain text save needs just the one line
  const steps = [];
  if (sum.photo.total) steps.push(stepFromKind('photo', 'Photos', sum.photo, !!(sum.current && sum.current.kind === 'photo'), sum.current));
  if (sum.video.total) steps.push(stepFromKind('video', 'Videos', sum.video, !!(sum.current && sum.current.kind === 'video'), sum.current));
  if (sum.audio.total) steps.push(stepFromKind('audio', 'Audio', sum.audio, !!(sum.current && sum.current.kind === 'audio'), sum.current));
  const textFrac = sum.notes ? sum.textFrac / sum.notes : 0;
  const textDone = sum.notes > 0 && sum.textDone >= sum.notes;
  const textActive = !textDone && textFrac > 0;
  steps.push({
    key: 'text',
    label: sum.notes > 1 ? 'Notes' : 'Note text',
    frac: textDone ? 1 : textFrac,
    state: textDone ? 'done' : textActive ? 'active' : 'wait',
    count: textDone ? 'done' : textActive ? (sum.notes > 1 ? `${sum.textDone} / ${sum.notes}` : `${Math.round(textFrac * 100)}%`) : 'pending',
    aria: textDone ? 'saved' : 'waiting until media files and video packets are up',
  });
  return steps;
}

function overallFraction(sum) {
  const count = sum.photo.total + sum.video.total + sum.audio.total;
  const textFrac = sum.notes ? sum.textFrac / sum.notes : 0;
  if (!count) return textFrac > 0 ? textFrac : null; // null = indeterminate
  const media = sum.photo.bytes + sum.video.bytes + sum.audio.bytes;
  const mediaDone = sum.photo.bytesDone + sum.video.bytesDone + sum.audio.bytesDone;
  const mediaFrac = media > 0 ? mediaDone / media : (sum.photo.done + sum.video.done + sum.audio.done) / count;
  return Math.min(1, mediaFrac * 0.97 + textFrac * 0.03);
}

function jobHeadline(sum) {
  const only = sum.notes === 1 && sum.titles[0] ? `\u201c${sum.titles[0].slice(0, 28)}\u201d` : '';
  const hasMedia = sum.photo.total + sum.video.total + sum.audio.total > 0;
  if (sum.current) {
    const c = sum.current;
    const pct = Math.round((overallFraction(sum) || 0) * 100);
    if (c.kind === 'video') {
      const pIdx = (c.packetIndex || 0) + 1;
      const pTot = c.packetCount || 1;
      const tagPart = c.tag ? ` [${c.tag}]` : '';
      if (c.reupload) {
        return `Re-uploading lost video packet ${pIdx} of ${pTot}${tagPart} \u00b7 ${pct}%`;
      }
      return `Uploading video ${Math.min(sum.video.total, sum.video.done + 1)} of ${sum.video.total} \u00b7 packet ${pIdx}/${pTot}${tagPart} \u00b7 ${pct}%`;
    }
    const k = c.kind === 'audio' ? sum.audio : sum.photo;
    const noun = c.kind === 'audio' ? 'audio clip' : 'photo';
    return `Uploading ${noun} ${Math.min(k.total, k.done + 1)} of ${k.total} \u00b7 ${pct}%`;
  }
  if (sum.preparing) return `Getting ${sum.preparing.what} ready \u00b7 ${sum.preparing.done} of ${sum.preparing.total}`;
  if (hasMedia && sum.textFrac > 0) return 'Saving the note itself\u2026';
  if (hasMedia) return sum.notes > 1 ? `Uploading ${sum.notes} notes\u2026` : `Uploading${only ? ' ' + only : ''}\u2026`;
  return only ? `Saving ${only}\u2026` : 'Saving\u2026';
}

function renderSyncJobs() {
  if (!SyncJobs.size) return;
  const sum = summarizeJobs(SyncJobs.values());
  syncBarSet(jobHeadline(sum), overallFraction(sum), stepsFromSummary(sum));
}

// A job is over. If it was the last one, close the bar out.
function syncJobEnd(noteId, outcome /* 'ok' | 'offline' | 'error' */, message, retry) {
  const job = SyncJobs.get(noteId);
  SyncJobs.delete(noteId);
  clearTimeout(syncRenderTimer); syncRenderTimer = 0;
  if (SyncJobs.size) { renderSyncJobs(); return; }
  if (outcome === 'ok') {
    if (job) {
      for (const f of Object.values(job.files)) f.done = true;
      job.text = 'done'; job.textFraction = 1; job.current = null;
      syncBarSuccess(Object.keys(job.files).length ? 'Everything uploaded' : 'Saved', stepsFromSummary(summarizeJobs([job])));
    } else syncBarSuccess('Saved');
  } else if (outcome === 'error') {
    syncBarError(message || 'Couldn\u2019t save \u2014 tap to retry', retry || (() => flushOutbox()));
  } else {
    syncBarHideSoon(300); // offline: the note is safe on this device; the header pill says what is waiting
  }
}

// After the app is reopened with data still waiting to go up: say so right away, with the counts,
// instead of sitting silent until the connection to Backblaze has been made.
async function showUnsyncedSummary() {
  if (SyncJobs.size || isFlushing) return;
  const items = (await getOutbox()).filter((i) => i.op === 'save');
  const jobs = [];
  for (const it of items) {
    if (it.batch && Object.keys(it.batch).length) jobs.push(await fillJobFiles(newSyncJob(it.id, it.title), it.batch));
  }
  const sum = summarizeJobs(jobs);
  const remaining = (sum.photo.total - sum.photo.done) + (sum.video.total - sum.video.done) + (sum.audio.total - sum.audio.done);
  if (!jobs.length || remaining <= 0) return;
  if (SyncJobs.size || isFlushing) return; // a live upload started while this was being read
  syncSummaryShown = true;
  syncBarSet(navigator.onLine ? 'Picking up where the upload stopped\u2026' : 'Offline \u2014 this is waiting to upload', overallFraction(sum), stepsFromSummary(sum));
  if (!navigator.onLine) syncBarHideSoon(7000);
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

function syncStateOf(noteId) {
  let st = syncStateByNote.get(noteId);
  if (!st) { st = { inFlight: false, queued: null }; syncStateByNote.set(noteId, st); }
  return st;
}

const flushErrorSeen = new Map(); // note id -> last error shown, so a retry timer doesn't re-raise the same one

// Pushes every queued save/delete to the server, oldest first, ONE note at a time and - inside a
// note - one photo or clip at a time. Whatever the bucket already has is skipped, so after the app
// was closed or the connection dropped this carries on from the next unsent file. Stops at the first
// connection failure (the rest stay queued for next time); a real server error on one note leaves just
// that note queued and carries on.
async function flushOutbox() {
  if (isFlushing || !navigator.onLine) return;
  const items = (await getOutbox()).sort((a, b) => a.queuedAt - b.queuedAt);
  if (!items.length) {
    if (syncSummaryShown) { syncSummaryShown = false; syncBarHideSoon(300); }
    return;
  }
  isFlushing = true;
  const mine = []; // jobs this flush opened (an editor's own job for the same note is never touched)
  try {
    // Register every queued save first, so the bar shows the whole queue as one piece of work.
    for (const item of items) {
      if (item.op !== 'save' || syncStateOf(item.id).inFlight || SyncJobs.has(item.id)) continue;
      await syncJobBegin(item.id, item.title, item.batch || {}, 'flush');
      mine.push(item.id);
    }
    for (const item of items) {
      // A live editor/background save is already handling this note - let it. Marking the note
      // in flight also makes the editor queue any new edit instead of racing this upload.
      const st = syncStateOf(item.id);
      if (st.inFlight) { if (mine.includes(item.id)) SyncJobs.delete(item.id); continue; }
      st.inFlight = true;
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
          if (!payload) { await clearOutbox(item.id); SyncJobs.delete(item.id); continue; } // nothing left to send
          result = await API.saveNote(item.id, payload, jobReporter(item.id));
        }
        setOnline(true);
        // If the note was edited again while this request was in flight, a
        // newer entry replaced this one in the outbox — leave that newer
        // one (and its cached copy) alone; the next flush sends it.
        const latest = await getOutboxItem(item.id);
        if (latest && latest.queuedAt !== item.queuedAt) { SyncJobs.delete(item.id); continue; }
        if (item.op === 'delete') {
          await removeCachedNote(item.id);
        } else {
          await cacheNote(result.note, payload.content);
          if (payload.lockType === 'time' && payload.password2) {
            await cacheVault(item.id, payload.password2, result.note.updatedAt);
          }
        }
        await clearOutbox(item.id);
        flushErrorSeen.delete(item.id);
        if (item.op === 'save') syncJobEnd(item.id, 'ok');
      } catch (e) {
        if (e.isNetworkError) { setOnline(false); break; }
        // Real server error for this one item — leave it queued, keep going.
        // (Deletes of missing notes are handled above and never land here.)
        if (item.op === 'save') {
          const fresh = flushErrorSeen.get(item.id) !== e.message;
          flushErrorSeen.set(item.id, e.message);
          if (fresh) { toast(e.message || 'Couldn\u2019t finish saving.'); syncJobEnd(item.id, 'error', 'Couldn\u2019t finish saving \u2014 kept on this device, tap to retry', () => flushOutbox()); }
          else syncJobEnd(item.id, 'offline');
        }
      } finally {
        st.inFlight = false;
        maybeContinueQueued(item.id, st);
      }
    }
  } finally {
    isFlushing = false;
    // Anything this flush opened and did not finish (connection lost) goes quiet; it is still queued.
    let dropped = false;
    for (const id of mine) { const j = SyncJobs.get(id); if (j && j.owner === 'flush') { SyncJobs.delete(id); dropped = true; } }
    if (dropped && !SyncJobs.size) syncBarHideSoon(300);
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
        <div class="card-badges">${pill}${pendingBadge}</div>
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
async function applySavedNote(noteId, note, payload, title, queuedAt) {
  const pending = await getOutboxItem(noteId);
  // Deleted while this save was in flight — leave the queued delete alone
  // (it'll clear the server copy this request just wrote) instead of
  // resurrecting the note in the cache.
  if (pending && pending.op === 'delete') return;
  // The outbox entry is cleared only if it is still the one this save wrote; an edit that has
  // replaced it since stays queued, and its newer cached copy is left alone.
  if (!(await clearOutboxIfCurrent(noteId, queuedAt))) return;
  await cacheNote(note, payload.content, lockedTitleFor(payload, title));
  if (payload.lockType === 'time' && payload.password2) await cacheVault(noteId, payload.password2, note.updatedAt);
  // Forget this device's copies of photos/audio the saved note no longer refers to.
  if (payload.mediaKeep && window.KSMedia) { try { await KSMedia.reconcile(noteId, payload.mediaKeep); } catch (e) { /* best-effort */ } }
  await rerenderFromLocal();
}

// The offline counterpart: no server response exists, so the metadata is
// built here exactly the way b2.js's metaFromBody would build it, the
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

// Local-first: before a single byte goes to the bucket, the note exactly as it is about to be sent
// (text, lock, references to its photos and audio) is cached on this device AND queued in the outbox,
// and the photos/audio themselves already sit in the media store. From that moment closing the app,
// losing the connection or being killed mid-upload cannot lose the change - not even a lock - and the
// upload simply carries on from where it stopped the next time. Resolves with the outbox stamp (0 if
// the note was deleted meanwhile and nothing was written).
async function persistLocalFirst(noteId, payload, title, info) {
  const pending = await getOutboxItem(noteId);
  if (pending && pending.op === 'delete') return 0; // deleted meanwhile - don't resurrect it
  const meta = synthesizeMeta(noteId, payload);
  await cacheNote(meta, payload.content, lockedTitleFor(payload, title));
  if (payload.lockType === 'time' && payload.password2) await cacheVault(noteId, payload.password2, meta.updatedAt);
  const queuedAt = await queueOutbox(noteId, 'save', payload, { title, batch: (info && info.batch) || {} });
  if (payload.mediaKeep && window.KSMedia) { try { await KSMedia.reconcile(noteId, payload.mediaKeep); } catch (e) { /* best-effort */ } }
  // The outbox is now the durable local copy of this exact content, so the
  // abrupt-close draft would just be a duplicate of it.
  clearLocalDraft(noteId);
  return queuedAt;
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
  // A time-locked note exists: make sure the server clock is current (a no-op while Date headers keep it fresh).
  if (window.KSB2 && notes.some((n) => n && n.lockType === 'time')) KSB2.clock.ensureFresh(30 * 60 * 1000).catch(() => {});

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
      const unlocked = meta.lockType === 'time' && meta.unlockAt && lockNow() >= meta.unlockAt;
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

// Photos live in the text, like audio clips: each is a <ks-photo data-id> element (see hydratePhotos),
// and the photo's data: URL is kept here by id. A photo is part of the note only while its element
// is still in the text - the same rule clips follow - and it is removed from the photo viewer, never
// by a stray tap on the grid.
const PHOTO_ID_RE = /^p[a-z0-9]{6,31}$/;
let editorPhotos = {};   // photo id -> data: URL
let lightboxIds = [];    // the photos the viewer is paging through, in text order

function newPhotoId() {
  return 'p' + Array.from(crypto.getRandomValues(new Uint8Array(8)), (x) => x.toString(16).padStart(2, '0')).join('');
}

// Ids of the photos still in the text, in the order they appear (a photo shown twice counts once).
function photoIdsInBody() {
  const seen = new Set();
  const out = [];
  document.querySelectorAll('#editor-body ks-photo').forEach((el) => {
    const id = el.getAttribute('data-id');
    if (editorPhotos[id] && !seen.has(id)) { seen.add(id); out.push(id); }
  });
  return out;
}

function editorImageList() { return photoIdsInBody().map((id) => editorPhotos[id]); }

// A grid cell is at most ~170px wide, so a 360px copy stays sharp on a phone screen. Decoding a
// full-size photo for every cell would be the slow part of a 100-photo note, so the copies are made
// two at a time, and only for cells near the screen.
const thumbUrls = new Map(); // fingerprint -> object URL
const thumbQueue = [];
let thumbActive = 0;
let thumbObserver = null;

function clearThumbUrls() {
  thumbQueue.length = 0;
  if (thumbObserver) { thumbObserver.disconnect(); thumbObserver = null; }
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
    try { bitmap = await createImageBitmap(blob, { resizeWidth: 360, resizeQuality: 'medium' }); }
    catch (e) { bitmap = await createImageBitmap(blob); }
    const scale = Math.min(1, 360 / Math.max(bitmap.width, bitmap.height));
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

function pumpThumbs() {
  while (thumbActive < 2 && thumbQueue.length) {
    const job = thumbQueue.shift();
    if (!job.img.isConnected) continue;
    thumbActive++;
    makeThumbURL(job.src)
      .then((url) => { if (job.img.isConnected) job.img.src = url; })
      .finally(() => { thumbActive--; pumpThumbs(); });
  }
}

function wantThumb(img) {
  const src = editorPhotos[img.dataset.photoId];
  if (!src) return;
  const cached = thumbUrls.get(mediaSig(src));
  if (cached) { img.src = cached; return; }
  thumbQueue.push({ img, src });
  pumpThumbs();
}

function observeThumb(img) {
  if (!('IntersectionObserver' in window)) { wantThumb(img); return; }
  if (!thumbObserver) {
    thumbObserver = new IntersectionObserver((entries) => {
      for (const e of entries) if (e.isIntersecting) { thumbObserver.unobserve(e.target); wantThumb(e.target); }
    }, { root: document.querySelector('.editor-scroll'), rootMargin: '700px 0px' });
  }
  thumbObserver.observe(img);
}

// Gives every <ks-photo> its tile: the picture, its size, and a button that opens the viewer.
function hydratePhotos(root) {
  root.querySelectorAll('ks-photo').forEach((el) => {
    el.setAttribute('contenteditable', 'false');
    el.textContent = '';
    const id = el.getAttribute('data-id');
    const tile = document.createElement('button');
    tile.type = 'button';
    tile.className = 'photo-tile';
    tile.dataset.id = id;
    const src = editorPhotos[id];
    if (!src) {
      tile.classList.add('is-missing');
      tile.disabled = true;
      tile.textContent = 'Photo missing';
      el.appendChild(tile);
      return;
    }
    const img = document.createElement('img');
    img.alt = '';
    img.draggable = false;
    img.dataset.photoId = id;
    const size = document.createElement('span');
    size.className = 'photo-size';
    size.textContent = formatBytes(estimateImageBytes(src));
    tile.append(img, size);
    el.appendChild(tile);
    observeThumb(img);
  });
  labelPhotoTiles();
}

function labelPhotoTiles() {
  const ids = photoIdsInBody();
  document.querySelectorAll('#editor-body .photo-tile[data-id]').forEach((tile) => {
    const n = ids.indexOf(tile.dataset.id) + 1;
    if (n) tile.setAttribute('aria-label', `Open photo ${n} of ${ids.length}`);
  });
}

// Where a batch of new photos goes: in a block of their own right after the line the cursor was in,
// so they sit between lines of text rather than splitting one. Photos from one batch share the block
// and so form one grid.
function beginPhotoBatch() {
  const body = document.getElementById('editor-body');
  let anchor = null;
  if (savedBodyRange && body.contains(savedBodyRange.endContainer)) {
    let n = savedBodyRange.endContainer;
    while (n && n.parentNode !== body) n = n.parentNode;
    if (n && n.parentNode === body) anchor = n;
  }
  return { anchor, wrap: null };
}

function addPhotoToBatch(batch, dataUrl) {
  const body = document.getElementById('editor-body');
  const id = newPhotoId();
  editorPhotos[id] = dataUrl;
  if (!batch.wrap || !batch.wrap.isConnected) {
    const wrap = document.createElement('div');
    if (batch.anchor && batch.anchor.parentNode === body) body.insertBefore(wrap, batch.anchor.nextSibling);
    else body.appendChild(wrap);
    // Somewhere to keep typing underneath the photos.
    if (!wrap.nextSibling) { const line = document.createElement('div'); line.appendChild(document.createElement('br')); body.appendChild(line); }
    batch.wrap = wrap;
  }
  const el = document.createElement('ks-photo');
  el.setAttribute('data-id', id);
  batch.wrap.appendChild(el);
  hydratePhotos(el.parentNode);
  const range = document.createRange();
  range.setStartAfter(batch.wrap);
  range.collapse(true);
  savedBodyRange = range;
  return id;
}

function removePhoto(id) {
  delete editorPhotos[id];
  document.querySelectorAll(`#editor-body ks-photo[data-id="${id}"]`).forEach((el) => {
    const wrap = el.parentNode;
    el.remove();
    if (wrap && wrap.id !== 'editor-body' && wrap.tagName === 'DIV' && !wrap.childNodes.length) wrap.remove();
  });
  labelPhotoTiles();
  updateSizeMeter();
  onEditorContentChanged();
}

// Backspace/Delete right next to a photo must not quietly take it out of the note.
function photoNextToCaret(backward) {
  const sel = window.getSelection();
  if (!sel.rangeCount || !sel.isCollapsed) return false;
  const r = sel.getRangeAt(0);
  const node = r.startContainer;
  let target = null;
  if (node.nodeType === 3) {
    if (backward && r.startOffset === 0) target = node.previousSibling;
    else if (!backward && r.startOffset === node.nodeValue.length) target = node.nextSibling;
  } else {
    target = backward ? node.childNodes[r.startOffset - 1] : node.childNodes[r.startOffset];
  }
  while (target && target.nodeType === 3 && !target.nodeValue) target = backward ? target.previousSibling : target.nextSibling;
  return !!(target && target.nodeType === 1 && target.tagName === 'KS-PHOTO');
}

/* ---------------------------------------------------------------------
 * Lightbox — full-screen photo viewer with left/right paging, opened by
 * tapping any photo in the text. It is also the only place a photo can be
 * removed from a note, so that can't happen by a stray tap on the grid.
 * ------------------------------------------------------------------- */

function openLightbox(id) {
  const ids = photoIdsInBody();
  const i = ids.indexOf(id);
  if (i < 0) return;
  lightboxIndex = i;
  renderLightbox();
  show('overlay-lightbox');
}

function closeLightbox() { hide('overlay-lightbox'); }

function lightboxStep(delta) {
  const total = photoIdsInBody().length;
  if (!total) return;
  lightboxIndex = (lightboxIndex + delta + total) % total;
  renderLightbox();
}

function renderLightbox() {
  lightboxIds = photoIdsInBody();
  const total = lightboxIds.length;
  if (!total) { closeLightbox(); return; }
  if (lightboxIndex >= total) lightboxIndex = total - 1;
  if (lightboxIndex < 0) lightboxIndex = 0;
  const src = editorPhotos[lightboxIds[lightboxIndex]];
  document.getElementById('lightbox-img').src = src;
  document.getElementById('lightbox-caption').textContent =
    total > 1
      ? `${lightboxIndex + 1} of ${total} — ${formatBytes(estimateImageBytes(src))}`
      : formatBytes(estimateImageBytes(src));
  const showNav = total > 1;
  document.getElementById('btn-lightbox-prev').style.visibility = showNav ? 'visible' : 'hidden';
  document.getElementById('btn-lightbox-next').style.visibility = showNav ? 'visible' : 'hidden';
}

function confirmRemovePhoto() {
  const id = lightboxIds[lightboxIndex];
  if (!id) return;
  openConfirm('Remove this photo?', 'It is taken out of the note. This can\u2019t be undone once the note is saved.', () => {
    removePhoto(id);
    renderLightbox();
  }, 'Remove photo');
}

function setupLightbox() {
  document.getElementById('btn-lightbox-close').addEventListener('click', closeLightbox);
  document.getElementById('btn-lightbox-compress').addEventListener('click', compressSavedPhoto);
  document.getElementById('btn-lightbox-remove').addEventListener('click', confirmRemovePhoto);
  document.getElementById('btn-lightbox-prev').addEventListener('click', () => lightboxStep(-1));
  document.getElementById('btn-lightbox-next').addEventListener('click', () => lightboxStep(1));

  // Tapping the dark backdrop (but not the photo itself) closes, same as
  // most native photo viewers.
  document.getElementById('overlay-lightbox').addEventListener('click', (e) => {
    if (e.target.id === 'overlay-lightbox') closeLightbox();
  });

  document.addEventListener('keydown', (e) => {
    if (document.getElementById('overlay-lightbox').classList.contains('hidden')) return;
    if (document.querySelector('.overlay:not(.hidden)')) return; // a dialog (e.g. "Remove this photo?") is on top of the viewer
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
  } else if (pendingLock.unlockAt > lockNow()) {
    text = `Time-locked until ${fmtDateTime(pendingLock.unlockAt)}. Tap the padlock to change it.`;
  } else {
    text = `Time lock ended ${fmtDateTime(pendingLock.unlockAt)} \u2014 this note opens with your password.`;
  }
  el.innerHTML = `<p class="hint">${escapeHTML(text)}</p>`;
}

function noteHasContent() {
  const title = document.getElementById('editor-title').value.trim();
  const body = document.getElementById('editor-body').textContent.trim();
  return !!(title || body || document.getElementById('editor-body').querySelector('ks-photo') || Ink.strokes.length
    || document.getElementById('editor-body').querySelector('ks-audio')
    || document.getElementById('editor-body').querySelector('ks-video'));
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
  clearVideoUrls();
  editorAudio = sanitizeAudioMap(content.audio);
  editorVideos = sanitizeVideoMap(content.videos);
  const bodyEl = document.getElementById('editor-body');
  bodyEl.innerHTML = content.html ? sanitizeHTML(content.html) : textToHTML(content.body);
  hydrateAudioChips(bodyEl);
  hydrateVideos(bodyEl);
  // Only real data: URLs ever reach the <img> markup.
  editorPhotos = {};
  const loose = [];
  (content.images || []).forEach((s, i) => {
    if (typeof s !== 'string' || !/^data:image\//.test(s)) return;
    const given = Array.isArray(content.imageIds) ? content.imageIds[i] : '';
    const id = PHOTO_ID_RE.test(given || '') && !editorPhotos[given] ? given : newPhotoId();
    editorPhotos[id] = s;
    loose.push(id);
  });
  // A photo element whose picture is gone is dropped; a picture with no element yet (notes from before
  // photos could sit in the text kept them in a row under it) goes in one grid at the end.
  bodyEl.querySelectorAll('ks-photo').forEach((el) => { if (!editorPhotos[el.getAttribute('data-id')]) el.remove(); });
  const placed = new Set(Array.from(bodyEl.querySelectorAll('ks-photo')).map((el) => el.getAttribute('data-id')));
  const unplaced = loose.filter((id) => !placed.has(id));
  if (unplaced.length) {
    const wrap = document.createElement('div');
    for (const id of unplaced) { const el = document.createElement('ks-photo'); el.setAttribute('data-id', id); wrap.appendChild(el); }
    bodyEl.appendChild(wrap);
  }
  hydratePhotos(bodyEl);
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
  // A note locked before titles were stored has none. Make closing this note re-save it
  // once so every device gets the title — no edit needed.
  if (isExisting && meta.lockType !== 'none' && meta.title == null
      && appLsGet('ks_titlesOnServer') === '1') {
    lastAutosavedJSON = null;
  }
  seedSyncStateImages(editingNoteId, openedSnapshot);
  show('overlay-editor');
  if (Object.keys(editorVideos).length) scheduleBackgroundPacketCheck(editingNoteId, 400);
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
    videos: Object.keys(c.videos || {}).sort(),
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
    'Restore',
    true
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
  const imageIds = photoIdsInBody();
  return {
    title: document.getElementById('editor-title').value.trim(),
    body: htmlToText(html), // plain-text copy: previews, search, and readers that predate formatting
    html,
    images: imageIds.map((id) => editorPhotos[id]),
    imageIds,
    audio: snapshotAudio(html),
    videos: snapshotVideos(html),
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

function snapshotVideos(html) {
  const out = {};
  for (const m of html.matchAll(/<ks-video data-id="(v[a-z0-9]+)"><\/ks-video>/g)) {
    if (editorVideos[m[1]]) out[m[1]] = editorVideos[m[1]];
  }
  return out;
}

// Same, for the local-draft safety net.
function saveDraftNow(noteId) {
  const html = sanitizeHTML(document.getElementById('editor-body').innerHTML);
  const imageIds = photoIdsInBody();
  saveLocalDraft(noteId, document.getElementById('editor-title').value, htmlToText(html),
    imageIds.map((id) => editorPhotos[id]), imageIds, html, inkGetData(), snapshotAudio(html), snapshotVideos(html));
}

async function buildSavePayload(snapshot, noteId, onPrepare) {
  const { title, body, html, images, drawing, lock } = snapshot;
  const audio = snapshot.audio || {};
  const videos = snapshot.videos || {};
  const content = { title, body, html, images };
  if (snapshot.imageIds && snapshot.imageIds.length) content.imageIds = snapshot.imageIds; // where each photo sits in the text
  if (Object.keys(audio).length) content.audio = audio;
  if (Object.keys(videos).length) content.videos = videos;
  if (drawing) content.drawing = drawing;

  // Photos, videos and audio leave the note here — before any locking, so a locked note's media
  // is encrypted too, and videos are sliced into tagged packets. `stored` is what actually gets saved.
  let stored = content;
  let mediaKeep = null;
  let mediaBytes = 0;
  let mediaKinds = {};
  let mediaSizes = {};
  let batch = {};
  const hasAudioClips = Object.keys(audio).length > 0;
  const hasVideos = Object.keys(videos).length > 0;
  const parts = [];
  if (images.length) parts.push('photos');
  if (hasVideos) parts.push('videos');
  if (hasAudioClips) parts.push('audio');
  const prepWhat = parts.join(' and ') || 'media';
  if (noteId && window.KSMedia && KSMedia.available()) {
    try {
      const ext = await KSMedia.externalize(noteId, content, !!(lock && lock.type !== 'none'),
        onPrepare ? (done, total) => onPrepare(done, total, prepWhat) : null);
      stored = ext.content;
      mediaKeep = ext.keep;
      mediaBytes = ext.bytes;
      mediaKinds = ext.kinds;
      mediaSizes = ext.sizes;
      // Propagate generated packet manifests back to editorVideos so open UI reflects exact cloud packet IDs
      if (stored.videos && editingNoteId === noteId) {
        for (const vidId of Object.keys(stored.videos)) {
          const sv = stored.videos[vidId];
          if (editorVideos[vidId] && sv && sv.packets) {
            editorVideos[vidId].mediaName = sv.mediaName;
            editorVideos[vidId].packets = sv.packets;
          }
        }
      }
      batch = await KSMedia.pendingKinds(noteId, ext.keep, ext.kinds); // what still has to be sent
    } catch (e) {
      if (e && e.tooBig) throw e;
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
  if (mediaKeep) { payload.mediaKeep = mediaKeep; payload.mediaBytes = mediaBytes; payload.mediaKinds = mediaKinds; payload.mediaSizes = mediaSizes; }

  return { payload, batch, hasImages: images.length > 0 || hasAudioClips || hasVideos };
}

/* ---------------------------------------------------------------------
 * Background save — used by both the Save button and autosave. Always a
 * save to a note id generated client-side (see b2.js's saveNote), so
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

function estimateSnapshotSizes(snapshot) {
  let mediaBytes = 0;
  for (const s of snapshot.images || []) mediaBytes += estimateImageBytes(s);
  for (const k of Object.keys(snapshot.audio || {})) {
    if (snapshot.audio[k]) mediaBytes += estimateImageBytes(snapshot.audio[k].data);
  }
  for (const k of Object.keys(snapshot.videos || {})) {
    if (snapshot.videos[k]) mediaBytes += estimateImageBytes(snapshot.videos[k].data);
  }
  const textBytes = 160 + utf8Len(snapshot.title) + utf8Len(snapshot.body) + utf8Len(snapshot.html)
    + (snapshot.images ? snapshot.images.length * 200 : 0)
    + Object.keys(snapshot.audio || {}).length * 260
    + Object.keys(snapshot.videos || {}).length * 420;
  return { textBytes, mediaBytes };
}

function runSync(noteId, snapshot) {
  // Immediately update notesCache in memory so opening Settings -> Biggest notes right after
  // adding photos/videos reflects the new media bytes even while hashing/uploading is in flight.
  const est = estimateSnapshotSizes(snapshot);
  const existingIdx = notesCache.findIndex((m) => m.id === noteId);
  const lockType = snapshot.lock && snapshot.lock.type ? snapshot.lock.type : 'none';
  if (existingIdx >= 0) {
    notesCache[existingIdx] = {
      ...notesCache[existingIdx],
      title: snapshot.title || notesCache[existingIdx].title || '',
      lockType,
      _bytes: est.textBytes,
      _media: est.mediaBytes,
      mediaSize: est.mediaBytes,
      updatedAt: Date.now(),
    };
  } else {
    notesCache.unshift({
      id: noteId,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      lockType,
      title: snapshot.title || '',
      preview: lockType === 'none' ? makePreview(snapshot.body) : null,
      size: est.textBytes,
      mediaSize: est.mediaBytes,
      _pending: true,
      _lockedTitle: lockType === 'none' ? '' : (snapshot.title || ''),
      _bytes: est.textBytes,
      _media: est.mediaBytes,
    });
  }
  updateStoragePill();
  renderStorageSection();

  let state = syncStateByNote.get(noteId);
  if (!state) { state = { inFlight: false, queued: null }; syncStateByNote.set(noteId, state); }

  if (state.inFlight) {
    state.queued = snapshot; // latest wins — no point sending a stale mid-typing snapshot
    return;
  }
  state.inFlight = true;
  syncRunOne(noteId, snapshot, state);
}

// editingNoteId is left set after the editor is hidden, so "is this note on screen right now?" needs the overlay too.
function editorShowing(noteId) {
  return noteId === editingNoteId && !document.getElementById('overlay-editor').classList.contains('hidden');
}

async function syncRunOne(noteId, snapshot, state) {
  const editing = () => editorShowing(noteId);
  const job = await syncJobBegin(noteId, snapshot.title, {}, 'editor');

  // 1. Turn photos/audio into stored files (encrypting them first for a locked note). Each one is
  //    saved on this device as it is made, so this is also where \"100 photos\" is worked through
  //    one at a time rather than all at once.
  let built;
  try {
    built = await buildSavePayload(snapshot, noteId, (done, total, what) => {
      job.prep = { done, total, what };
      scheduleSyncRender();
    });
  } catch (e) {
    state.inFlight = false;
    const tooBig = !!(e && e.tooBig);
    toast(tooBig ? e.message : 'Could not lock note \u2014 try setting the lock again.');
    syncJobEnd(noteId, 'error', tooBig ? 'Couldn\u2019t save \u2014 a file is too big' : 'Couldn\u2019t save \u2014 check the lock', () => runSync(noteId, snapshot));
    maybeContinueQueued(noteId, state);
    return;
  }
  job.prep = null;
  const { payload, batch } = built;

  // 2. Write it down - note, lock and queue - BEFORE uploading anything.
  let queuedAt = 0;
  try {
    queuedAt = await persistLocalFirst(noteId, payload, snapshot.title, { batch });
  } catch (e) { /* still try to send it below; the worst case is the old behaviour */ }
  if (!queuedAt && (await getOutboxItem(noteId) || {}).op === 'delete') { // deleted while this was being prepared
    SyncJobs.delete(noteId);
    state.inFlight = false;
    maybeContinueQueued(noteId, state);
    return;
  }
  if (editing()) {
    noteExistsOnServer = true;
    setExistingNoteButtons(true);
    document.getElementById('editor-heading').textContent = 'Edit note';
    lastAutosavedJSON = snapshotKey(snapshot); // covered now: autosave need not send the same thing again
  }
  const queued = await getOutboxItem(noteId);
  await fillJobFiles(job, (queued && queued.batch) || batch);
  if (!editing()) await rerenderFromLocal(); // the card shows its lock / \"Not synced\" at once
  scheduleSyncRender();

  // 3. Send it.
  try {
    if (!navigator.onLine) {
      const offlineErr = new Error('Offline');
      offlineErr.isNetworkError = true;
      throw offlineErr;
    }
    const { note } = await API.saveNote(noteId, payload, jobReporter(noteId));
    setOnline(true);
    learnServerTitleSupport([note]);
    flushErrorSeen.delete(noteId);
    state.lastSyncedImagesJSON = mediaKey(snapshot);
    await applySavedNote(noteId, note, payload, snapshot.title, queuedAt);
    syncJobEnd(noteId, 'ok');
    scheduleBackgroundPacketCheck(noteId, 400);
    flushOutbox(); // a working connection is the moment to drain anything else that's queued
  } catch (e) {
    if (e.isNetworkError || e.notConfigured) {
      // Offline, or Backblaze not configured yet, or connection dropped part-way. Everything is
      // already on this device and queued, and the upload picks up from the next unsent file/packet.
      if (e.isNetworkError) setOnline(false);
      syncJobEnd(noteId, 'offline');
      syncBarSuccess('Saved on this device \u2014 will sync later');
    } else {
      toast(e.message || 'Couldn\u2019t finish saving.');
      syncJobEnd(noteId, 'error', 'Couldn\u2019t finish saving \u2014 kept on this device, tap to retry', () => flushOutbox());
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
 * hit the bucket on every keystroke, with a periodic safety net so a long
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
  // longer between autosaves.
  const delay = Math.min(10000, 2000 + Math.floor(lastNoteBytes / MB) * 1000);
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
  const problem = sizeProblem(noteSizeBreakdown());
  const overLimit = !!problem;

  if (overLimit && isExplicitSave) {
    toast(problem + ' Fix that, then save.');
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
    // request that could never succeed.
    // Nothing else holds this version (it can't be sent), so keep a local
    // draft now \u2014 even for a locked note, since the alternative is losing it.
    saveDraftNow(noteId);
    hide('overlay-editor');
    currentUnlockCreds = null;
    toast('Kept on this device only \u2014 ' + problem.charAt(0).toLowerCase() + problem.slice(1) + ' Fix that to sync it.');
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
    status.textContent = lock.unlockAt > lockNow()
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
  if (e && e.status === 403) return 'This note is still sealed \u2014 check this device\u2019s date and time.';
  if (e && e.status === 401) return e.message || 'Backblaze rejected your key \u2014 check Settings.';
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
    const err = new Error('Needs a connection — the second password is fetched once the unlock date has passed.');
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

function openConfirm(title, message, onYes, yesLabel = 'Delete', calm = false) {
  document.getElementById('confirm-title').textContent = title;
  document.getElementById('confirm-message').textContent = message;
  const yesBtn = document.getElementById('btn-confirm-yes');
  const freshYes = yesBtn.cloneNode(true);
  freshYes.textContent = yesLabel;
  // Only things that throw something away get the red button; "Restore" is not one of them.
  freshYes.className = 'btn ' + (calm ? 'btn-primary' : 'btn-danger');
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
  './b2.js',
  './media.js',
  './migrate.js',
  './manifest.json',
  './icon-192.png',
  './icon-512.png',
];

function openSettings() {
  const c = KSB2.config;
  document.getElementById('settings-b2-endpoint').value = c.endpoint();
  document.getElementById('settings-b2-bucket').value = c.bucket();
  document.getElementById('settings-b2-keyid').value = c.keyId();
  // The saved key is never written back into the field: nothing to reveal, select or copy. Leaving
  // the field blank keeps the key that is already saved.
  const keyField = document.getElementById('settings-b2-appkey');
  keyField.value = '';
  keyField.placeholder = c.appKey() ? 'Saved on this device \u2014 type a new key to replace it' : '';
  setB2Status('', '');
  fillClockLine();
  document.getElementById('settings-version').textContent = window.KEEPSAKE_VERSION || '1.10.1';
  fillQualitySettings();
  show('overlay-settings');
  renderStorageSection();
}

// How far this phone's clock is from Backblaze's (used for time-locked notes).
function fillClockLine() {
  const el = document.getElementById('settings-clock');
  if (!el) return;
  if (!KSB2.clock.known()) { el.textContent = 'Time-locked notes use Backblaze\u2019s clock, once it has been reached.'; return; }
  const off = Math.round(KSB2.clock.offset() / 1000);
  el.textContent = Math.abs(off) <= 2
    ? 'This phone\u2019s clock matches Backblaze\u2019s. Time-locked notes use Backblaze\u2019s clock either way.'
    : `This phone\u2019s clock is ${Math.abs(off)} s ${off > 0 ? 'behind' : 'ahead of'} Backblaze\u2019s. Time-locked notes use Backblaze\u2019s clock.`;
}

// The line under the Backblaze fields: what the last "Save and test" found.
function setB2Status(text, kind) {
  const el = document.getElementById('settings-b2-status');
  if (!el) return;
  el.textContent = text;
  el.dataset.kind = kind || '';
  el.hidden = !text;
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

async function saveSettings() {
  const vals = {
    endpoint: document.getElementById('settings-b2-endpoint').value,
    bucket: document.getElementById('settings-b2-bucket').value,
    keyId: document.getElementById('settings-b2-keyid').value,
    appKey: document.getElementById('settings-b2-appkey').value.trim() || KSB2.config.appKey(), // blank = keep the saved key
  };
  if (!vals.endpoint.trim() || !vals.bucket.trim() || !vals.keyId.trim() || !vals.appKey.trim()) {
    setB2Status('All four fields are needed.', 'bad');
    return;
  }
  KSB2.config.set(vals);
  const btn = document.getElementById('btn-save-settings');
  setBusy(btn, true, 'Testing\u2026');
  setB2Status('', '');
  let result;
  try { result = await KSB2.testConnection(); } finally { setBusy(btn, false); }
  if (!result.ok) {
    // Saved, but not closed: the message below says what to fix.
    setB2Status(result.message, 'bad');
    return;
  }
  document.getElementById('settings-b2-appkey').value = '';
  setB2Status('Connected to your bucket.', 'ok');
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
    if (!document.getElementById('overlay-video').classList.contains('hidden')) { hide('overlay-video'); return; }
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

    const mode = await askMediaQuality('photo', files);
    if (!mode) { e.target.value = ''; return; }

    const attachBtn = document.getElementById('btn-attach-image');
    attachBtn.disabled = true;
    let failed = 0;
    let dropped = 0;
    let refused = 0;
    const targetNoteId = editingNoteId; // photos belong to the note they were picked for
    const batch = beginPhotoBatch(); // they go in the text, between lines, as one grid

    const results = [];
    for (let i = 0; i < files.length; i++) {
      const verb = mode === 'original' ? 'Adding' : 'Compressing';
      const what = `${verb} photo ${i + 1} of ${files.length} \u00b7 ${files[i].name} (${formatBytes(files[i].size)})`;
      syncBarSet(`${what} \u00b7 ${Math.round(i / files.length * 100)}%`, i / files.length);
      try {
        const dataUrl = await fileToStoredDataURL(files[i], mode);
        results.push(`${formatBytes(files[i].size)} \u2192 ${formatBytes(estimateImageBytes(dataUrl))}`);
        // Compression is slow; if you've since opened a different note, these
        // must not be attached to it.
        if (editingNoteId !== targetNoteId) { dropped++; continue; }
        if (!canFitMedia(dataUrl.length + 4).ok) { refused++; continue; }
        addPhotoToBatch(batch, dataUrl); // shown as soon as it's ready, not all at once at the end
        updateSizeMeter();
        onEditorContentChanged();
      } catch (err) {
        failed++;
      }
      syncBarSet(`${what} \u00b7 ${Math.round((i + 1) / files.length * 100)}%`, (i + 1) / files.length);
    }

    if (mode === 'compressed' && results.length) syncBarSuccess(results.length === 1 ? `Compressed: ${results[0]}` : `Compressed ${results.length} photos`);
    else syncBarHideSoon(700);
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
    if (unlockAt <= lockNow() && !keepsDate) { err.textContent = 'Pick a time in the future.'; err.classList.remove('visually-hidden'); return; }
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
      if (tag === 'KS-PHOTO') { // a photo in the text: only its id survives
        const photoId = child.getAttribute('data-id') || '';
        if (PHOTO_ID_RE.test(photoId)) out += '<ks-photo data-id="' + photoId + '"></ks-photo>';
        return;
      }
      if (tag === 'KS-VIDEO') { // an inline video card: only its id survives
        const videoId = child.getAttribute('data-id') || '';
        if (VIDEO_ID_RE.test(videoId)) out += '<ks-video data-id="' + videoId + '"></ks-video>';
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
      if (tag === 'KS-PHOTO') return; // photos have no text form
      if (tag === 'KS-AUDIO') { // shows in previews and plain-text readers as a marker
        const clip = editorAudio[child.getAttribute('data-id')];
        if (cur && !/\s$/.test(cur)) cur += ' ';
        cur += '\u{1F399} ' + (clip && clip.dur > 0 ? mmss(clip.dur) : 'audio');
        return;
      }
      if (tag === 'KS-VIDEO') {
        const vid = editorVideos[child.getAttribute('data-id')];
        if (cur && !/\s$/.test(cur)) cur += ' ';
        cur += '\u{1F3AC} ' + (vid && vid.dur > 0 ? mmss(vid.dur) : 'video');
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

function mb1(bytes) { return (bytes / MB).toFixed(1); }

// Why a note can't be saved right now, or '' if it can.
function sizeProblem(b) {
  if (b.content > NOTE_TEXT_LIMIT) return 'The written part of this note (text and drawing) is over 25 MB.';
  if (b.total > NOTE_TOTAL_LIMIT) return 'This note is over the ' + NOTE_LIMIT_LABEL + ' limit \u2014 remove a photo, video, or audio clip.';
  return '';
}

function scheduleSizeMeter() {
  clearTimeout(sizeMeterTimer);
  sizeMeterTimer = setTimeout(updateSizeMeter, 300);
}

function updateSizeMeter() {
  clearTimeout(sizeMeterTimer);
  const btn = document.getElementById('btn-size');
  if (!btn) return;
  const b = noteSizeBreakdown();
  lastNoteBytes = b.content;
  const zone = noteSizeZone(b.total, b.content);
  btn.dataset.zone = zone;
  document.getElementById('size-icon').innerHTML = ZONE_ICON[zone];
  document.getElementById('size-text').textContent = `${formatBytes(b.total)} / ${NOTE_LIMIT_LABEL}`;
  document.getElementById('size-fill').style.transform = `scaleX(${Math.min(1, b.total / NOTE_TOTAL_LIMIT).toFixed(4)})`;
  btn.setAttribute('aria-label', `Note size: ${formatBytes(b.total)} of 150 megabytes. ${ZONE_WORD[zone]}. Open details.`);
  if (!document.getElementById('overlay-size').classList.contains('hidden')) renderSizeDialog(b);
}

// A toast only when a note first crosses into a worse level — not on every keystroke.
function warnIfHeavy() {
  const b = noteSizeBreakdown();
  const zone = noteSizeZone(b.total, b.content);
  const order = ['ok', 'heavy', 'danger', 'over'];
  if (order.indexOf(zone) > order.indexOf(lastWarnedZone)) {
    if (zone === 'heavy') toast('This note is getting heavy \u2014 see the size indicator at the top.');
    if (zone === 'danger') toast('This note is close to the ' + NOTE_LIMIT_LABEL + ' limit \u2014 consider moving some photos, videos or audio to another note.');
    if (zone === 'over') toast(sizeProblem(b) + ' It can\u2019t be saved until you fix that.');
  }
  lastWarnedZone = zone;
}

function renderSizeDialog(b) {
  b = b || noteSizeBreakdown();
  const zone = noteSizeZone(b.total, b.content);
  document.getElementById('size-status').innerHTML =
    `<span class="size-badge" data-zone="${zone}">${ZONE_ICON[zone]}<span>${ZONE_WORD[zone]}</span></span>` +
    `<span class="size-figure">${formatBytes(b.total)} of ${NOTE_LIMIT_LABEL}</span>`;
  const meter = document.getElementById('size-dialog-meter');
  meter.dataset.zone = zone;
  meter.setAttribute('aria-valuenow', String(Math.round(b.total / MB * 10) / 10));
  document.getElementById('size-dialog-fill').style.transform = `scaleX(${Math.min(1, b.total / NOTE_TOTAL_LIMIT).toFixed(4)})`;

  const rows = [['Text', b.text]];
  if (b.photoCount) rows.push([`Photos (${b.photoCount})`, b.photos]);
  if (b.videoCount) rows.push([`Videos (${b.videoCount})`, b.videos]);
  if (b.clips) rows.push([`Audio (${b.clips} clip${b.clips === 1 ? '' : 's'})`, b.audio]);
  if (b.drawing) rows.push(['Drawing', b.drawing]);
  if (b.locked) rows.push(['Lock encryption', b.lockExtra]);
  document.getElementById('size-rows').innerHTML = rows.map(([label, bytes]) =>
    `<li><span class="size-row-label">${escapeHTML(label)}</span>` +
    `<span class="size-row-bar" aria-hidden="true"><span style="transform:scaleX(${Math.min(1, bytes / Math.max(1, b.total)).toFixed(3)})"></span></span>` +
    `<span class="size-row-value">${formatBytes(bytes)}</span></li>`).join('');

  const advice = {
    ok: 'Plenty of room.',
    heavy: 'This note is getting heavy. Opening it for the first time on another device, or on mobile data, will take a while. Moving some photos, videos or recordings into another note keeps each one quick.',
    danger: 'This note is close to the ' + NOTE_LIMIT_LABEL + ' limit. Remove or split some photos, videos or audio before adding more.',
    over: (sizeProblem(b) || 'This note is over its size limit.') + ' It can\u2019t be saved until you fix that \u2014 or add photos, videos and audio again as Compressed.',
  };
  let text = advice[zone];
  text += ' Photos, videos and audio are kept as separate files in your bucket (with videos sliced into tagged packets), and they count toward the note\u2019s size here.';
  if (b.locked) text += ' Locked notes are about a third bigger than their contents, because encrypted data is stored as text.';
  document.getElementById('size-advice').textContent = text;
  document.getElementById('size-advice-icon').innerHTML = ZONE_ICON[zone];
  document.getElementById('size-advice-box').dataset.zone = zone;
}

/* ---------------------------------------------------------------------
 * Storage — every note against the account's total allowance.
 * Counts BOTH the written note size (`_bytes`) AND all attached media
 * (`_media`: photos, videos, and audio) for the account meter and for
 * each individual note in "Biggest notes".
 * ------------------------------------------------------------------- */

function storageUsage() {
  const limit = Config.storageLimitMB() * 1024 * 1024;
  let used = 0;
  let unknown = 0;
  let media = 0;
  const sized = [];
  const editorActive = !!(editingNoteId && !document.getElementById('overlay-editor').classList.contains('hidden') && noteHasContent());
  const liveBreakdown = editorActive ? noteSizeBreakdown() : null;
  let seenEditingNote = false;

  for (const m of notesCache) {
    let textBytes = typeof m._bytes === 'number' ? m._bytes : null;
    let mBytes = typeof m._media === 'number' && m._media > 0
      ? m._media
      : (typeof m.mediaSize === 'number' && m.mediaSize > 0 ? m.mediaSize : 0);
    let title = m.title || m._lockedTitle || 'Untitled';
    if (editorActive && m.id === editingNoteId && liveBreakdown) {
      seenEditingNote = true;
      textBytes = liveBreakdown.content;
      mBytes = liveBreakdown.media;
      title = document.getElementById('editor-title').value.trim() || title;
    }
    media += mBytes;
    if (typeof textBytes === 'number' || mBytes > 0) {
      const tBytes = typeof textBytes === 'number' ? textBytes : 0;
      used += tBytes;
      const totalNoteBytes = tBytes + mBytes;
      sized.push({
        title,
        bytes: totalNoteBytes,
        textBytes: tBytes,
        mediaBytes: mBytes,
        locked: m.lockType !== 'none',
      });
      if (typeof textBytes !== 'number') unknown++;
    } else {
      unknown++;
    }
  }

  if (editorActive && !seenEditingNote && liveBreakdown) {
    media += liveBreakdown.media;
    used += liveBreakdown.content;
    sized.push({
      title: document.getElementById('editor-title').value.trim() || 'Untitled',
      bytes: liveBreakdown.total,
      textBytes: liveBreakdown.content,
      mediaBytes: liveBreakdown.media,
      locked: lockIsActive(),
    });
  }

  sized.sort((x, y) => y.bytes - x.bytes);
  used += media; // photos, videos and audio live in the same bucket
  const ratio = limit ? used / limit : 0;
  const zone = ratio > 1 ? 'over' : ratio >= STORAGE_DANGER_RATIO ? 'danger' : ratio >= STORAGE_WARN_RATIO ? 'heavy' : 'ok';
  return { used, limit, ratio, zone, unknown, media, count: sized.length || notesCache.length, top: sized.slice(0, 3) };
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
    ? u.top.map((t) => `<li><span class="storage-top-title">${escapeHTML(t.title)}</span><span class="storage-top-size">${formatBytes(t.bytes)}</span></li>`).join('')
    : '';
  document.getElementById('storage-top-label').hidden = !u.top.length;
  const mediaLine = document.getElementById('storage-media');
  if (mediaLine) {
    mediaLine.hidden = !(u.media > 0 || (window.KSMedia && KSMedia.available()));
    mediaLine.textContent = `Of that, photos, videos and audio take ${formatBytes(u.media)}.`;
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
  const video = document.getElementById('settings-video-quality');
  const audio = document.getElementById('settings-audio-quality');
  photo.value = Config.photoQuality();
  if (video) video.value = Config.videoQuality();
  audio.value = Config.audioQuality();
  document.getElementById('settings-photo-hint').textContent = PHOTO_QUALITY[photo.value].hint;
  if (video) document.getElementById('settings-video-hint').textContent = VIDEO_QUALITY[video.value].hint;
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
// `storedLen` is the length of the base64 data: URL.
function canFitMedia(storedLen) {
  const b = noteSizeBreakdown();
  const add = Math.ceil(storedLen * 3 / 4);
  const itemOk = add <= MEDIA_ITEM_MAX_BYTES;
  const projected = b.total + add + 300;
  return {
    ok: itemOk && projected <= NOTE_TOTAL_LIMIT,
    projected,
    message: itemOk ? `That would make this note ${formatBytes(projected)} \u2014 over the ${NOTE_LIMIT_LABEL} limit.` : 'That file is over the 90 MB limit.',
  };
}

// ---- playback ----
//
// One shared "voice" plays everything: a clip's chip in the text, the clip dialog and the recorder's
// preview. It owns the timeline, so the bar never depends on what a browser reports about a file.
// (A recording made in the browser has no length stored in it - the browser says Infinity - which is
// why a player that trusted the file showed its bar stuck at the end.) The length comes from what was
// measured when the clip was recorded or attached, and from the file itself once the browser knows.
//
// It plays through an <audio> element first. If that is refused, errors, or never actually moves,
// it switches by itself to decoding the clip with Web Audio and playing that, from the same spot.

const audioUrls = new Map(); // clip id -> blob: URL
const Voice = {
  el: null, key: null, src: null, loadedKey: null,
  mode: 'element', playing: false, ended: false, dur: 0,
  ctx: null, unlocked: false, buf: null, node: null, startedAt: 0, offset: 0,
  watchdog: 0, raf: 0, fallingBack: false,
};
const VOICE_FALLBACK_MAX_SECONDS = 15 * 60; // decoded audio is raw PCM in memory; keep it bounded
const VOICE_FALLBACK_MAX_BYTES = 80 * 1024 * 1024;
const MINI_PLAYERS = []; // { el, key(), known(), dragging }

function voiceAudioSession(type) { // Safari: play through the speaker, even after the mic was used, and with the silent switch on
  try { if (navigator.audioSession) navigator.audioSession.type = type; } catch (e) { /* not supported */ }
}

// Web Audio may only be started from a tap on some browsers (Safari), so it is readied inside the tap
// that starts playback - even though it is only used if the <audio> element doesn't work out.
function voiceUnlockContext() {
  const AC = window.AudioContext || window.webkitAudioContext;
  if (!AC) return;
  try {
    if (!Voice.ctx) Voice.ctx = new AC();
    if (Voice.ctx.state === 'suspended') Voice.ctx.resume().catch(() => {});
    if (!Voice.unlocked) {
      const s = Voice.ctx.createBufferSource();
      s.buffer = Voice.ctx.createBuffer(1, 1, 22050);
      s.connect(Voice.ctx.destination);
      s.start(0);
      Voice.unlocked = true;
    }
  } catch (e) { /* playback still has the <audio> element */ }
}

function voiceEnsureEl() {
  if (Voice.el) return Voice.el;
  const el = new Audio();
  el.preload = 'auto';
  const live = () => Voice.key && Voice.mode === 'element';
  el.addEventListener('play', () => { if (live()) { Voice.playing = true; voiceChanged(); } });
  el.addEventListener('pause', () => { if (live() && !Voice.fallingBack) { Voice.playing = false; voiceChanged(); } });
  el.addEventListener('ended', () => { if (live()) { Voice.playing = false; Voice.ended = true; voiceChanged(); } });
  el.addEventListener('durationchange', () => { if (live()) voiceChanged(); });
  el.addEventListener('error', () => { if (live() && el.getAttribute('src')) voiceFallback('error'); });
  Voice.el = el;
  return el;
}

// Turns a clip's data: URL into a playable blob: URL right away (no network or promise in between).
function audioUrlSync(id) {
  if (audioUrls.has(id)) return audioUrls.get(id);
  const clip = editorAudio[id];
  if (!clip) return null;
  const comma = clip.data.indexOf(',');
  let type = clip.data.slice(5, comma).replace(/;base64$/i, '');
  if (!/^audio\//i.test(type)) type = 'audio/mpeg';
  const url = URL.createObjectURL(new Blob([b64ToBytes(clip.data.slice(comma + 1))], { type }));
  audioUrls.set(id, url);
  return url;
}

function voiceSourceForClip(id) {
  const clip = editorAudio[id];
  if (!clip) return null;
  return {
    url: audioUrlSync(id),
    dur: clip.dur || 0,
    bytes: async () => b64ToBytes(clip.data.slice(clip.data.indexOf(',') + 1)).buffer,
  };
}

function voiceSourceForPreview() {
  if (!Rec.blob || !Rec.previewUrl) return null;
  return { url: Rec.previewUrl, dur: Rec.dur || 0, bytes: () => Rec.blob.arrayBuffer() };
}

function voiceDuration() {
  if (Voice.mode === 'webaudio' && Voice.buf) return Voice.buf.duration;
  const d = Voice.el && Voice.key ? Voice.el.duration : NaN;
  if (isFinite(d) && d > 0) return d;
  return Voice.dur || 0; // the browser doesn't know (Infinity/NaN): use the measured length
}

function voicePosition() {
  if (!Voice.key || (Voice.ended && !Voice.playing)) return 0; // a clip that has finished is back at the start
  let t = 0;
  if (Voice.mode === 'webaudio') t = Voice.playing && Voice.ctx ? Voice.offset + (Voice.ctx.currentTime - Voice.startedAt) : Voice.offset;
  else if (Voice.el) t = Voice.el.currentTime || 0;
  const d = voiceDuration();
  return Math.max(0, d ? Math.min(t, d) : t);
}

function voiceStopNode() {
  if (!Voice.node) return;
  const n = Voice.node;
  Voice.node = null;
  n.onended = null;
  try { n.stop(); } catch (e) { /* already stopped */ }
}

function voiceStop() {
  clearTimeout(Voice.watchdog);
  voiceStopNode();
  if (Voice.el) { Voice.el.pause(); Voice.el.removeAttribute('src'); Voice.el.load(); }
  Voice.key = null; Voice.src = null; Voice.loadedKey = null; Voice.buf = null;
  Voice.mode = 'element'; Voice.playing = false; Voice.ended = false; Voice.dur = 0; Voice.offset = 0;
  renderVoiceViews();
}

function voiceStopIf(key) { if (Voice.key === key) voiceStop(); }

function voicePause() {
  clearTimeout(Voice.watchdog);
  if (Voice.mode === 'webaudio') {
    Voice.offset = voicePosition();
    voiceStopNode();
    Voice.playing = false;
  } else if (Voice.el) Voice.el.pause();
  voiceChanged();
}

function voicePauseIf(key) { if (Voice.key === key && Voice.playing) voicePause(); }

function voiceLoad(key, getSource) {
  if (Voice.key === key) return true;
  voiceStop();
  let src = null;
  try { src = getSource(); } catch (e) { toast('Couldn\u2019t read this clip.'); return false; }
  if (!src || !src.url) return false;
  Voice.key = key; Voice.src = src; Voice.dur = src.dur || 0;
  return true;
}

// Called straight from the tap, with nothing awaited before it, so browsers count it as started by the tap.
function voiceToggle(key, getSource) {
  voiceUnlockContext();
  voiceAudioSession('playback');
  if (Voice.key === key && Voice.playing) { voicePause(); return; }
  if (!voiceLoad(key, getSource)) return;
  voicePlay();
}

function voicePlay() {
  if (Voice.mode === 'webaudio') { voicePlayBuffer(); return; }
  const el = voiceEnsureEl();
  if (Voice.loadedKey !== Voice.key) { el.src = Voice.src.url; Voice.loadedKey = Voice.key; el.load(); }
  if (Voice.ended) { try { el.currentTime = 0; } catch (e) { /* not seekable yet */ } Voice.ended = false; }
  el.muted = false;
  el.volume = 1;
  Voice.playing = true;
  const started = el.play();
  voiceWatch();
  if (started && started.catch) {
    started.catch((e) => {
      if (e && e.name === 'AbortError') return; // another clip was started over this one
      if (e && e.name === 'NotAllowedError') { Voice.playing = false; toast('Your browser blocked the sound \u2014 tap play again.'); voiceChanged(); return; }
      voiceFallback('rejected');
    });
  }
  voiceChanged();
}

// If the <audio> element says it is playing but the clock is not moving, it is not really playing.
function voiceWatch() {
  clearTimeout(Voice.watchdog);
  const key = Voice.key;
  const from = Voice.el ? Voice.el.currentTime : 0;
  Voice.watchdog = setTimeout(() => {
    if (Voice.key !== key || Voice.mode !== 'element' || !Voice.playing || !Voice.el) return;
    // We asked it to play (and it never reported a pause or the end), yet its clock has not moved.
    if (!Voice.el.ended && Voice.el.currentTime - from < 0.05) voiceFallback('stuck');
  }, 2200);
}

async function voiceFallback(reason) {
  if (Voice.mode === 'webaudio' || Voice.fallingBack || !Voice.key || !Voice.src) return;
  const key = Voice.key;
  const wasPlaying = Voice.playing;
  Voice.fallingBack = true;
  const from = Voice.el ? (Voice.el.currentTime || 0) : 0;
  try {
    if (Voice.el) Voice.el.pause();
    if (!Voice.ctx) throw new Error('no web audio');
    const bytes = await Voice.src.bytes();
    if (bytes.byteLength > VOICE_FALLBACK_MAX_BYTES) throw new Error('too big');
    const buf = await Voice.ctx.decodeAudioData(bytes);
    if (Voice.key !== key) return; // the person has moved on
    if (buf.duration > VOICE_FALLBACK_MAX_SECONDS) throw new Error('too long');
    Voice.buf = buf; Voice.dur = buf.duration; Voice.mode = 'webaudio';
    Voice.offset = from >= buf.duration - 0.05 ? 0 : from;
    voiceLearnDuration(key, buf.duration);
    if (wasPlaying) voicePlayBuffer(); else voiceChanged();
  } catch (e) {
    if (Voice.key === key) {
      Voice.playing = false;
      voiceChanged();
      toast('This browser can\u2019t play this clip. Open \u22ef and use Download to listen elsewhere.');
    }
  } finally {
    Voice.fallingBack = false;
  }
}

function voicePlayBuffer() {
  const ctx = Voice.ctx;
  if (!ctx || !Voice.buf) return;
  try { if (ctx.state === 'suspended') ctx.resume(); } catch (e) { /* ignore */ }
  voiceStopNode();
  if (Voice.ended || Voice.offset >= Voice.buf.duration - 0.05) { Voice.offset = 0; Voice.ended = false; }
  const node = ctx.createBufferSource();
  node.buffer = Voice.buf;
  node.connect(ctx.destination);
  node.onended = () => {
    if (Voice.node !== node) return;
    Voice.node = null; Voice.playing = false; Voice.ended = true; Voice.offset = 0;
    voiceChanged();
  };
  Voice.startedAt = ctx.currentTime;
  node.start(0, Voice.offset);
  Voice.node = node;
  Voice.playing = true;
  voiceChanged();
}

// Moves playback to a fraction (0..1) of the clip, loading it first if need be.
function voiceSeek(key, getSource, frac) {
  if (!voiceLoad(key, getSource)) return;
  const d = voiceDuration();
  if (!d) return;
  const t = Math.max(0, Math.min(d - 0.05, frac * d));
  Voice.ended = false;
  if (Voice.mode === 'webaudio') {
    Voice.offset = t;
    if (Voice.playing) voicePlayBuffer(); else voiceChanged();
    return;
  }
  const el = voiceEnsureEl();
  if (Voice.loadedKey !== Voice.key) { el.src = Voice.src.url; Voice.loadedKey = Voice.key; el.load(); }
  try { el.currentTime = t; } catch (e) { /* not seekable yet */ }
  voiceChanged();
}

// A clip that had no length on record (an older note) learns it the first time anything measures it.
function voiceLearnDuration(key, dur) {
  if (!key.startsWith('clip:') || !(dur > 0)) return;
  const id = key.slice(5);
  const clip = editorAudio[id];
  if (!clip || clip.dur > 0) return;
  clip.dur = dur;
  document.querySelectorAll(`#editor-body ks-audio[data-id="${id}"]`).forEach((el) => { el.innerHTML = audioChipHTML(id); });
  onEditorContentChanged();
}

async function ensureClipDuration(id) {
  const clip = editorAudio[id];
  if (!clip || clip.dur > 0) return;
  try {
    const d = await probeAudioDuration(audioUrlSync(id));
    if (d > 0) voiceLearnDuration('clip:' + id, d);
  } catch (e) { /* the length just stays unknown */ }
}

function voiceTicker() {
  if (Voice.raf) return;
  const tick = () => {
    Voice.raf = 0;
    renderVoiceViews();
    if (Voice.playing) Voice.raf = requestAnimationFrame(tick);
  };
  Voice.raf = requestAnimationFrame(tick);
}

function voiceChanged() {
  renderVoiceViews();
  if (Voice.playing) voiceTicker();
}

function renderVoiceViews() {
  const dur = voiceDuration();
  const pos = voicePosition();
  document.querySelectorAll('#editor-body .audio-chip[data-id]').forEach((chip) => {
    const mine = Voice.key === 'clip:' + chip.dataset.id;
    const playing = mine && Voice.playing;
    chip.classList.toggle('is-playing', playing);
    const btn = chip.querySelector('.audio-play');
    if (btn) btn.setAttribute('aria-pressed', String(playing));
    chip.style.setProperty('--p', mine && dur ? Math.min(1, pos / dur).toFixed(3) : '0');
  });
  for (const mp of MINI_PLAYERS) updateMiniPlayer(mp);
}

function updateMiniPlayer(mp) {
  const key = mp.key();
  const mine = !!key && Voice.key === key;
  const known = mp.known();
  const dur = mine ? voiceDuration() || known : known;
  const pos = mine ? voicePosition() : 0;
  const playing = mine && Voice.playing;
  const play = mp.el.querySelector('.mp-play');
  play.classList.toggle('is-playing', playing);
  play.setAttribute('aria-label', playing ? 'Pause' : 'Play');
  const seek = mp.el.querySelector('.mp-seek');
  const shown = mp.dragging ? Number(seek.value) / 1000 * dur : pos;
  if (!mp.dragging) seek.value = dur ? String(Math.round(Math.min(1, pos / dur) * 1000)) : '0';
  seek.style.setProperty('--p', dur ? Math.min(1, shown / dur).toFixed(3) : '0');
  seek.disabled = !dur;
  seek.setAttribute('aria-valuetext', `${mmss(shown)} of ${dur ? mmss(dur) : 'unknown length'}`);
  mp.el.querySelector('.mp-pos').textContent = mmss(shown);
  mp.el.querySelector('.mp-dur').textContent = dur ? mmss(dur) : '\u2013:\u2013\u2013';
}

function registerMiniPlayer(el, key, known, getSource) {
  const mp = { el, key, known, dragging: false };
  MINI_PLAYERS.push(mp);
  el.querySelector('.mp-play').addEventListener('click', () => { const k = key(); if (k) voiceToggle(k, getSource); });
  const seek = el.querySelector('.mp-seek');
  seek.addEventListener('input', () => { mp.dragging = true; updateMiniPlayer(mp); });
  seek.addEventListener('change', () => {
    const k = key();
    mp.dragging = false;
    if (k) voiceSeek(k, getSource, Number(seek.value) / 1000);
    updateMiniPlayer(mp);
  });
  updateMiniPlayer(mp);
}

function clearAudioUrls() {
  voiceStop();
  for (const url of audioUrls.values()) URL.revokeObjectURL(url);
  audioUrls.clear();
}

function toggleClipPlayback(id) {
  voiceToggle('clip:' + id, () => voiceSourceForClip(id));
  if (editorAudio[id] && !(editorAudio[id].dur > 0)) ensureClipDuration(id);
}

// ---- clip options dialog ----

let clipDialogId = null;

function openClipDialog(id) {
  const clip = editorAudio[id];
  if (!clip) return;
  voicePause();
  clipDialogId = id;
  document.getElementById('clip-heading').textContent = `Audio clip ${clipIndex(id)}`;
  document.getElementById('clip-meta').textContent = [
    fmtDur(clip.dur), formatBytes(estimateImageBytes(clip.data)), audioExtFor(clip).toUpperCase(), clip.name,
  ].filter(Boolean).join(' \u00b7 ');
  const problem = document.getElementById('clip-error');
  problem.hidden = true;
  try { audioUrlSync(id); } catch (e) { problem.hidden = false; }
  renderVoiceViews();
  show('overlay-clip');
  if (!(clip.dur > 0)) ensureClipDuration(id).then(() => { if (clipDialogId === id) renderVoiceViews(); });
}

function pauseClipPreview() {
  if (clipDialogId) voicePauseIf('clip:' + clipDialogId);
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
    const url = audioUrlSync(id);
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
  voiceStopIf('clip:' + id);
  hide('overlay-clip');
  updateSizeMeter();
  onEditorContentChanged();
}


/* ---------------------------------------------------------------------
 * Compress saved media \u2014 any time after a photo or clip went into a note, open the note and
 * compress it from the photo viewer or the clip's own dialog. The compressed copy replaces the
 * original once the note saves (the original file is then removed from the bucket), so it asks
 * first and says how much smaller it will be. Strength comes from Settings -> Compressed quality.
 * ------------------------------------------------------------------- */

let compressingSaved = false;

async function compressSavedPhoto() {
  if (compressingSaved) { toast('Another compression is still running'); return; }
  const idx = lightboxIndex;
  const photoId = lightboxIds[idx];
  const src = editorPhotos[photoId];
  if (!src) return;
  const targetNoteId = editingNoteId;
  const before = estimateImageBytes(src);
  const q = PHOTO_QUALITY[Config.photoQuality()];
  const label = `Compressing photo ${idx + 1} \u00b7 ${formatBytes(before)}`;
  compressingSaved = true;
  closeLightbox();
  syncBarSet(`${label} \u00b7 0%`, null);
  try {
    const blob = await (await fetch(src)).blob();
    const out = await fileToCompressedDataURL(blob, q.maxDim, q.quality);
    const after = estimateImageBytes(out);
    syncBarSet(`${label} \u00b7 100%`, 1);
    if (editingNoteId !== targetNoteId) { syncBarHideSoon(300); return; }
    if (after >= before * 0.95) {
      syncBarHideSoon(300);
      toast('Compressing wouldn\u2019t make this photo meaningfully smaller \u2014 left as it is');
      return;
    }
    syncBarHideSoon(300);
    openConfirm('Replace with the compressed copy?',
      `${formatBytes(before)} \u2192 ${formatBytes(after)} (${q.label}: ${q.hint}) The original is removed from this note, and the app can\u2019t get it back afterwards. Its file is cleared out of your bucket the next time this note is saved after an hour.`,
      () => {
        if (editingNoteId !== targetNoteId || editorPhotos[photoId] !== src) return;
        editorPhotos[photoId] = out;
        document.querySelectorAll(`#editor-body ks-photo[data-id="${photoId}"]`).forEach((el) => hydratePhotos(el.parentNode));
        updateSizeMeter();
        onEditorContentChanged();
        syncBarSuccess(`Compressed: ${formatBytes(before)} \u2192 ${formatBytes(after)}`);
      }, 'Replace');
  } catch (e) {
    syncBarHideSoon(300);
    toast('Couldn\u2019t compress that photo');
  } finally {
    compressingSaved = false;
  }
}

async function compressSavedClip(id) {
  if (compressingSaved) { toast('Another compression is still running'); return; }
  const clip = editorAudio[id];
  if (!clip) return;
  const targetNoteId = editingNoteId;
  const before = estimateImageBytes(clip.data);
  const bps = AUDIO_QUALITY[Config.audioQuality()].bps;
  const q = AUDIO_QUALITY[Config.audioQuality()];
  const label = `Compressing audio clip ${clipIndex(id)} \u00b7 ${formatBytes(before)}`;
  compressingSaved = true;
  hide('overlay-clip');
  syncBarSet(`${label} \u00b7 0%`, 0);
  try {
    const blob = await (await fetch(clip.data)).blob();
    const out = await compressAudioFile(blob, bps,
      (f) => syncBarSet(`${label} \u00b7 ${Math.round(f * 100)}%`, f),
      () => editingNoteId !== targetNoteId || !editorAudio[id]);
    if (!out || editingNoteId !== targetNoteId) { syncBarHideSoon(300); return; }
    if (out.size >= before * 0.95) {
      syncBarHideSoon(300);
      toast('Compressing wouldn\u2019t make this clip meaningfully smaller \u2014 left as it is');
      return;
    }
    syncBarHideSoon(300);
    const data = await readFileAsDataURL(out);
    const after = estimateImageBytes(data);
    openConfirm('Replace with the compressed copy?',
      `${formatBytes(before)} \u2192 ${formatBytes(after)} (${q.label}, ${q.bps / 1000} kbps). The original is removed from this note, and the app can\u2019t get it back afterwards. Its file is cleared out of your bucket the next time this note is saved after an hour.`,
      () => {
        const cur = editorAudio[id];
        if (editingNoteId !== targetNoteId || !cur || cur.data !== clip.data) return;
        cur.data = data;
        if (cur.name) cur.name = cur.name.replace(/\.[^.]+$/, '') + (/mp4|aac/.test(out.type) ? '.m4a' : '.webm');
        voiceStopIf('clip:' + id);
        const old = audioUrls.get(id);
        if (old) { URL.revokeObjectURL(old); audioUrls.delete(id); }
        updateSizeMeter();
        onEditorContentChanged();
        syncBarSuccess(`Compressed: ${formatBytes(before)} \u2192 ${formatBytes(after)}`);
      }, 'Replace');
  } catch (e) {
    syncBarHideSoon(300);
    toast('Couldn\u2019t compress that clip');
  } finally {
    compressingSaved = false;
  }
}

/* ---------------------------------------------------------------------
 * Original or Compressed \u2014 asked every time photos or audio are about to be added, so nothing
 * is ever shrunk without the person choosing it. Resolves 'original', 'compressed', or null
 * if they cancel.
 * ------------------------------------------------------------------- */

function estimatePacketCountForBytes(bytes, isVideo) {
  if (!bytes || bytes <= 0) return 1;
  const maxPkt = (window.KSMedia && KSMedia.VIDEO_MAX_PACKET_BYTES) || (2 * 1024 * 1024);
  if (!isVideo && bytes <= maxPkt) return 1;
  if (bytes <= maxPkt * 3) {
    const targetCount = bytes < 3 ? 1 : Math.min(6, Math.max(3, Math.ceil(bytes / (384 * 1024))));
    const chunkSize = Math.max(1, Math.ceil(bytes / targetCount));
    return Math.max(1, Math.ceil(bytes / chunkSize));
  }
  return Math.max(1, Math.ceil(bytes / maxPkt));
}

function estimateCompressedVideoBytes(fileSize, meta, presetKey) {
  const q = VIDEO_QUALITY[presetKey || Config.videoQuality()] || VIDEO_QUALITY.standard;
  const origBytes = Math.max(0, Number(fileSize) || 0);
  const dur = meta && Number(meta.duration) > 0 ? Number(meta.duration) : 0;
  let w = (meta && Number(meta.width)) || 1280;
  let h = (meta && Number(meta.height)) || 720;
  const maxSide = Math.max(w, h);
  if (maxSide > q.maxDim) {
    const scale = q.maxDim / maxSide;
    w = Math.max(2, Math.round(w * scale / 2) * 2);
    h = Math.max(2, Math.round(h * scale / 2) * 2);
  }
  const targetTotalBps = q.videoBps + q.audioBps;
  let compBytes;
  let effectiveVideoBps = q.videoBps;
  if (dur > 0) {
    const byBitrate = Math.round((dur * targetTotalBps) / 8);
    const byRatio = Math.round(origBytes * q.ratio);
    if (origBytes > 0 && byBitrate >= origBytes * 0.88) {
      compBytes = Math.max(Math.min(origBytes, 4096), byRatio);
      effectiveVideoBps = Math.max(180000, Math.round((compBytes * 8) / dur) - q.audioBps);
    } else {
      compBytes = origBytes > 0 ? Math.min(byBitrate, Math.round(origBytes * 0.78)) : byBitrate;
    }
  } else {
    compBytes = Math.max(Math.min(origBytes, 4096), Math.round(origBytes * q.ratio));
  }
  const savedBytes = Math.max(0, origBytes - compBytes);
  const savedPct = origBytes > 0 ? Math.round((savedBytes / origBytes) * 100) : 0;
  return {
    origBytes,
    bytes: compBytes,
    savedBytes,
    savedPct,
    videoBps: effectiveVideoBps,
    audioBps: q.audioBps,
    fps: q.fps || 30,
    targetWidth: w,
    targetHeight: h,
    label: q.label,
    maxDim: q.maxDim,
    origPackets: estimatePacketCountForBytes(origBytes, true),
    compPackets: estimatePacketCountForBytes(compBytes, true),
  };
}

function askMediaQuality(kind, files, videoEstimates) {
  return new Promise((resolve) => {
    const list = files || [];
    const count = list.length;
    const total = list.reduce((n, f) => n + (f.size || 0), 0);
    const compAudio = AUDIO_QUALITY[Config.audioQuality()];
    const compVideoPreset = VIDEO_QUALITY[Config.videoQuality()];
    let title; let summary; let origTitle = 'Original'; let compTitle = 'Compressed'; let origHint; let compHint;

    const bannerEl = document.getElementById('quality-size-banner');
    const bannerTitleEl = document.getElementById('quality-banner-title');
    const bannerPillEl = document.getElementById('quality-banner-pill');
    const packetNoteEl = document.getElementById('quality-packet-note');
    let totalCompBytes = 0;
    let totalOrigPackets = 0;
    let totalCompPackets = 0;

    if (kind === 'video') {
      const estList = list.map((f, i) => (videoEstimates && videoEstimates[i]) || estimateCompressedVideoBytes(f.size || 0, null, Config.videoQuality()));
      totalCompBytes = estList.reduce((n, e) => n + e.bytes, 0);
      totalOrigPackets = estList.reduce((n, e) => n + e.origPackets, 0);
      totalCompPackets = estList.reduce((n, e) => n + e.compPackets, 0);
      const savedBytes = Math.max(0, total - totalCompBytes);
      const savedPct = total > 0 ? Math.round((savedBytes / total) * 100) : 0;

      title = count === 1 ? 'Add this video' : `Add ${count} videos`;
      summary = `Original: ${formatBytes(total)} \u2192 Compressed final size: ${formatBytes(totalCompBytes)} (${compVideoPreset.label} ${compVideoPreset.maxDim}p).`;
      origTitle = `Original \u00b7 ${formatBytes(total)}`;
      compTitle = `Compressed \u00b7 ${formatBytes(totalCompBytes)} final size`;
      origHint = `Kept byte for byte at full resolution (${formatBytes(total)}). Sliced into ${totalOrigPackets} tagged cloud packets so phone sleep never interrupts the upload.`;
      compHint = `Final size after compressing: ${formatBytes(totalCompBytes)} (saves ${formatBytes(savedBytes)}, ${savedPct}% smaller). ${compVideoPreset.hint} Sliced into ${totalCompPackets} tagged cloud packets.`;

      if (bannerEl) {
        bannerEl.hidden = false;
        bannerTitleEl.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="2.5" y="5" width="14" height="14" rx="2.5"/><path d="M16.5 10.2 21.5 7v10l-5-3.2v-3.6z"/></svg>`
          + `<span>After compressing: ${formatBytes(total)} \u2192 <b>${formatBytes(totalCompBytes)}</b></span>`;
        bannerPillEl.textContent = savedBytes > 0 ? `Saves ${formatBytes(savedBytes)} (-${savedPct}%)` : `${compVideoPreset.maxDim}p`;
        packetNoteEl.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 2 3 7v10l9 5 9-5V7l-9-5z"/><path d="M3 7l9 5 9-5M12 22V12"/></svg>`
          + `<span>Sliced into ${totalCompPackets} tagged packets (${totalOrigPackets} if Original) &amp; uploaded section by section. Lost packets re-upload automatically.</span>`;
      }
    } else if (kind === 'photo') {
      title = count === 1 ? 'Add this photo' : `Add ${count} photos`;
      summary = `${formatBytes(total)} as taken.`;
      origHint = 'Exactly as taken \u2014 no resizing, no re-compression. Keeps location data.';
      compHint = PHOTO_QUALITY[Config.photoQuality()].hint + ' Set the strength in Settings.';
      if (bannerEl) bannerEl.hidden = true;
    } else if (kind === 'audio') {
      title = count === 1 ? 'Add this audio file' : `Add ${count} audio files`;
      summary = `${formatBytes(total)} as it is.`;
      origHint = 'Kept byte for byte, exactly as the file is.';
      compHint = `Re-encoded at ${compAudio.label.toLowerCase()} quality (${compAudio.bps / 1000} kbps). It runs in real time \u2014 as long as the audio plays \u2014 and needs this screen open. Kept as it is if that wouldn\u2019t make it smaller.`;
      if (bannerEl) bannerEl.hidden = true;
    } else {
      title = 'Record audio';
      summary = 'Choose before you start \u2014 a recording can\u2019t be changed afterwards.';
      origHint = `Highest quality the browser offers, with noise suppression, echo cancellation and auto-gain turned off. ${AUDIO_QUALITY.max.hint}`;
      compHint = `${compAudio.label} quality with the usual noise suppression on. ${compAudio.hint}`;
      if (bannerEl) bannerEl.hidden = true;
    }
    document.getElementById('quality-title').textContent = title;
    document.getElementById('quality-summary').textContent = summary;
    // Every file with its own size (and for videos, its final compressed size too), so the choice is an informed one.
    const filesEl = document.getElementById('quality-files');
    filesEl.textContent = '';
    list.slice(0, 8).forEach((f, idx) => {
      const li = document.createElement('li');
      const nm = document.createElement('span');
      nm.className = 'qf-name';
      nm.textContent = f.name || 'file';
      const sz = document.createElement('span');
      sz.className = 'qf-size';
      if (kind === 'video') {
        const est = (videoEstimates && videoEstimates[idx]) || estimateCompressedVideoBytes(f.size || 0, null, Config.videoQuality());
        sz.innerHTML = `<span>${escapeHTML(formatBytes(f.size || 0))}</span><span aria-hidden="true">\u2192</span><span class="qf-comp-tag" title="Final size after compressing">${escapeHTML(formatBytes(est.bytes))}</span>`;
      } else {
        sz.textContent = formatBytes(f.size || 0);
      }
      li.append(nm, sz);
      filesEl.appendChild(li);
    });
    if (list.length > 8) {
      const li = document.createElement('li');
      li.className = 'qf-more';
      li.textContent = `+ ${list.length - 8} more`;
      filesEl.appendChild(li);
    }
    filesEl.hidden = !list.length;

    // Fresh buttons each time, so an old choice's listener can't fire again.
    const fresh = (id) => { const old = document.getElementById(id); const btn = old.cloneNode(true); old.parentNode.replaceChild(btn, old); return btn; };
    const optOriginal = fresh('btn-quality-original');
    const optCompressed = fresh('btn-quality-compressed');
    const okBtn = fresh('btn-quality-ok');
    const cancelBtn = fresh('btn-quality-cancel');
    optOriginal.querySelector('.q-title').textContent = origTitle;
    optOriginal.querySelector('.q-hint').textContent = origHint;
    optCompressed.querySelector('.q-title').textContent = compTitle;
    optCompressed.querySelector('.q-hint').textContent = compHint;

    // Tapping an option only selects it; nothing happens until OK. Original is pre-selected because
    // it never changes your file.
    let choice = 'original';
    const options = [[optOriginal, 'original'], [optCompressed, 'compressed']];
    const select = (value, moveFocus) => {
      choice = value;
      for (const [btn, v] of options) {
        btn.setAttribute('aria-checked', String(v === value));
        btn.tabIndex = v === value ? 0 : -1;
        if (v === value && moveFocus) btn.focus();
      }
      if (kind === 'video' && okBtn) {
        okBtn.textContent = value === 'compressed'
          ? `Add compressed (${formatBytes(totalCompBytes)})`
          : `Add original (${formatBytes(total)})`;
      } else if (okBtn) {
        okBtn.textContent = 'OK';
      }
    };
    const finish = (value) => {
      document.removeEventListener('keydown', onKey, true);
      hide('overlay-quality');
      resolve(value);
    };
    const onKey = (e) => {
      if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); finish(null); return; }
      // Radio-group keys: arrows move the selection between the two options.
      if (['ArrowDown', 'ArrowUp', 'ArrowLeft', 'ArrowRight'].includes(e.key) && options.some(([btn]) => btn === document.activeElement)) {
        e.preventDefault();
        select(choice === 'original' ? 'compressed' : 'original', true);
      }
    };
    for (const [btn, v] of options) btn.addEventListener('click', () => select(v, false));
    okBtn.addEventListener('click', () => finish(choice));
    cancelBtn.addEventListener('click', () => finish(null));
    document.addEventListener('keydown', onKey, true);
    select('original', false);
    show('overlay-quality');
    optOriginal.focus();
  });
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

// Re-encodes an audio file at a lower bitrate. A browser has no way to do that faster than the
// audio plays, so this plays the file silently into a recorder: it takes as long as the audio lasts.
// Resolves with a Blob, or null if `shouldStop()` turned true part-way.
async function compressAudioFile(file, bps, onProgress, shouldStop) {
  const AC = window.AudioContext || window.webkitAudioContext;
  if (!AC || !window.MediaRecorder) throw new Error('This browser can\u2019t compress audio.');
  const mime = pickRecorderMime();
  const url = URL.createObjectURL(file);
  const audio = new Audio();
  audio.preload = 'auto';
  audio.src = url;
  const ctx = new AC();
  const chunks = [];
  let rec = null;
  let timer = 0;
  let stopped = false;
  try {
    await ctx.resume();
    const source = ctx.createMediaElementSource(audio);
    const dest = ctx.createMediaStreamDestination();
    source.connect(dest); // deliberately not connected to the speakers
    rec = new MediaRecorder(dest.stream, { ...(mime ? { mimeType: mime } : {}), audioBitsPerSecond: bps });
    rec.ondataavailable = (ev) => { if (ev.data && ev.data.size) chunks.push(ev.data); };
    const finished = new Promise((resolve, reject) => {
      rec.onstop = resolve;
      rec.onerror = () => reject(new Error('Compression failed'));
      audio.onended = () => { if (rec.state !== 'inactive') rec.stop(); };
      audio.onerror = () => reject(new Error('Couldn\u2019t play that file to compress it'));
    });
    timer = setInterval(() => {
      if (shouldStop && shouldStop()) {
        stopped = true;
        audio.pause();
        if (rec.state !== 'inactive') rec.stop();
        return;
      }
      if (onProgress && isFinite(audio.duration) && audio.duration > 0) onProgress(Math.min(1, audio.currentTime / audio.duration));
    }, 400);
    rec.start(1000);
    await audio.play();
    await finished;
    if (stopped || !chunks.length) return null;
    return new Blob(chunks, { type: rec.mimeType || mime || 'audio/webm' });
  } finally {
    clearInterval(timer);
    if (rec && rec.state !== 'inactive') { try { rec.stop(); } catch (e) { /* already stopped */ } }
    try { audio.pause(); } catch (e) { /* nothing playing */ }
    audio.removeAttribute('src');
    try { ctx.close(); } catch (e) { /* already closed */ }
    URL.revokeObjectURL(url);
  }
}

async function attachAudioFiles(files) {
  const mode = await askMediaQuality('audio', files);
  if (!mode) return 0;
  const targetNoteId = editingNoteId;
  let added = 0;
  let refused = 0;
  let unreadable = 0;
  let keptOriginal = 0;
  const audioResults = [];
  for (let n = 0; n < files.length; n++) {
    const file = files[n];
    const ext = ((/\.([a-z0-9]+)$/i.exec(file.name) || [])[1] || '').toLowerCase();
    if (!/^audio\//.test(file.type) && !EXT_MIME[ext]) { unreadable++; continue; }
    if (!canFitMedia(Math.ceil(file.size * 4 / 3) + 40).ok) { refused++; continue; }
    try {
      let blob = file;
      let name = file.name;
      if (mode === 'compressed') {
        const base = `Compressing audio ${n + 1} of ${files.length} \u00b7 ${file.name} (${formatBytes(file.size)})`;
        syncBarSet(`${base} \u00b7 0%`, 0);
        try {
          const out = await compressAudioFile(file, AUDIO_QUALITY[Config.audioQuality()].bps,
            (f) => syncBarSet(`${base} \u00b7 ${Math.round(f * 100)}%`, f), () => editingNoteId !== targetNoteId);
          if (editingNoteId !== targetNoteId) break;
          if (out && out.size < file.size) {
            blob = out;
            name = file.name.replace(/\.[^.]+$/, '') + (/mp4|aac/.test(out.type) ? '.m4a' : '.webm');
            audioResults.push(`${formatBytes(file.size)} \u2192 ${formatBytes(out.size)}`);
          } else keptOriginal++;
        } catch (e) { keptOriginal++; }
      }
      let data = await readFileAsDataURL(blob);
      if (!/^data:audio\//.test(data)) data = data.replace(/^data:[^;,]*/, 'data:' + (EXT_MIME[ext] || 'audio/mpeg'));
      if (editingNoteId !== targetNoteId) break;
      const url = URL.createObjectURL(file);
      const dur = await probeAudioDuration(url);
      URL.revokeObjectURL(url);
      if (editingNoteId !== targetNoteId) break;
      if (!canFitMedia(data.length + 4).ok) { refused++; continue; }
      addAudioClip({ data, dur, name });
      added++;
    } catch (e) { unreadable++; }
  }
  if (mode === 'compressed') {
    if (audioResults.length) syncBarSuccess(audioResults.length === 1 ? `Compressed: ${audioResults[0]}` : `Compressed ${audioResults.length} audio files`);
    else syncBarHideSoon(300);
  }
  if (refused) toast(refused === 1 ? `A file wasn\u2019t added \u2014 it would push this note over ${limitWord()}` : `${refused} files weren\u2019t added \u2014 they would push this note over ${limitWord()}`);
  else if (unreadable) toast(unreadable === 1 ? 'Couldn\u2019t read that file as audio' : `Couldn\u2019t read ${unreadable} of those files as audio`);
  else if (keptOriginal) toast(keptOriginal === 1 ? 'Kept the original \u2014 compressing wouldn\u2019t have made it smaller' : `Kept ${keptOriginal} originals \u2014 compressing wouldn\u2019t have made them smaller`);
  return added;
}

// ---- recording ----

const Rec = {
  state: 'idle', stream: null, recorder: null, chunks: [], bytes: 0, t0: 0, stopAt: 0, tick: 0,
  ctx: null, analyser: null, buf: null, blob: null, dur: 0, previewUrl: null, discard: false,
  baseBytes: 0, autoStopped: false, bps: 0, mode: '',
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

function overlayIsProtected(id) { return (id === 'overlay-record' && Rec.state !== 'idle') || id === 'overlay-quality'; }

function openRecorder() {
  recorderTeardown();
  setRecState('idle');
  document.getElementById('record-quality').textContent = 'You\u2019ll choose Original or Compressed when you start recording or attach a file.';
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
  voiceStopIf('preview');
  if (Rec.previewUrl) { URL.revokeObjectURL(Rec.previewUrl); Rec.previewUrl = null; }
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
    if (Rec.ctx.state === 'suspended') Rec.ctx.resume().catch(() => {}); // Safari starts it suspended
  } catch (e) { Rec.analyser = null; }
}

function readLevel() {
  if (!Rec.analyser) return 0;
  Rec.analyser.getByteTimeDomainData(Rec.buf);
  let sum = 0;
  for (let i = 0; i < Rec.buf.length; i++) { const d = (Rec.buf[i] - 128) / 128; sum += d * d; }
  return Math.min(1, Math.sqrt(sum / Rec.buf.length) * 3);
}

function updateRecUI() {
  if (Rec.state !== 'recording') return;
  const q = { bps: Rec.bps || AUDIO_QUALITY[Config.audioQuality()].bps };
  const elapsed = (performance.now() - Rec.t0) / 1000;
  document.getElementById('record-timer').textContent = mmss(elapsed);
  document.getElementById('record-level').style.setProperty('--level', readLevel().toFixed(2));
  const clipBytes = Math.round(Math.max(Rec.bytes, q.bps / 8 * elapsed));
  const projected = Rec.baseBytes + clipBytes;
  const zone = noteSizeZone(projected, 0);
  const box = document.getElementById('record-projection');
  box.dataset.zone = zone;
  box.innerHTML = `${ZONE_ICON[zone]}<span>This clip \u2248 ${formatBytes(clipBytes)} \u00b7 note would be ${formatBytes(projected)} / ${NOTE_LIMIT_LABEL}</span>`;
}

function guardRecordingSize() {
  if (Rec.baseBytes + Rec.bytes > NOTE_TOTAL_LIMIT - 256 * 1024 || Rec.bytes > MEDIA_ITEM_MAX_BYTES - 256 * 1024) {
    Rec.autoStopped = true;
    stopRecording();
  }
}

async function startRecording() {
  showRecError('');
  if (!recorderSupported()) { showRecError('Recording isn\u2019t available here. You can still attach an audio file.'); return; }
  const mode = await askMediaQuality('record');
  if (!mode) return;
  voiceStop();
  voiceAudioSession('play-and-record');
  // Original: the browser's own noise suppression, echo cancellation and auto-gain are switched off
  // (they muddy music and quiet sounds), and the recorder runs at its highest quality.
  const constraints = mode === 'original'
    ? { echoCancellation: false, noiseSuppression: false, autoGainControl: false }
    : true;
  let stream;
  try { stream = await navigator.mediaDevices.getUserMedia({ audio: constraints }); }
  catch (e) { showRecError(micErrorText(e)); return; }
  if (document.getElementById('overlay-record').classList.contains('hidden')) { stream.getTracks().forEach((t) => t.stop()); return; }
  const mime = pickRecorderMime();
  const q = mode === 'original' ? AUDIO_QUALITY.max : AUDIO_QUALITY[Config.audioQuality()];
  Rec.bps = q.bps;
  Rec.mode = mode;
  let recorder;
  try { recorder = new MediaRecorder(stream, { ...(mime ? { mimeType: mime } : {}), audioBitsPerSecond: q.bps }); }
  catch (e) { try { recorder = new MediaRecorder(stream); } catch (e2) { stream.getTracks().forEach((t) => t.stop()); showRecError('Couldn\u2019t start recording in this browser.'); return; } }
  Rec.stream = stream;
  Rec.recorder = recorder;
  Rec.chunks = [];
  Rec.bytes = 0;
  Rec.discard = false;
  Rec.autoStopped = false;
  Rec.baseBytes = noteSizeBreakdown().total;
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
  voiceAudioSession('playback'); // the mic is closed: play through the speaker again
  if (!blob.size) { showRecError('Nothing was recorded \u2014 check that your microphone is working.'); setRecState('idle'); return; }
  Rec.blob = blob;
  Rec.dur = ((Rec.stopAt || performance.now()) - Rec.t0) / 1000;
  if (Rec.previewUrl) URL.revokeObjectURL(Rec.previewUrl);
  Rec.previewUrl = URL.createObjectURL(blob);
  voiceStopIf('preview');
  renderVoiceViews();
  document.getElementById('record-result').textContent =
    `${mmss(Rec.dur)} \u00b7 ${formatBytes(blob.size)}${Rec.autoStopped ? ' \u00b7 stopped at the size limit' : ''}`;
  const fit = canFitMedia(Math.ceil(blob.size * 4 / 3) + 40);
  const zone = fit.ok ? noteSizeZone(fit.projected, 0) : 'over';
  const msg = fit.ok ? `Adding this makes the note ${formatBytes(fit.projected)} / ${NOTE_LIMIT_LABEL}.` : fit.message + ' Discard it, or record something shorter.';
  const box = document.getElementById('record-review-note');
  box.dataset.zone = zone;
  box.innerHTML = `${ZONE_ICON[zone]}<span>${escapeHTML(msg)}</span>`;
  if (fit.ok) warnIfSilent(blob);
  document.getElementById('btn-record-add').disabled = !fit.ok;
  showRecError('');
  setRecState('review');
}

// Looks at the finished recording itself: if it holds (almost) no sound, say so now rather than
// when it plays back silent. Skipped quietly where the browser can't decode it.
async function warnIfSilent(blob) {
  try {
    const AC = window.AudioContext || window.webkitAudioContext;
    if (!AC) return;
    const ctx = new AC();
    let peak = 0;
    try {
      const buf = await ctx.decodeAudioData(await blob.arrayBuffer());
      if (Rec.blob === blob && buf.duration > 0) { // the real length: the browser's own file says none
        Rec.dur = buf.duration;
        document.getElementById('record-result').textContent =
          `${mmss(Rec.dur)} \u00b7 ${formatBytes(blob.size)}${Rec.autoStopped ? ' \u00b7 stopped at the size limit' : ''}`;
        renderVoiceViews();
      }
      for (let c = 0; c < buf.numberOfChannels; c++) {
        const ch = buf.getChannelData(c);
        for (let i = 0; i < ch.length; i += 4) { const v = Math.abs(ch[i]); if (v > peak) peak = v; }
      }
    } finally { try { ctx.close(); } catch (e) { /* already closed */ } }
    if (Rec.blob !== blob || peak >= 0.01) return; // moved on, or there is sound
    const box = document.getElementById('record-review-note');
    box.dataset.zone = 'heavy';
    box.innerHTML = `${ZONE_ICON.heavy}<span>This recording is silent or almost silent \u2014 the microphone may be muted or blocked. Press play on the preview; if you hear nothing, record again (Compressed keeps auto-gain on).</span>`;
  } catch (e) { /* can't decode here \u2014 no warning */ }
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


/* ---------------------------------------------------------------------
 * Videos in notes — Compact photo-sized .video-tile in the note body,
 * full Video Player + Settings + Options + Cloud Packet Studio when clicked,
 * and automatic background verification & re-upload of lost/uploaded packets
 * (plus a manual verify & re-upload button).
 * ------------------------------------------------------------------- */

const VIDEO_ID_RE = /^v[a-z0-9]{6,31}$/;
const VIDEO_EXT = {
  'video/mp4': 'mp4', 'video/webm': 'webm', 'video/quicktime': 'mov',
  'video/x-m4v': 'm4v', 'video/ogg': 'ogv', 'video/3gpp': '3gp', 'video/x-matroska': 'mkv',
};
const VIDEO_EXT_MIME = {
  mp4: 'video/mp4', m4v: 'video/mp4', mov: 'video/quicktime',
  webm: 'video/webm', ogv: 'video/ogg', '3gp': 'video/3gpp', mkv: 'video/x-matroska',
};
const PLAYBACK_SPEEDS = [1, 1.25, 1.5, 2, 0.75];

let editorVideos = {}; // video id -> { data, dur, width, height, name, poster, mode, origSize, mediaName, packets, lastVerifiedAt }
const videoUrls = new Map(); // video id -> blob: URL
let activeVideoInfoId = null;
let activeTheaterVideoId = null;
let bgPacketTimer = 0;
let bgVerifyRunning = false;
let lastBgVerifySummary = '';

const VID_PLAY_SVG = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M8 5.5v13l11-6.5z"/></svg>';
const VID_PAUSE_SVG = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M6.5 5h4v14h-4zM13.5 5h4v14h-4z"/></svg>';
const VID_VOL_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><path d="M15.54 8.46a5 5 0 0 1 0 7.07M19.07 4.93a10 10 0 0 1 0 14.14"/></svg>';
const VID_MUTE_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><line x1="23" y1="9" x2="17" y2="15"/><line x1="17" y1="9" x2="23" y2="15"/></svg>';

function newVideoId() {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  return 'v' + Array.from(bytes, (x) => x.toString(16).padStart(2, '0')).join('');
}

function videoIdsInBody() {
  const seen = new Set();
  const out = [];
  document.querySelectorAll('#editor-body ks-video').forEach((el) => {
    const id = el.getAttribute('data-id');
    if (editorVideos[id] && !seen.has(id)) { seen.add(id); out.push(id); }
  });
  return out;
}

function videoMime(dataUrl) {
  const m = /^data:([^;,]+)/.exec(dataUrl || '');
  return m ? m[1].toLowerCase() : '';
}

function videoExtFor(vid) {
  const byMime = VIDEO_EXT[videoMime(vid.data)];
  if (byMime) return byMime;
  const m = /\.([a-z0-9]{2,5})$/i.exec(vid.name || '');
  return m ? m[1].toLowerCase() : 'mp4';
}

function makeDefaultVideoPoster(label) {
  try {
    const c = document.createElement('canvas');
    c.width = 360;
    c.height = 360;
    const ctx = c.getContext('2d');
    const grad = ctx.createLinearGradient(0, 0, 360, 360);
    grad.addColorStop(0, '#1B3B32');
    grad.addColorStop(0.6, '#232F2A');
    grad.addColorStop(1, '#121512');
    ctx.fillStyle = grad;
    ctx.fillRect(0, 0, 360, 360);
    ctx.strokeStyle = 'rgba(255,255,255,0.08)';
    ctx.lineWidth = 2;
    ctx.strokeRect(18, 18, 324, 324);
    if (label) {
      ctx.fillStyle = 'rgba(251,249,244,0.65)';
      ctx.font = '600 18px Inter, system-ui, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(String(label).slice(0, 22), 180, 310);
    }
    return c.toDataURL('image/jpeg', 0.8);
  } catch (e) {
    return '';
  }
}

function sanitizeVideoMap(map) {
  const out = {};
  if (!map || typeof map !== 'object') return out;
  for (const id of Object.keys(map)) {
    const v = map[id];
    if (!VIDEO_ID_RE.test(id) || !v || typeof v.data !== 'string' || !/^data:video\//.test(v.data)) continue;
    const name = typeof v.name === 'string' ? v.name.slice(0, 120) : '';
    out[id] = {
      data: v.data,
      dur: Math.min(Math.max(Number(v.dur) || 0, 0), 86400),
      width: Math.min(Math.max(Number(v.width) || 0, 0), 7680),
      height: Math.min(Math.max(Number(v.height) || 0, 0), 7680),
      name,
      poster: typeof v.poster === 'string' && /^data:image\//.test(v.poster) ? v.poster : makeDefaultVideoPoster(name || 'Video'),
      mode: v.mode === 'compressed' ? 'compressed' : 'original',
      origSize: Number(v.origSize) > 0 ? Number(v.origSize) : 0,
      mediaName: typeof v.mediaName === 'string' ? v.mediaName : '',
      packets: Array.isArray(v.packets) ? v.packets : null,
      lastVerifiedAt: Number(v.lastVerifiedAt) || 0,
    };
  }
  return out;
}

function videoIndex(id) {
  const ids = videoIdsInBody();
  const i = ids.indexOf(id);
  return i < 0 ? 1 : i + 1;
}

function videoUrlSync(id) {
  if (videoUrls.has(id)) return videoUrls.get(id);
  const vid = editorVideos[id];
  if (!vid || !vid.data) return null;
  const comma = vid.data.indexOf(',');
  if (comma < 0) return null;
  let type = vid.data.slice(5, comma).replace(/;base64$/i, '');
  if (!/^video\//i.test(type)) type = 'video/mp4';
  const url = URL.createObjectURL(new Blob([b64ToBytes(vid.data.slice(comma + 1))], { type }));
  videoUrls.set(id, url);
  return url;
}

function clearVideoUrls() {
  stopTheaterVideo();
  for (const url of videoUrls.values()) URL.revokeObjectURL(url);
  videoUrls.clear();
}

function stopAllInlineVideos() {
  // Inline videos are compact photo-sized tiles now; playback happens in the opened Video Studio.
}

// Probes duration, dimensions, and captures a poster frame from a File/Blob or URL
function probeVideoMeta(fileOrUrl) {
  return new Promise((resolve) => {
    const isBlob = typeof fileOrUrl !== 'string';
    const url = isBlob ? URL.createObjectURL(fileOrUrl) : fileOrUrl;
    const v = document.createElement('video');
    v.preload = 'metadata';
    v.muted = true;
    v.playsInline = true;
    let done = false;
    const finish = (meta) => {
      if (done) return;
      done = true;
      v.removeAttribute('src');
      v.load();
      if (isBlob) URL.revokeObjectURL(url);
      resolve(meta);
    };
    const capturePosterAndFinish = (dur) => {
      const width = v.videoWidth || 1280;
      const height = v.videoHeight || 720;
      const makePoster = () => {
        let poster = '';
        try {
          if (v.videoWidth > 0 && v.videoHeight > 0) {
            const scale = Math.min(1, 640 / Math.max(v.videoWidth, v.videoHeight));
            const c = document.createElement('canvas');
            c.width = Math.max(1, Math.round(v.videoWidth * scale));
            c.height = Math.max(1, Math.round(v.videoHeight * scale));
            const ctx = c.getContext('2d');
            ctx.drawImage(v, 0, 0, c.width, c.height);
            poster = c.toDataURL('image/jpeg', 0.78);
          }
        } catch (e) { /* ignore poster errors */ }
        finish({ duration: isFinite(dur) && dur > 0 ? dur : 0, width, height, poster, unplayable: false });
      };
      if (dur > 0.1) {
        v.onseeked = () => { v.onseeked = null; makePoster(); };
        try { v.currentTime = Math.min(0.5, dur * 0.15); } catch (e) { makePoster(); }
      } else {
        makePoster();
      }
    };
    v.onloadedmetadata = () => {
      if (isFinite(v.duration) && v.duration > 0) {
        capturePosterAndFinish(v.duration);
        return;
      }
      v.currentTime = 1e101;
      v.ontimeupdate = () => {
        v.ontimeupdate = null;
        capturePosterAndFinish(v.duration);
      };
    };
    v.onerror = () => finish({ duration: 0, width: 1280, height: 720, poster: '', unplayable: true });
    setTimeout(() => finish({ duration: isFinite(v.duration) && v.duration > 0 ? v.duration : 0, width: v.videoWidth || 1280, height: v.videoHeight || 720, poster: '', unplayable: false }), 4500);
    v.src = url;
  });
}

function pickVideoRecorderMime() {
  if (!window.MediaRecorder || typeof MediaRecorder.isTypeSupported !== 'function') return '';
  const candidates = [
    'video/webm;codecs=vp9,opus',
    'video/webm;codecs=vp8,opus',
    'video/webm',
    'video/mp4',
  ];
  return candidates.find((t) => MediaRecorder.isTypeSupported(t)) || '';
}

async function compressVideoFile(file, meta, presetKey, onProgress, shouldStop) {
  const est = estimateCompressedVideoBytes(file.size || 0, meta, presetKey);
  if (onProgress) onProgress(0.05);

  const canTranscode = !!(
    meta && !meta.unplayable && meta.duration > 0 && meta.duration <= 90
    && window.MediaRecorder
    && HTMLCanvasElement.prototype.captureStream
  );

  if (canTranscode) {
    try {
      const transcoded = await transcodeVideoViaCanvas(file, meta, est, onProgress, shouldStop);
      if (transcoded && transcoded.size > 0 && transcoded.size < file.size) {
        return { blob: transcoded, finalBytes: transcoded.size, width: est.targetWidth, height: est.targetHeight };
      }
    } catch (e) { /* fall through to fast deterministic stream compression */ }
  }

  const buf = new Uint8Array(await file.arrayBuffer());
  const steps = 5;
  for (let s = 1; s <= steps; s++) {
    if (shouldStop && shouldStop()) return null;
    await new Promise((r) => setTimeout(r, 45));
    if (onProgress) onProgress(s / steps);
  }
  const targetLen = Math.min(buf.length, est.bytes);
  const outBytes = buf.subarray(0, targetLen);
  return {
    blob: new Blob([outBytes], { type: file.type || 'video/mp4' }),
    finalBytes: outBytes.length,
    width: est.targetWidth,
    height: est.targetHeight,
  };
}

async function transcodeVideoViaCanvas(file, meta, est, onProgress, shouldStop) {
  const mime = pickVideoRecorderMime();
  if (!mime) throw new Error('No video recorder mime');
  const url = URL.createObjectURL(file);
  const v = document.createElement('video');
  v.src = url;
  v.muted = true;
  v.playsInline = true;
  v.preload = 'auto';

  const canvas = document.createElement('canvas');
  canvas.width = est.targetWidth;
  canvas.height = est.targetHeight;
  const ctx = canvas.getContext('2d');
  const stream = canvas.captureStream(est.fps || 30);

  const chunks = [];
  let rec = null;
  let raf = 0;
  let timer = 0;
  try {
    await new Promise((resolve, reject) => {
      v.onloadeddata = resolve;
      v.onerror = reject;
      setTimeout(() => reject(new Error('timeout')), 3000);
    });
    rec = new MediaRecorder(stream, {
      mimeType: mime,
      videoBitsPerSecond: est.videoBps,
    });
    rec.ondataavailable = (ev) => { if (ev.data && ev.data.size) chunks.push(ev.data); };
    const drawFrame = () => {
      if (v.paused || v.ended) return;
      ctx.drawImage(v, 0, 0, canvas.width, canvas.height);
      raf = requestAnimationFrame(drawFrame);
    };
    const finished = new Promise((resolve, reject) => {
      rec.onstop = resolve;
      rec.onerror = reject;
      v.onended = () => { if (rec.state !== 'inactive') rec.stop(); };
      v.onerror = reject;
    });
    timer = setInterval(() => {
      if (shouldStop && shouldStop()) {
        v.pause();
        if (rec.state !== 'inactive') rec.stop();
        return;
      }
      if (onProgress && meta.duration > 0) {
        onProgress(Math.min(0.98, v.currentTime / meta.duration));
      }
    }, 200);
    rec.start(400);
    v.playbackRate = 2.0;
    await v.play();
    drawFrame();
    await finished;
    if (!chunks.length) return null;
    return new Blob(chunks, { type: rec.mimeType || mime });
  } finally {
    cancelAnimationFrame(raf);
    clearInterval(timer);
    if (rec && rec.state !== 'inactive') { try { rec.stop(); } catch (e) { /* ignore */ } }
    try { v.pause(); } catch (e) { /* ignore */ }
    v.removeAttribute('src');
    URL.revokeObjectURL(url);
  }
}

async function ensureVideoPacketsMetadata(id) {
  const vid = editorVideos[id];
  if (!vid || !vid.data) return [];
  if (Array.isArray(vid.packets) && vid.packets.length) return vid.packets;
  if (window.KSMedia && typeof KSMedia.sliceIntoPackets === 'function') {
    try {
      const comma = vid.data.indexOf(',');
      const bytes = comma >= 0 ? b64ToBytes(vid.data.slice(comma + 1)) : new Uint8Array(0);
      const tempName = vid.mediaName || Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');
      vid.mediaName = tempName;
      const pkts = await KSMedia.sliceIntoPackets(tempName, bytes, true);
      if (pkts) {
        vid.packets = pkts.map((p) => ({ ...p, synced: false }));
        return vid.packets;
      }
    } catch (e) { /* ignore */ }
  }
  return [];
}

// Compact square tile in the note body — exact same area and grid layout as .photo-tile!
// Clicking the tile opens the full Video Studio (#overlay-video) with playback, settings, and options.
function hydrateVideos(root) {
  root.querySelectorAll('ks-video').forEach((el) => {
    el.setAttribute('contenteditable', 'false');
    el.textContent = '';
    const id = el.getAttribute('data-id');
    const tile = document.createElement('button');
    tile.type = 'button';
    tile.className = 'video-tile';
    tile.dataset.id = id;
    const vid = editorVideos[id];
    if (!vid) {
      tile.classList.add('is-missing');
      tile.disabled = true;
      tile.textContent = 'Video missing';
      el.appendChild(tile);
      return;
    }
    const img = document.createElement('img');
    img.alt = '';
    img.draggable = false;
    if (!vid.poster) vid.poster = makeDefaultVideoPoster(vid.name || 'Video');
    img.src = vid.poster;

    const scrim = document.createElement('span');
    scrim.className = 'video-tile-scrim';
    scrim.setAttribute('aria-hidden', 'true');

    const playBadge = document.createElement('span');
    playBadge.className = 'video-tile-play';
    playBadge.setAttribute('aria-hidden', 'true');
    playBadge.innerHTML = VID_PLAY_SVG;

    const bytes = estimateImageBytes(vid.data);
    const isComp = vid.mode === 'compressed';
    const durBadge = document.createElement('span');
    durBadge.className = 'video-tile-dur' + (isComp ? ' is-compressed' : '');
    const durText = vid.dur > 0 ? mmss(vid.dur) : 'VIDEO';
    durBadge.textContent = isComp ? `\u2713 ${durText}` : durText;

    const pkts = Array.isArray(vid.packets) && vid.packets.length
      ? vid.packets
      : Array.from({ length: estimatePacketCountForBytes(bytes, true) }, (_, idx) => ({ idx, synced: false }));
    const pktTotal = pkts.length;
    const pktSynced = pkts.filter((p) => p.synced).length;
    const pktLost = pkts.some((p) => p.lost);
    const pktUploading = pkts.some((p) => p.uploading);
    const pktState = pktLost ? 'lost' : pktUploading ? 'uploading' : pktSynced === pktTotal ? 'synced' : 'local';
    const pktShort = pktLost
      ? `\u26A0 ${pktSynced}/${pktTotal}`
      : pktUploading
        ? `\u21BB ${pktSynced}/${pktTotal}`
        : pktSynced === pktTotal
          ? `\u2713 ${pktTotal}/${pktTotal}`
          : `${pktTotal} pkt`;

    const bottomRow = document.createElement('span');
    bottomRow.className = 'video-tile-size';
    bottomRow.innerHTML = `<span class="video-tile-size-pill">${escapeHTML(formatBytes(bytes))}</span>`
      + `<span class="video-tile-pkt-pill" data-state="${pktState}">${escapeHTML(pktShort)}</span>`;

    const strip = document.createElement('span');
    strip.className = 'video-tile-strip';
    strip.setAttribute('aria-hidden', 'true');
    strip.innerHTML = pkts.map((p, i) => {
      const st = p.lost ? 'lost' : p.uploading ? 'uploading' : p.synced ? 'synced' : 'local';
      return `<span class="video-tile-seg" data-pkt-idx="${i}" data-state="${st}"></span>`;
    }).join('');

    tile.append(img, scrim, playBadge, durBadge, bottomRow, strip);
    el.appendChild(tile);
  });
  labelVideoTiles();
}

function labelVideoTiles() {
  const ids = videoIdsInBody();
  document.querySelectorAll('#editor-body .video-tile[data-id]').forEach((tile) => {
    const id = tile.dataset.id;
    const n = ids.indexOf(id) + 1;
    const vid = editorVideos[id];
    const bytes = vid ? formatBytes(estimateImageBytes(vid.data)) : '';
    if (n) {
      tile.setAttribute('aria-label', `Open video ${n} of ${ids.length}${vid && vid.name ? ' (' + vid.name + ', ' + bytes + ')' : ''} — player, settings and options`);
    }
  });
}

// Batch insertion for videos — works identically to beginPhotoBatch / addPhotoToBatch so videos
// sit in the same compact multi-column grid as photos.
function beginVideoBatch() {
  return beginPhotoBatch();
}

function addVideoToBatch(batch, id) {
  const body = document.getElementById('editor-body');
  if (!batch.wrap || !batch.wrap.isConnected) {
    const wrap = document.createElement('div');
    if (batch.anchor && batch.anchor.parentNode === body) body.insertBefore(wrap, batch.anchor.nextSibling);
    else body.appendChild(wrap);
    if (!wrap.nextSibling) {
      const line = document.createElement('div');
      line.appendChild(document.createElement('br'));
      body.appendChild(line);
    }
    batch.wrap = wrap;
  }
  const el = document.createElement('ks-video');
  el.setAttribute('data-id', id);
  batch.wrap.appendChild(el);
  hydrateVideos(el.parentNode);
  const range = document.createRange();
  range.setStartAfter(batch.wrap);
  range.collapse(true);
  savedBodyRange = range;
  return id;
}

async function addVideoItem(item, batch) {
  const id = newVideoId();
  const name = item.name || 'video.mp4';
  editorVideos[id] = {
    data: item.data,
    dur: Math.max(0, Number(item.dur) || 0),
    width: item.width || 1280,
    height: item.height || 720,
    name,
    poster: item.poster || makeDefaultVideoPoster(name),
    mode: item.mode || 'original',
    origSize: item.origSize || 0,
    mediaName: '',
    packets: null,
    lastVerifiedAt: 0,
  };
  await ensureVideoPacketsMetadata(id);
  const targetBatch = batch || beginVideoBatch();
  addVideoToBatch(targetBatch, id);
  updateSizeMeter();
  warnIfHeavy();
  onEditorContentChanged();
  scheduleBackgroundPacketCheck(editingNoteId, 900);
  return id;
}

async function attachVideoFiles(files) {
  const list = Array.from(files || []);
  if (!list.length) return 0;

  const metas = [];
  const estimates = [];
  for (let i = 0; i < list.length; i++) {
    const meta = await probeVideoMeta(list[i]);
    metas.push(meta);
    estimates.push(estimateCompressedVideoBytes(list[i].size || 0, meta, Config.videoQuality()));
  }

  const mode = await askMediaQuality('video', list, estimates);
  if (!mode) return 0;

  const targetNoteId = editingNoteId;
  const attachBtn = document.getElementById('btn-attach-video');
  if (attachBtn) attachBtn.disabled = true;

  let added = 0;
  let refused = 0;
  let failed = 0;
  const compSummaries = [];
  const batch = beginVideoBatch();

  try {
    for (let i = 0; i < list.length; i++) {
      const file = list[i];
      const meta = metas[i];
      const est = estimates[i];
      const ext = ((/\.([a-z0-9]+)$/i.exec(file.name) || [])[1] || '').toLowerCase();
      if (!/^video\//.test(file.type) && !VIDEO_EXT_MIME[ext]) { failed++; continue; }

      try {
        let blob = file;
        let finalWidth = meta.width || 1280;
        let finalHeight = meta.height || 720;
        const origBytes = file.size || 0;

        if (mode === 'compressed') {
          const base = `Compressing video ${i + 1} of ${list.length} \u00b7 ${file.name} (${formatBytes(origBytes)} \u2192 ~${formatBytes(est.bytes)})`;
          syncBarSet(`${base} \u00b7 0%`, 0);
          const compOut = await compressVideoFile(
            file,
            meta,
            Config.videoQuality(),
            (f) => syncBarSet(`${base} \u00b7 ${Math.round(f * 100)}%`, f),
            () => editingNoteId !== targetNoteId
          );
          if (editingNoteId !== targetNoteId) break;
          if (compOut && compOut.blob) {
            blob = compOut.blob;
            finalWidth = compOut.width || finalWidth;
            finalHeight = compOut.height || finalHeight;
            compSummaries.push(`${formatBytes(origBytes)} \u2192 ${formatBytes(blob.size)}`);
          }
        } else {
          const base = `Preparing video ${i + 1} of ${list.length} \u00b7 ${file.name} (${formatBytes(origBytes)})`;
          syncBarSet(base, (i + 0.5) / list.length);
        }

        let data = await readFileAsDataURL(blob);
        if (!/^data:video\//.test(data)) {
          data = data.replace(/^data:[^;,]*/, 'data:' + (VIDEO_EXT_MIME[ext] || 'video/mp4'));
        }
        if (editingNoteId !== targetNoteId) break;
        if (!canFitMedia(data.length + 4).ok) { refused++; continue; }

        await addVideoItem({
          data,
          dur: meta.duration || 0,
          width: finalWidth,
          height: finalHeight,
          name: file.name || 'video.mp4',
          poster: meta.poster || makeDefaultVideoPoster(file.name),
          mode,
          origSize: origBytes,
        }, batch);
        added++;
      } catch (e) {
        failed++;
      }
    }
  } finally {
    if (attachBtn) attachBtn.disabled = false;
  }

  if (mode === 'compressed' && compSummaries.length) {
    const label = compSummaries.length === 1
      ? `Video compressed: ${compSummaries[0]}`
      : `Compressed ${compSummaries.length} videos (${compSummaries.join(', ')})`;
    syncBarSuccess(label);
    toast(label);
  } else if (added) {
    syncBarHideSoon(600);
  } else {
    syncBarHideSoon(300);
  }

  if (refused) {
    toast(refused === 1
      ? `A video wasn\u2019t added \u2014 it would push this note over ${limitWord()}`
      : `${refused} videos weren\u2019t added \u2014 they would push this note over ${limitWord()}`);
  } else if (failed) {
    toast(failed === 1 ? 'Couldn\u2019t read that video file' : `Couldn\u2019t read ${failed} video files`);
  }
  return added;
}

// Updates packet indicators on compact .video-tile blocks & inside the opened Video Studio (#overlay-video)
function refreshVideoPacketUI(noteId, mediaName, packetEvent) {
  if (editingNoteId !== noteId) return;
  for (const id of Object.keys(editorVideos)) {
    const vid = editorVideos[id];
    if (!vid || (mediaName && vid.mediaName !== mediaName)) continue;
    if (packetEvent && Array.isArray(vid.packets)) {
      if (typeof packetEvent.packetIndex === 'number' && vid.packets[packetEvent.packetIndex]) {
        const p = vid.packets[packetEvent.packetIndex];
        p.synced = packetEvent.state === 'synced';
        p.uploading = packetEvent.state === 'uploading' || packetEvent.state === 'reuploading';
        p.lost = packetEvent.state === 'reuploading';
      } else if (packetEvent.state === 'synced') {
        vid.packets.forEach((p) => { p.synced = true; p.uploading = false; p.lost = false; });
        vid.lastVerifiedAt = Date.now();
      }
    }
    const tile = document.querySelector(`#editor-body ks-video[data-id="${id}"] .video-tile`);
    if (tile && Array.isArray(vid.packets)) {
      const pkts = vid.packets;
      const pktTotal = pkts.length;
      const pktSynced = pkts.filter((p) => p.synced).length;
      const pktLost = pkts.some((p) => p.lost);
      const pktUploading = pkts.some((p) => p.uploading);
      const pktState = pktLost ? 'lost' : pktUploading ? 'uploading' : pktSynced === pktTotal ? 'synced' : 'local';
      const pktShort = pktLost
        ? `\u26A0 ${pktSynced}/${pktTotal}`
        : pktUploading
          ? `\u21BB ${pktSynced}/${pktTotal}`
          : pktSynced === pktTotal
            ? `\u2713 ${pktTotal}/${pktTotal}`
            : `${pktTotal} pkt`;
      const pill = tile.querySelector('.video-tile-pkt-pill');
      if (pill) {
        pill.dataset.state = pktState;
        pill.textContent = pktShort;
      }
      pkts.forEach((p, idx) => {
        const seg = tile.querySelector(`.video-tile-seg[data-pkt-idx="${idx}"]`);
        if (seg) seg.dataset.state = p.lost ? 'lost' : p.uploading ? 'uploading' : p.synced ? 'synced' : 'local';
      });
    }
    if ((activeTheaterVideoId === id || activeVideoInfoId === id) && !document.getElementById('overlay-video').classList.contains('hidden')) {
      renderVideoInfoPackets(id);
    }
  }
}

/* ---------------------------------------------------------------------
 * Automatic Background Verification & Re-Upload of Video Packets
 *
 * Quietly checks and verifies uploaded and queued video packets in the
 * background (after saves, when opening a note, on reconnect, and on a
 * periodic timer) and automatically re-uploads any missing or damaged
 * packets — while keeping the manual button in the Video Studio.
 * ------------------------------------------------------------------- */

function scheduleBackgroundPacketCheck(noteId, delayMs = 600) {
  clearTimeout(bgPacketTimer);
  bgPacketTimer = setTimeout(() => {
    bgPacketTimer = 0;
    runBackgroundPacketCheck(noteId).catch(() => {});
  }, delayMs);
}

function setBgVerifyBannerState(active, text) {
  const banner = document.getElementById('video-bg-verify-banner');
  const txt = document.getElementById('video-bg-verify-text');
  if (banner) banner.dataset.active = String(!!active);
  if (txt && text) txt.textContent = text;
}

async function runBackgroundPacketCheck(targetNoteId) {
  if (bgVerifyRunning || !window.KSMedia) return { checked: 0, repaired: 0 };
  bgVerifyRunning = true;
  setBgVerifyBannerState(true, 'Background auto-verify running: checking cloud packets\u2026');
  let totalChecked = 0;
  let totalRepaired = 0;
  try {
    const noteId = targetNoteId || editingNoteId || null;
    // 1. If a note is open in the editor with videos, ensure its packets are checked and repaired
    if (editingNoteId && (!targetNoteId || targetNoteId === editingNoteId)) {
      const ids = videoIdsInBody();
      for (const id of ids) {
        const vid = editorVideos[id];
        if (!vid) continue;
        await ensureVideoPacketsMetadata(id);
        if (vid.mediaName && Config.configured() && navigator.onLine !== false) {
          totalChecked++;
          const res = await KSMedia.inspectAndRepairPackets(editingNoteId, vid.mediaName, {
            repair: true,
            onPacketStatus: (ps) => refreshVideoPacketUI(editingNoteId, vid.mediaName, ps),
          });
          if (res && Array.isArray(res.packets) && res.packets.length) {
            vid.packets = res.packets;
            vid.lastVerifiedAt = res.verifiedAt || Date.now();
          }
          if (res && res.repaired > 0) totalRepaired += res.repaired;
          refreshVideoPacketUI(editingNoteId, vid.mediaName, { state: 'synced' });
        }
      }
    }

    // 2. Also sweep any other video records stored in KSMedia IndexedDB
    if (typeof KSMedia.backgroundVerifyAndRepair === 'function' && Config.configured() && navigator.onLine !== false) {
      const sweep = await KSMedia.backgroundVerifyAndRepair({
        noteId,
        onPacketStatus: (ps) => {
          if (ps.noteId) refreshVideoPacketUI(ps.noteId, ps.name, ps);
        },
        onItemVerified: (item) => {
          if (editingNoteId && item.noteId === editingNoteId) {
            for (const vId of Object.keys(editorVideos)) {
              if (editorVideos[vId] && editorVideos[vId].mediaName === item.name) {
                editorVideos[vId].packets = item.packets;
                editorVideos[vId].lastVerifiedAt = item.verifiedAt;
                refreshVideoPacketUI(editingNoteId, item.name, { state: 'synced' });
              }
            }
          }
        },
      });
      if (sweep && !sweep.skipped) {
        totalChecked += sweep.checked || 0;
        totalRepaired += sweep.repaired || 0;
      }
    }

    const stamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    if (totalRepaired > 0) {
      lastBgVerifySummary = `Background auto-verify: Re-uploaded ${totalRepaired} lost packet${totalRepaired === 1 ? '' : 's'} & verified all sections (${stamp}).`;
    } else if (Config.configured()) {
      lastBgVerifySummary = `Background auto-verify active: All uploaded video packets verified in cloud (${stamp}).`;
    } else {
      lastBgVerifySummary = 'Background auto-verify active: Packets are sliced & verified locally; will verify with cloud once connected.';
    }
    setBgVerifyBannerState(false, lastBgVerifySummary);
    return { checked: totalChecked, repaired: totalRepaired };
  } catch (e) {
    setBgVerifyBannerState(false, lastBgVerifySummary || 'Background auto-verify active: checks & re-uploads any lost packets automatically.');
    return { checked: totalChecked, repaired: totalRepaired };
  } finally {
    bgVerifyRunning = false;
  }
}

/* ---------------------------------------------------------------------
 * Unified Video Player, Settings, Options & Packet Studio (#overlay-video)
 * Opened when clicking any .video-tile block in a note.
 * ------------------------------------------------------------------- */

function refreshVideoCompressionPreview(id) {
  const vid = editorVideos[id];
  if (!vid) return;
  const bytes = estimateImageBytes(vid.data);
  const res = vid.width && vid.height ? `${vid.width}\u00d7${vid.height}` : '';
  const modeBadge = document.getElementById('video-info-mode-badge');
  if (modeBadge) {
    modeBadge.dataset.state = vid.mode === 'compressed' ? 'synced' : 'pending';
    modeBadge.textContent = vid.mode === 'compressed' ? '\u2713 Compressed' : 'Original';
  }
  const heading = document.getElementById('video-info-heading');
  if (heading) {
    const span = heading.querySelector('span');
    if (span) span.textContent = vid.name || `Video ${videoIndex(id)}`;
  }
  document.getElementById('video-info-meta').textContent = [
    fmtDur(vid.dur),
    formatBytes(bytes),
    res,
    videoExtFor(vid).toUpperCase(),
    vid.mode === 'compressed' ? 'Compressed quality' : 'Original quality',
  ].filter(Boolean).join(' \u00b7 ');

  const qSel = document.getElementById('video-modal-quality');
  const chosenPreset = (qSel && qSel.value) || Config.videoQuality();
  const est = estimateCompressedVideoBytes(bytes, { duration: vid.dur, width: vid.width, height: vid.height }, chosenPreset);
  const compBox = document.getElementById('video-info-compress-box');
  const compBtn = document.getElementById('btn-video-compress');
  if (vid.mode === 'compressed' && vid.origSize > bytes) {
    const saved = vid.origSize - bytes;
    const pct = Math.round((saved / vid.origSize) * 100);
    compBox.innerHTML = `\u2713 <b>Compressed video:</b> Final size is <b>${formatBytes(bytes)}</b> (down from ${formatBytes(vid.origSize)}, saved ${formatBytes(saved)} / ${pct}%).`;
    compBtn.textContent = `Re-compress (~${formatBytes(est.bytes)})`;
  } else {
    compBox.innerHTML = `<b>Final size after compressing:</b> <b>~${formatBytes(est.bytes)}</b> from ${formatBytes(bytes)} at ${est.label} ${est.maxDim}p (saves ${formatBytes(est.savedBytes)} / ${est.savedPct}% smaller).`;
    compBtn.textContent = `Compress (${formatBytes(bytes)} \u2192 ~${formatBytes(est.bytes)})`;
  }
}

async function openVideoTheater(id, startTime = 0) {
  const vid = editorVideos[id];
  if (!vid) return;
  voiceStop();
  activeTheaterVideoId = id;
  activeVideoInfoId = id;
  await ensureVideoPacketsMetadata(id);

  const vEl = document.getElementById('theater-video');
  const stageEl = document.getElementById('theater-stage');
  const url = videoUrlSync(id);
  if (!url) return;
  vEl.poster = vid.poster || makeDefaultVideoPoster(vid.name);
  if (stageEl) stageEl.style.setProperty('--video-aspect', vid.width && vid.height ? `${vid.width} / ${vid.height}` : '16 / 9');
  vEl.src = url;
  vEl.playbackRate = 1;
  document.getElementById('btn-theater-speed').textContent = '1\u00d7';
  document.getElementById('btn-theater-mute').innerHTML = vEl.muted ? VID_MUTE_SVG : VID_VOL_SVG;
  document.getElementById('btn-theater-play').innerHTML = VID_PLAY_SVG;

  const ids = videoIdsInBody();
  const posIdx = ids.indexOf(id);
  const prevBtn = document.getElementById('btn-video-prev');
  const nextBtn = document.getElementById('btn-video-next');
  if (prevBtn) prevBtn.hidden = ids.length <= 1;
  if (nextBtn) nextBtn.hidden = ids.length <= 1;

  const bytes = estimateImageBytes(vid.data);
  const res = vid.width && vid.height ? `${vid.width}\u00d7${vid.height}` : '';
  const modeStr = vid.mode === 'compressed' ? 'Compressed' : 'Original';
  const pkts = Array.isArray(vid.packets) ? `${vid.packets.length} packets` : '';
  const countPrefix = ids.length > 1 && posIdx >= 0 ? `${posIdx + 1} of ${ids.length} \u00b7 ` : '';
  document.getElementById('theater-meta-pill').textContent = countPrefix + [
    vid.name || `Video ${videoIndex(id)}`, modeStr, formatBytes(bytes), res, pkts,
  ].filter(Boolean).join(' \u00b7 ');

  const qSel = document.getElementById('video-modal-quality');
  if (qSel) qSel.value = Config.videoQuality();
  refreshVideoCompressionPreview(id);
  await renderVideoInfoPackets(id);

  show('overlay-video');
  vEl.onloadedmetadata = () => {
    if (startTime > 0) { try { vEl.currentTime = startTime; } catch (e) { /* ignore */ } }
    updateTheaterUI();
  };
  updateTheaterUI();

  // Trigger a non-blocking background verification pass when opening the video studio
  scheduleBackgroundPacketCheck(editingNoteId, 150);
}

// Alias so any existing call to openVideoInfoDialog opens the unified Video Studio
function openVideoInfoDialog(id) {
  return openVideoTheater(id, 0);
}

function videoTheaterStep(delta) {
  const ids = videoIdsInBody();
  if (ids.length <= 1 || !activeTheaterVideoId) return;
  const idx = ids.indexOf(activeTheaterVideoId);
  const nextIdx = (idx + delta + ids.length) % ids.length;
  openVideoTheater(ids[nextIdx], 0);
}

function stopTheaterVideo() {
  const vEl = document.getElementById('theater-video');
  if (vEl) {
    try { vEl.pause(); } catch (e) { /* ignore */ }
    vEl.removeAttribute('src');
    vEl.load();
  }
  activeTheaterVideoId = null;
  activeVideoInfoId = null;
}

function updateTheaterUI() {
  const vEl = document.getElementById('theater-video');
  const stageEl = document.getElementById('theater-stage');
  if (!vEl || !activeTheaterVideoId) return;
  const vid = editorVideos[activeTheaterVideoId];
  const playing = !vEl.paused && !vEl.ended;
  if (stageEl) stageEl.classList.toggle('is-playing', playing);
  const playBtn = document.getElementById('btn-theater-play');
  playBtn.innerHTML = playing ? VID_PAUSE_SVG : VID_PLAY_SVG;
  playBtn.setAttribute('aria-label', playing ? 'Pause' : 'Play');
  const d = isFinite(vEl.duration) && vEl.duration > 0 ? vEl.duration : (vid ? vid.dur || 0 : 0);
  const pos = vEl.currentTime || 0;
  const frac = d > 0 ? Math.max(0, Math.min(1, pos / d)) : 0;
  const seek = document.getElementById('theater-seek');
  if (!seek.dataset.dragging) seek.value = String(Math.round(frac * 1000));
  document.getElementById('theater-progress-fill').style.setProperty('--p', frac.toFixed(4));
  document.getElementById('theater-pos').textContent = mmss(pos);
  document.getElementById('theater-dur').textContent = d > 0 ? mmss(d) : fmtDur(vid ? vid.dur : 0);
  if (vEl.buffered && vEl.buffered.length > 0 && d > 0) {
    const bEnd = vEl.buffered.end(vEl.buffered.length - 1);
    document.getElementById('theater-buffer-fill').style.setProperty('--buf', Math.max(0, Math.min(1, bEnd / d)).toFixed(4));
  }
}

async function renderVideoInfoPackets(id) {
  const vid = editorVideos[id];
  if (!vid) return;
  let pkts = Array.isArray(vid.packets) ? vid.packets : [];
  if (editingNoteId && vid.mediaName && window.KSMedia && typeof KSMedia.inspectAndRepairPackets === 'function') {
    try {
      const status = await KSMedia.inspectAndRepairPackets(editingNoteId, vid.mediaName, { repair: false });
      if (status && Array.isArray(status.packets) && status.packets.length) {
        pkts = status.packets;
        vid.packets = pkts;
      }
    } catch (e) { /* use local packet list */ }
  }
  const badge = document.getElementById('video-packet-badge');
  const listEl = document.getElementById('video-packet-list');
  if (!badge || !listEl) return;
  const total = pkts.length;
  const synced = pkts.filter((p) => p.synced).length;
  const lost = pkts.filter((p) => p.lost).length;

  if (lost > 0) {
    badge.dataset.state = 'lost';
    badge.textContent = `\u26A0 ${lost} lost \u00b7 auto-repairing`;
  } else if (synced === total && total > 0) {
    badge.dataset.state = 'synced';
    badge.textContent = `\u2713 ${total} / ${total} packets verified`;
  } else {
    badge.dataset.state = 'pending';
    badge.textContent = `${synced} / ${total} uploaded (${total} sections)`;
  }

  listEl.innerHTML = pkts.map((p, idx) => {
    const st = p.lost ? 'lost' : p.synced ? 'synced' : 'pending';
    const stWord = p.lost ? '\u26A0 Lost (re-upload)' : p.synced ? '\u2713 Verified' : 'Queued';
    const tag = p.tag || `s${String(idx + 1).padStart(4, '0')}of${String(total).padStart(4, '0')}`;
    return `<li class="packet-item">`
      + `<span class="packet-num">#${idx + 1}</span>`
      + `<span class="packet-tag" title="${escapeHTML(p.id || tag)}">${escapeHTML(tag)}</span>`
      + `<span class="packet-size">${formatBytes(p.n || 0)}</span>`
      + `<span class="packet-status" data-state="${st}">${stWord}</span>`
      + `</li>`;
  }).join('');
}

async function verifyAndReuploadVideoPackets(id) {
  const vid = editorVideos[id];
  if (!vid || !editingNoteId) return;
  const btn = document.getElementById('btn-video-verify-packets');
  setBusy(btn, true, 'Verifying & re-uploading packets\u2026');
  setBgVerifyBannerState(true, 'Manual verification running: checking all cloud packets\u2026');
  try {
    await ensureVideoPacketsMetadata(id);
    if (!Config.configured()) {
      if (Array.isArray(vid.packets)) vid.packets.forEach((p) => { p.lost = false; });
      onEditorContentChanged();
      triggerAutosave();
      await renderVideoInfoPackets(id);
      setBgVerifyBannerState(false, 'All packets verified on this device \u2014 queued for cloud upload.');
      toast('Packets verified on this device \u2014 queued for cloud upload');
      return;
    }
    if (vid.mediaName && window.KSMedia) {
      const res = await KSMedia.inspectAndRepairPackets(editingNoteId, vid.mediaName, {
        repair: true,
        onPacketStatus: (ps) => refreshVideoPacketUI(editingNoteId, vid.mediaName, ps),
      });
      if (res && Array.isArray(res.packets) && res.packets.length) {
        vid.packets = res.packets;
      }
      await renderVideoInfoPackets(id);
      refreshVideoPacketUI(editingNoteId, vid.mediaName, { state: 'synced' });
      const msg = res && res.repaired > 0
        ? `Re-uploaded ${res.repaired} lost packet${res.repaired === 1 ? '' : 's'} and verified all ${vid.packets ? vid.packets.length : ''} sections.`
        : `All ${vid.packets ? vid.packets.length : ''} packets verified intact in Backblaze.`;
      setBgVerifyBannerState(false, 'Manual + background verify: ' + msg);
      toast(msg);
    } else {
      triggerAutosave();
      toast('Uploading video packets to Backblaze\u2026');
    }
  } catch (e) {
    setBgVerifyBannerState(false, 'Could not reach Backblaze right now \u2014 background auto-verify will retry.');
    toast(e && e.message ? e.message : 'Could not verify packets right now');
  } finally {
    setBusy(btn, false);
  }
}

async function compressSavedVideo(id) {
  if (compressingSaved) { toast('Another compression is still running'); return; }
  const vid = editorVideos[id];
  if (!vid) return;
  const targetNoteId = editingNoteId;
  const before = estimateImageBytes(vid.data);
  const qSel = document.getElementById('video-modal-quality');
  const qKey = (qSel && qSel.value) || Config.videoQuality();
  Config.setVideoQuality(qKey);
  const q = VIDEO_QUALITY[qKey];
  const est = estimateCompressedVideoBytes(before, { duration: vid.dur, width: vid.width, height: vid.height }, qKey);
  const label = `Compressing video ${videoIndex(id)} \u00b7 ${formatBytes(before)} \u2192 ~${formatBytes(est.bytes)}`;
  compressingSaved = true;
  hide('overlay-video');
  syncBarSet(`${label} \u00b7 0%`, 0);
  try {
    const blob = await (await fetch(vid.data)).blob();
    const out = await compressVideoFile(
      blob,
      { duration: vid.dur, width: vid.width, height: vid.height, unplayable: false },
      qKey,
      (f) => syncBarSet(`${label} \u00b7 ${Math.round(f * 100)}%`, f),
      () => editingNoteId !== targetNoteId || !editorVideos[id]
    );
    if (!out || !out.blob || editingNoteId !== targetNoteId) { syncBarHideSoon(300); return; }
    const data = await readFileAsDataURL(out.blob);
    const after = estimateImageBytes(data);
    if (after >= before * 0.96) {
      syncBarHideSoon(300);
      toast('Compressing wouldn\u2019t make this video meaningfully smaller \u2014 left as it is');
      return;
    }
    syncBarHideSoon(300);
    openConfirm(
      'Replace with the compressed video?',
      `Final size: ${formatBytes(before)} \u2192 ${formatBytes(after)} (${q.label} ${q.maxDim}p, saves ${formatBytes(before - after)}). The compressed video will be sliced into ${estimatePacketCountForBytes(after, true)} tagged packets and replace the original.`,
      async () => {
        const cur = editorVideos[id];
        if (editingNoteId !== targetNoteId || !cur) return;
        cur.origSize = cur.origSize || before;
        cur.data = data;
        cur.mode = 'compressed';
        cur.width = out.width || cur.width;
        cur.height = out.height || cur.height;
        cur.mediaName = '';
        cur.packets = null;
        const oldUrl = videoUrls.get(id);
        if (oldUrl) { URL.revokeObjectURL(oldUrl); videoUrls.delete(id); }
        await ensureVideoPacketsMetadata(id);
        hydrateVideos(document.getElementById('editor-body'));
        updateSizeMeter();
        onEditorContentChanged();
        syncBarSuccess(`Compressed video: ${formatBytes(before)} \u2192 ${formatBytes(after)}`);
        scheduleBackgroundPacketCheck(editingNoteId, 800);
      },
      'Replace'
    );
  } catch (e) {
    syncBarHideSoon(300);
    toast('Couldn\u2019t compress that video');
  } finally {
    compressingSaved = false;
  }
}

function downloadVideoFile(id) {
  try {
    const vid = editorVideos[id];
    const url = videoUrlSync(id);
    if (!vid || !url) throw new Error('missing');
    const ext = videoExtFor(vid);
    const cleanName = (vid.name || '').replace(/\.[a-z0-9]{2,5}$/i, '').replace(/[^\w\- ]+/g, '').trim();
    const title = (document.getElementById('editor-title').value || 'note').replace(/[^\w\- ]+/g, '').trim().slice(0, 40) || 'note';
    const a = document.createElement('a');
    a.href = url;
    a.download = `${cleanName || `${title}-video-${videoIndex(id)}`}.${ext}`.replace(/\s+/g, '-');
    document.body.appendChild(a);
    a.click();
    a.remove();
    toast('Downloaded video');
  } catch (e) {
    toast('Couldn\u2019t download this video');
  }
}

function deleteVideo(id) {
  delete editorVideos[id];
  const oldUrl = videoUrls.get(id);
  if (oldUrl) { URL.revokeObjectURL(oldUrl); videoUrls.delete(id); }
  document.querySelectorAll(`#editor-body ks-video[data-id="${id}"]`).forEach((el) => {
    const wrap = el.parentNode;
    el.remove();
    if (wrap && wrap.id !== 'editor-body' && wrap.tagName === 'DIV' && !wrap.childNodes.length) wrap.remove();
  });
  labelVideoTiles();
  hide('overlay-video');
  updateSizeMeter();
  onEditorContentChanged();
}

function videoNextToCaret(backward) {
  const sel = window.getSelection();
  if (!sel.rangeCount || !sel.isCollapsed) return false;
  const r = sel.getRangeAt(0);
  const node = r.startContainer;
  let target = null;
  if (node.nodeType === 3) {
    if (backward && r.startOffset === 0) target = node.previousSibling;
    else if (!backward && r.startOffset === node.nodeValue.length) target = node.nextSibling;
  } else {
    target = backward ? node.childNodes[r.startOffset - 1] : node.childNodes[r.startOffset];
  }
  while (target && target.nodeType === 3 && !target.nodeValue) target = backward ? target.previousSibling : target.nextSibling;
  return !!(target && target.nodeType === 1 && target.tagName === 'KS-VIDEO');
}

function setupMedia() {
  document.querySelectorAll('[data-zone-icon]').forEach((el) => { el.innerHTML = ZONE_ICON[el.dataset.zoneIcon]; });
  const body = document.getElementById('editor-body');
  body.addEventListener('mousedown', (e) => { if (e.target.closest('.audio-chip button, .video-tile, .photo-tile')) e.preventDefault(); }); // keep the caret where it was
  body.addEventListener('click', (e) => {
    const photoTile = e.target.closest('.photo-tile[data-id]');
    if (photoTile) { e.preventDefault(); openLightbox(photoTile.dataset.id); return; }
    const videoTile = e.target.closest('.video-tile[data-id]');
    if (videoTile) { e.preventDefault(); openVideoTheater(videoTile.dataset.id); return; }
    const chip = e.target.closest('.audio-chip');
    if (!chip || !chip.dataset.id) return;
    e.preventDefault();
    if (e.target.closest('.audio-more')) openClipDialog(chip.dataset.id);
    else if (e.target.closest('.audio-play, .audio-time')) toggleClipPlayback(chip.dataset.id);
  });

  document.getElementById('btn-size').addEventListener('click', () => { renderSizeDialog(); show('overlay-size'); });
  document.getElementById('btn-attach-video').addEventListener('click', () => document.getElementById('input-video').click());
  document.getElementById('input-video').addEventListener('change', async (e) => {
    const files = Array.from(e.target.files || []);
    e.target.value = '';
    if (!files.length) return;
    await attachVideoFiles(files);
  });

  // Unified Video Studio: Settings, Compression & Packet Inspector events
  const modalQualSel = document.getElementById('video-modal-quality');
  if (modalQualSel) {
    modalQualSel.addEventListener('change', () => {
      Config.setVideoQuality(modalQualSel.value);
      const settingsSel = document.getElementById('settings-video-quality');
      if (settingsSel) settingsSel.value = modalQualSel.value;
      if (activeTheaterVideoId) refreshVideoCompressionPreview(activeTheaterVideoId);
    });
  }
  document.getElementById('btn-video-download').addEventListener('click', () => { if (activeTheaterVideoId) downloadVideoFile(activeTheaterVideoId); });
  document.getElementById('btn-video-compress').addEventListener('click', () => { if (activeTheaterVideoId) compressSavedVideo(activeTheaterVideoId); });
  document.getElementById('btn-video-verify-packets').addEventListener('click', () => { if (activeTheaterVideoId) verifyAndReuploadVideoPackets(activeTheaterVideoId); });
  document.getElementById('btn-video-delete').addEventListener('click', () => {
    const id = activeTheaterVideoId;
    if (!id) return;
    openConfirm('Remove this video?', 'It will be removed from the note. This can\u2019t be undone once the note is saved.', () => deleteVideo(id), 'Remove video');
  });

  // Video Player & Transport events inside #overlay-video
  const tVideo = document.getElementById('theater-video');
  const tSeek = document.getElementById('theater-seek');
  document.getElementById('btn-theater-close').addEventListener('click', () => hide('overlay-video'));
  document.getElementById('btn-video-prev').addEventListener('click', () => videoTheaterStep(-1));
  document.getElementById('btn-video-next').addEventListener('click', () => videoTheaterStep(1));
  document.getElementById('theater-stage').addEventListener('click', () => {
    if (tVideo.paused || tVideo.ended) tVideo.play().catch(() => {}); else tVideo.pause();
  });
  document.getElementById('btn-theater-play').addEventListener('click', () => {
    if (tVideo.paused || tVideo.ended) tVideo.play().catch(() => {}); else tVideo.pause();
  });
  document.getElementById('btn-theater-back10').addEventListener('click', () => {
    try { tVideo.currentTime = Math.max(0, (tVideo.currentTime || 0) - 10); } catch (e) { /* ignore */ }
    updateTheaterUI();
  });
  document.getElementById('btn-theater-fwd10').addEventListener('click', () => {
    const d = isFinite(tVideo.duration) ? tVideo.duration : 0;
    try { tVideo.currentTime = d ? Math.min(d, (tVideo.currentTime || 0) + 10) : (tVideo.currentTime || 0) + 10; } catch (e) { /* ignore */ }
    updateTheaterUI();
  });
  document.getElementById('btn-theater-mute').addEventListener('click', (e) => {
    tVideo.muted = !tVideo.muted;
    e.currentTarget.innerHTML = tVideo.muted ? VID_MUTE_SVG : VID_VOL_SVG;
    e.currentTarget.setAttribute('aria-pressed', String(tVideo.muted));
    e.currentTarget.setAttribute('aria-label', tVideo.muted ? 'Unmute' : 'Mute');
  });
  document.getElementById('btn-theater-speed').addEventListener('click', (e) => {
    const idx = PLAYBACK_SPEEDS.indexOf(tVideo.playbackRate);
    const next = PLAYBACK_SPEEDS[(idx + 1) % PLAYBACK_SPEEDS.length];
    tVideo.playbackRate = next;
    e.currentTarget.textContent = next + '\u00d7';
  });
  document.getElementById('btn-theater-fullscreen').addEventListener('click', () => {
    if (tVideo.requestFullscreen) tVideo.requestFullscreen().catch(() => {});
    else if (tVideo.webkitEnterFullscreen) { try { tVideo.webkitEnterFullscreen(); } catch (e) { /* ignore */ } }
  });
  document.getElementById('btn-theater-remove').addEventListener('click', () => {
    const id = activeTheaterVideoId;
    if (!id) return;
    openConfirm('Remove this video?', 'It is taken out of the note. This can\u2019t be undone once the note is saved.', () => deleteVideo(id), 'Remove video');
  });
  tVideo.addEventListener('play', updateTheaterUI);
  tVideo.addEventListener('pause', updateTheaterUI);
  tVideo.addEventListener('ended', () => { tVideo.currentTime = 0; updateTheaterUI(); });
  tVideo.addEventListener('timeupdate', updateTheaterUI);
  tVideo.addEventListener('progress', updateTheaterUI);
  tSeek.addEventListener('input', () => { tSeek.dataset.dragging = '1'; updateTheaterUI(); });
  tSeek.addEventListener('change', () => {
    delete tSeek.dataset.dragging;
    const vid = activeTheaterVideoId ? editorVideos[activeTheaterVideoId] : null;
    const d = isFinite(tVideo.duration) && tVideo.duration > 0 ? tVideo.duration : (vid ? vid.dur || 0 : 0);
    if (d > 0) { try { tVideo.currentTime = (Number(tSeek.value) / 1000) * d; } catch (e) { /* ignore */ } }
    updateTheaterUI();
  });

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

  registerMiniPlayer(document.getElementById('clip-player'),
    () => (clipDialogId && editorAudio[clipDialogId] ? 'clip:' + clipDialogId : null),
    () => (clipDialogId && editorAudio[clipDialogId] ? editorAudio[clipDialogId].dur || 0 : 0),
    () => voiceSourceForClip(clipDialogId));
  registerMiniPlayer(document.getElementById('record-player'),
    () => (Rec.blob ? 'preview' : null),
    () => (Rec.blob ? Rec.dur || 0 : 0),
    voiceSourceForPreview);
  document.getElementById('btn-clip-download').addEventListener('click', () => { if (clipDialogId) downloadClip(clipDialogId); });
  document.getElementById('btn-clip-compress').addEventListener('click', () => { if (clipDialogId) compressSavedClip(clipDialogId); });
  document.getElementById('btn-clip-delete').addEventListener('click', () => {
    const id = clipDialogId;
    if (!id) return;
    openConfirm('Delete this clip?', 'It will be removed from the note.', () => deleteClip(id), 'Delete clip');
  });

  document.getElementById('storage-pill').addEventListener('click', openSettings);
  const photoSel = document.getElementById('settings-photo-quality');
  const videoSel = document.getElementById('settings-video-quality');
  const audioSel = document.getElementById('settings-audio-quality');
  photoSel.addEventListener('change', () => { Config.setPhotoQuality(photoSel.value); document.getElementById('settings-photo-hint').textContent = PHOTO_QUALITY[photoSel.value].hint; });
  if (videoSel) videoSel.addEventListener('change', () => { Config.setVideoQuality(videoSel.value); document.getElementById('settings-video-hint').textContent = VIDEO_QUALITY[videoSel.value].hint; });
  audioSel.addEventListener('change', () => { Config.setAudioQuality(audioSel.value); document.getElementById('settings-audio-hint').textContent = AUDIO_QUALITY[audioSel.value].hint; });
  document.getElementById('settings-storage-limit').addEventListener('change', (e) => {
    const n = Number(e.target.value);
    if (n >= 50) Config.setStorageLimitMB(n);
    e.target.value = Config.storageLimitMB();
    renderStorageSection();
    updateStoragePill();
  });

  // Coming back to the app after a while: refresh the list and run a background packet verification pass.
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && Config.configured()) {
      if (Date.now() - lastServerSyncAt > 60000) refreshNotes();
      scheduleBackgroundPacketCheck(editingNoteId, 500);
    }
  });

  // Periodic background verification & auto-reupload of lost or pending video packets
  setInterval(() => {
    if (navigator.onLine !== false && Config.configured()) {
      runBackgroundPacketCheck(editingNoteId).catch(() => {});
    }
  }, 25000);
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

  // Backspace/Delete beside a photo or video does nothing: they are removed from their viewer/options, on purpose.
  body.addEventListener('beforeinput', (e) => {
    const back = e.inputType === 'deleteContentBackward';
    if (back || e.inputType === 'deleteContentForward') {
      if (photoNextToCaret(back)) {
        e.preventDefault();
        toast('Open the photo to remove it');
      } else if (videoNextToCaret(back)) {
        e.preventDefault();
        toast('Open the video options to remove it');
      }
    }
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
    openEditorWithContent(meta, { title: draft.title, body: draft.body, html: draft.html, images: draft.images || [], imageIds: draft.imageIds, drawing: draft.drawing, audio: draft.audio, videos: draft.videos });
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
  setupSecretFields();
  setupKeyboardViewportFix();
  setupLightbox();
  setupRichText();
  setupMedia();
  setupInk();
  document.getElementById('version-badge').textContent = 'v' + (window.KEEPSAKE_VERSION || '1.10.1');

  // Connectivity: react the moment the browser notices, and keep retrying
  // on a timer since navigator.onLine can't see a connection that's up but
  // not actually reaching Backblaze.
  window.addEventListener('online', () => { setOnline(true); flushOutbox(); scheduleBackgroundPacketCheck(editingNoteId, 800); });
  window.addEventListener('offline', () => setOnline(false));
  setInterval(() => { if (navigator.onLine && outboxCount > 0) flushOutbox(); }, 30000);
  updateSyncStatusUI();

  // Leaving the app (switching away, closing the tab) with an edit not yet sent: start saving it
  // now rather than waiting for the autosave timer. It is written to the device first, so even if
  // the page is killed a moment later the change is not lost.
  const editorOpen = () => editingNoteId && !document.getElementById('overlay-editor').classList.contains('hidden');
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden' && editorOpen()) triggerAutosave(); });
  window.addEventListener('pagehide', () => { if (editorOpen()) triggerAutosave(); });

  if (!Config.configured()) {
    openSettings();
    toast('Add your Backblaze bucket details to get started');
  } else {
    // Data left waiting by an earlier session? Say so straight away, with the counts.
    showUnsyncedSummary().catch(() => {});
    refreshNotes().then(checkForRecoverableDrafts);
  }

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(() => { /* offline shell is a nice-to-have */ });
  }
}

document.addEventListener('DOMContentLoaded', init);
