/* Keepsake — media.js
 * Photos and audio kept as separate files in your Backblaze B2 bucket instead of inside the note.
 *
 * How it fits together
 *   - In the editor nothing changes: photos and clips are data: URLs.
 *   - When a note is SAVED, every data: URL is swapped for a short reference ("ks-media:<name>")
 *     and the bytes are queued for upload. A manifest in the note says what each reference is.
 *     For a locked note the bytes are encrypted first, with a random key that lives inside the
 *     note's own encrypted content, so the bucket only ever holds ciphertext for those.
 *   - When a note is OPENED, the references are swapped back for data: URLs (from this device's
 *     copy if it has one, otherwise downloaded from the bucket).
 *   - Uploads and downloads go straight to the bucket through b2.js.
 *
 * Self-contained on purpose: its own small IndexedDB ("keepsake-media"), its own helpers.
 */
(function (root) {
  'use strict';

  const REF_PREFIX = 'ks-media:';
  const NAME_RE = /^[a-f0-9]{32}$/;
  const MAX_ITEM_BYTES = 90 * 1024 * 1024; // per file: a photo or clip is held in memory while a note is open
  const CACHE_CAP_BYTES = 300 * 1024 * 1024; // synced copies kept on this device; oldest-used go first
  let cacheCap = CACHE_CAP_BYTES;
  const DB_NAME = 'keepsake-media';
  const INFO = 'info';   // light: { id, noteId, name, size, used, pending }
  const BLOB = 'blob';   // heavy: { id, bytes }

  /* ------------------------------------------------------------------ helpers */

  function hex(buf) {
    return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
  }

  function randomName() {
    return hex(root.crypto.getRandomValues(new Uint8Array(16)));
  }

  function bytesToB64(bytes) {
    let s = '';
    const CH = 0x8000;
    for (let i = 0; i < bytes.length; i += CH) s += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
    return root.btoa(s);
  }

  function b64ToBytes(str) {
    const bin = root.atob(str);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // "data:image/jpeg;base64,...." -> { type: 'image/jpeg', b64 }. Anything that isn't a
  // base64 data URL returns null and simply stays inside the note.
  function parseDataURL(url) {
    if (typeof url !== 'string' || url.charCodeAt(0) !== 100 /* d */) return null;
    const comma = url.indexOf(',');
    if (comma < 0 || comma > 200) return null;
    const head = url.slice(5, comma);
    if (!/;base64$/i.test(head)) return null;
    return { type: head.slice(0, -7), b64: url.slice(comma + 1) };
  }

  async function dataUrlToBytes(url) {
    const p = parseDataURL(url);
    if (!p) throw new Error('Not a base64 data URL');
    return { type: p.type, bytes: b64ToBytes(p.b64) };
  }

  function bytesToDataUrl(bytes, type) {
    const blobType = type || 'application/octet-stream';
    if (typeof root.FileReader === 'function' && typeof root.Blob === 'function') {
      // Native base64 encoding of a big Blob is far faster than building the string by hand.
      return new Promise((resolve, reject) => {
        const r = new root.FileReader();
        r.onload = () => {
          // FileReader writes "data:<type>;base64," using the Blob's type; make sure
          // the header is exactly what we stored so a round trip is byte-for-byte.
          const s = String(r.result);
          const comma = s.indexOf(',');
          resolve('data:' + blobType + ';base64,' + s.slice(comma + 1));
        };
        r.onerror = () => reject(r.error || new Error('Could not read media'));
        r.readAsDataURL(new root.Blob([bytes], { type: 'application/octet-stream' }));
      });
    }
    return Promise.resolve('data:' + blobType + ';base64,' + bytesToB64(bytes));
  }

  async function sha256Hex(bytes) {
    return hex(await root.crypto.subtle.digest('SHA-256', bytes));
  }

  /* --------------------------------------------------------------- encryption */

  async function genKeyB64() {
    const key = await root.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    return bytesToB64(new Uint8Array(await root.crypto.subtle.exportKey('raw', key)));
  }

  function importKey(b64) {
    return root.crypto.subtle.importKey('raw', b64ToBytes(b64), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }

  async function encryptBytes(key, bytes) {
    const iv = root.crypto.getRandomValues(new Uint8Array(12));
    const ct = await root.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes);
    return { iv: bytesToB64(iv), bytes: new Uint8Array(ct) };
  }

  async function decryptBytes(key, ivB64, bytes) {
    return new Uint8Array(await root.crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(ivB64) }, key, bytes));
  }

  /* ------------------------------------------------------- local copy (IndexedDB) */

  let dbPromise = null;

  function openDB() {
    if (dbPromise) return dbPromise;
    dbPromise = new Promise((resolve, reject) => {
      if (!root.indexedDB) { dbPromise = null; reject(new Error('IndexedDB unavailable')); return; }
      const req = root.indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(INFO)) db.createObjectStore(INFO, { keyPath: 'id' });
        if (!db.objectStoreNames.contains(BLOB)) db.createObjectStore(BLOB, { keyPath: 'id' });
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

  async function run(stores, mode, fn) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      let tx;
      try { tx = db.transaction(stores, mode); } catch (e) { reject(e); return; }
      let result;
      try { result = fn(tx); } catch (e) { try { tx.abort(); } catch (e2) { /* done */ } reject(e); return; }
      tx.oncomplete = () => resolve(result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error || new Error('Transaction aborted'));
    });
  }

  function req(store, method, arg) {
    return openDB().then((db) => new Promise((resolve, reject) => {
      const r = db.transaction(store, 'readonly').objectStore(store)[method](arg);
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    }));
  }

  const idOf = (noteId, name) => noteId + '/' + name;

  async function cachePut(noteId, name, bytes, pending) {
    const id = idOf(noteId, name);
    await run([INFO, BLOB], 'readwrite', (tx) => {
      // Structured cloning copies a typed array's whole underlying buffer, so only
      // hand over the buffer itself when the array covers all of it.
      const whole = bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength;
      tx.objectStore(BLOB).put({ id, bytes: whole ? bytes.buffer : bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) });
      tx.objectStore(INFO).put({ id, noteId, name, size: bytes.length, used: Date.now(), pending: !!pending });
    });
    if (!pending) await evict().catch(() => {});
  }

  async function cacheGet(noteId, name) {
    const id = idOf(noteId, name);
    const rec = await req(BLOB, 'get', id);
    if (!rec) return null;
    const info = await req(INFO, 'get', id);
    if (info) run(INFO, 'readwrite', (tx) => { tx.objectStore(INFO).put({ ...info, used: Date.now() }); }).catch(() => {});
    return new Uint8Array(rec.bytes);
  }

  async function infoGet(noteId, name) { return (await req(INFO, 'get', idOf(noteId, name))) || null; }

  async function infoForNote(noteId) {
    const all = (await req(INFO, 'getAll')) || [];
    return all.filter((i) => i.noteId === noteId);
  }

  async function markSynced(noteId, name) {
    const info = await infoGet(noteId, name);
    if (info) await run(INFO, 'readwrite', (tx) => { tx.objectStore(INFO).put({ ...info, pending: false, used: Date.now() }); });
  }

  async function cacheDelete(entries) {
    if (!entries.length) return;
    await run([INFO, BLOB], 'readwrite', (tx) => {
      for (const e of entries) { tx.objectStore(INFO).delete(e.id); tx.objectStore(BLOB).delete(e.id); }
    });
  }

  // Keeps this device's copies under the cap by dropping the ones used longest ago.
  // Files still waiting to upload are never dropped.
  async function evict() {
    const all = (await req(INFO, 'getAll')) || [];
    let total = all.reduce((n, i) => n + i.size, 0);
    if (total <= cacheCap) return;
    const candidates = all.filter((i) => !i.pending).sort((a, b) => a.used - b.used);
    const drop = [];
    for (const c of candidates) {
      if (total <= cacheCap) break;
      drop.push(c);
      total -= c.size;
    }
    await cacheDelete(drop);
  }

  async function cacheBytesUsed() {
    const all = (await req(INFO, 'getAll')) || [];
    return all.reduce((n, i) => n + i.size, 0);
  }

  /* ------------------------------------------------------------ talking to the bucket */

  async function downloadBytes(noteId, name) {
    const bytes = await root.KSB2.getBytesOrNull(root.KSB2.mediaKey(noteId, name));
    if (!bytes) {
      const err = new Error('A photo or audio clip is missing from your bucket');
      err.status = 404;
      throw err;
    }
    return bytes;
  }

  function uploadBytes(noteId, name, bytes, sha, onProgress) {
    return root.KSB2.putBytes(root.KSB2.mediaKey(noteId, name), bytes, sha, onProgress ? (loaded) => onProgress(loaded) : null);
  }

  /* ------------------------------------------------------------------- settings */

  // Photos and audio always live in the bucket once it is set up.
  function available() { return !!(root.KSB2 && root.KSB2.config.configured()); }
  function enabled() { return available(); }

  /* ----------------------------------------------- references <-> data URLs */

  // For each note, remember which data URL was uploaded as which file, so saving the
  // same photo again is free. Only the last couple of notes are kept (the strings are big).
  const indexes = new Map();   // noteId -> Map(dataUrl -> entry)
  const noteKeys = new Map();  // noteId -> base64 AES key (locked notes only)

  function indexFor(noteId) {
    let idx = indexes.get(noteId);
    if (!idx) {
      idx = new Map();
      indexes.set(noteId, idx);
      while (indexes.size > 2) indexes.delete(indexes.keys().next().value);
    } else {
      indexes.delete(noteId);
      indexes.set(noteId, idx);
    }
    return idx;
  }

  function isRef(s) { return typeof s === 'string' && s.startsWith(REF_PREFIX) && NAME_RE.test(s.slice(REF_PREFIX.length)); }
  function refName(s) { return s.slice(REF_PREFIX.length); }

  // content: { title, body, html, images: [dataUrl], audio: { id: {data, dur, name} }, drawing }
  // -> { content (references instead of data), keep: [names], bytes: total stored in B2 }
  async function externalize(noteId, content, locked) {
    const none = { content, keep: [], bytes: 0 };
    if (!enabled()) return none;

    const images = content.images || [];
    const audio = content.audio || {};
    const wantsImage = images.some((s) => parseDataURL(s));
    const audioIds = Object.keys(audio).filter((id) => audio[id] && parseDataURL(audio[id].data));
    if (!wantsImage && !audioIds.length) return none;

    let keyB64 = null;
    if (locked) {
      keyB64 = noteKeys.get(noteId) || null;
      if (!keyB64) { keyB64 = await genKeyB64(); noteKeys.set(noteId, keyB64); }
    }
    const key = locked ? await importKey(keyB64) : null;
    const idx = indexFor(noteId);
    const manifest = {};

    async function refFor(dataUrl) {
      let e = idx.get(dataUrl);
      if (!(e && e.enc === locked && (!locked || e.keyB64 === keyB64))) {
        const { type, bytes } = await dataUrlToBytes(dataUrl);
        let stored = bytes;
        let iv = null;
        if (locked) { const enc = await encryptBytes(key, bytes); stored = enc.bytes; iv = enc.iv; }
        if (stored.length > MAX_ITEM_BYTES) {
          const err = new Error('A photo or audio clip is over the 90 MB limit');
          err.tooBig = true;
          throw err;
        }
        const name = randomName();
        await cachePut(noteId, name, stored, true);
        e = { name, t: type, n: stored.length, iv, enc: locked, keyB64: locked ? keyB64 : null };
        idx.set(dataUrl, e);
      }
      manifest[e.name] = e.iv ? { t: e.t, n: e.n, iv: e.iv } : { t: e.t, n: e.n };
      return REF_PREFIX + e.name;
    }

    const out = { ...content };
    out.images = [];
    for (const s of images) out.images.push(parseDataURL(s) ? await refFor(s) : s);
    if (Object.keys(audio).length) {
      out.audio = {};
      for (const id of Object.keys(audio)) {
        const clip = audio[id];
        out.audio[id] = (clip && parseDataURL(clip.data)) ? { ...clip, data: await refFor(clip.data) } : clip;
      }
    }
    out.media = manifest;
    if (locked) out.mediaKey = keyB64;
    const keep = Object.keys(manifest);
    return { content: out, keep, bytes: keep.reduce((n, k) => n + manifest[k].n, 0) };
  }

  function notAvailableOffline(cause) {
    const err = new Error('Photos and audio aren\u2019t on this device yet \u2014 open this note once while connected.');
    err.notCached = true;
    err.cause = cause;
    return err;
  }

  // The reverse: references -> data URLs (and the manifest is dropped), so the rest of
  // the app sees the same content it always did. Throws rather than ever returning a note
  // with media quietly missing: saving that would lose the media for good.
  async function inflate(noteId, content, opts) {
    const manifest = content && content.media;
    if (!manifest || typeof manifest !== 'object') return content;
    const o = opts || {};
    const key = content.mediaKey ? await importKey(content.mediaKey) : null;
    const dataByName = {};
    let announced = false;

    const names = new Set();
    for (const s of content.images || []) if (isRef(s)) names.add(refName(s));
    for (const id of Object.keys(content.audio || {})) {
      const d = content.audio[id] && content.audio[id].data;
      if (isRef(d)) names.add(refName(d));
    }

    for (const name of names) {
      const m = manifest[name];
      if (!m) throw new Error('A photo or audio clip in this note has no record \u2014 the note looks damaged.');
      let stored = await cacheGet(noteId, name).catch(() => null);
      if (!stored) {
        if (!announced && o.onDownload) { announced = true; o.onDownload(); }
        try { stored = await downloadBytes(noteId, name); } catch (e) {
          if (e.isNetworkError) throw notAvailableOffline(e);
          throw e;
        }
        if (m.n && stored.length !== m.n) throw new Error('A photo or audio clip came back the wrong size \u2014 try again.');
        await cachePut(noteId, name, stored, false).catch(() => {});
      }
      let plain = stored;
      if (m.iv) {
        if (!key) throw new Error('This note\u2019s media is encrypted but its key is missing.');
        plain = await decryptBytes(key, m.iv, stored);
      }
      dataByName[name] = { url: await bytesToDataUrl(plain, m.t), entry: { name, t: m.t, n: m.n, iv: m.iv || null, enc: !!m.iv, keyB64: m.iv ? content.mediaKey : null } };
    }

    const idx = indexFor(noteId);
    if (content.mediaKey) noteKeys.set(noteId, content.mediaKey);
    const pick = (s) => {
      if (!isRef(s)) return s;
      const d = dataByName[refName(s)];
      if (!d) throw new Error('A photo or audio clip in this note could not be found.');
      idx.set(d.url, d.entry);
      return d.url;
    };

    const out = { ...content };
    delete out.media;
    delete out.mediaKey;
    out.images = (content.images || []).map(pick);
    if (content.audio) {
      out.audio = {};
      for (const id of Object.keys(content.audio)) {
        const clip = content.audio[id];
        out.audio[id] = clip && isRef(clip.data) ? { ...clip, data: pick(clip.data) } : clip;
      }
    }
    return out;
  }

  /* ----------------------------------------------------------------- uploading */

  // Uploads whichever of `names` are still only on this device. Returns the bytes sent.
  async function uploadPending(noteId, names, onProgress) {
    const todo = [];
    for (const name of names) {
      if (!NAME_RE.test(name)) continue;
      const info = await infoGet(noteId, name);
      if (info && info.pending) todo.push(info);
    }
    const total = todo.reduce((n, i) => n + i.size, 0);
    if (!total) return 0;
    let done = 0;
    for (const info of todo) {
      const bytes = await cacheGet(noteId, info.name);
      if (!bytes) throw new Error('A photo or clip waiting to upload is missing from this device.');
      const sha = await sha256Hex(bytes);
      const base0 = done;
      await uploadBytes(noteId, info.name, bytes, sha, onProgress ? (loaded) => onProgress(Math.min(1, (base0 + loaded) / total)) : null);
      await markSynced(noteId, info.name);
      done += info.size;
      if (onProgress) onProgress(Math.min(1, done / total));
    }
    return total;
  }

  // After a note is saved or queued: forget local copies it no longer refers to.
  async function reconcile(noteId, keepNames) {
    const keep = new Set(keepNames || []);
    const mine = await infoForNote(noteId);
    await cacheDelete(mine.filter((i) => !keep.has(i.name)));
  }

  async function dropNote(noteId) {
    indexes.delete(noteId);
    noteKeys.delete(noteId);
    const mine = await infoForNote(noteId);
    await cacheDelete(mine);
  }

  /* ----------------------------------------------------- offline + download helpers */

  async function list(noteId) {
    return root.KSB2.listMedia(noteId);
  }

  // Quietly fetches a note's media so the note opens offline, while there is room.
  async function prefetchNote(noteId, expectedBytes) {
    const have = await infoForNote(noteId);
    if (have.reduce((n, i) => n + i.size, 0) >= expectedBytes) return;
    let used = await cacheBytesUsed();
    const haveNames = new Set(have.map((i) => i.name));
    for (const item of await list(noteId)) {
      if (haveNames.has(item.name)) continue;
      if (used + item.size > cacheCap) return;
      const bytes = await downloadBytes(noteId, item.name);
      await cachePut(noteId, item.name, bytes, false);
      used += bytes.length;
    }
  }

  // For "Download": adds the stored bytes of every file the note has (still encrypted for a
  // locked note) next to the note, so the downloaded file is a complete backup.
  async function attachToBundle(noteId, bundle, opts) {
    const o = opts || {};
    let items;
    try { items = await list(noteId); } catch (e) {
      if (!e.isNetworkError) throw e;
      // Offline: whatever this device holds for the note is what can go in the file.
      items = (await infoForNote(noteId)).map((i) => ({ name: i.name, size: i.size }));
    }
    if (!items.length) return bundle;
    const total = items.reduce((n, i) => n + i.size, 0);
    const limit = o.maxBytes || 200 * 1024 * 1024;
    if (total > limit) {
      bundle._mediaNote = 'This note has ' + Math.round(total / 1048576) + ' MB of photos and audio in Backblaze, too large to include here. They are in your bucket under media/' + noteId + '/.';
      return bundle;
    }
    if (o.onDownload) o.onDownload();
    const media = {};
    for (const item of items) {
      let bytes = await cacheGet(noteId, item.name).catch(() => null);
      if (!bytes) bytes = await downloadBytes(noteId, item.name);
      media[item.name] = bytesToB64(bytes);
    }
    bundle.media = media;
    bundle._mediaHint = 'Each entry is a file from the note, base64-encoded. In the note, "ks-media:<name>" refers to media[<name>]. For a locked note these are encrypted: decrypt with AES-GCM using the note\u2019s mediaKey and each file\u2019s iv.';
    return bundle;
  }

  root.KSMedia = {
    REF_PREFIX, NAME_RE, MAX_ITEM_BYTES, CACHE_CAP_BYTES,
    available, enabled,
    externalize, inflate, uploadPending, reconcile, dropNote,
    prefetchNote, attachToBundle, cacheBytesUsed,
    _test: { setCap(n) { cacheCap = n; }, resetMemory() { indexes.clear(); noteKeys.clear(); }, parseDataURL, bytesToDataUrl, cachePut, cacheGet, infoGet, infoForNote, evict, indexes, noteKeys },
  };
})(typeof window !== 'undefined' ? window : globalThis);
