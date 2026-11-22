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
  // Photos and clips are one 32-hex file. A video is many parts, <32 hex>.<5 digits> (see video.js).
  const BASE_RE = /^[a-f0-9]{32}$/;
  const NAME_RE = /^[a-f0-9]{32}(?:\.\d{5})?$/;
  const MAX_ITEM_BYTES = 90 * 1024 * 1024; // per file: a photo or clip is held in memory while a note is open
  const CACHE_CAP_BYTES = 300 * 1024 * 1024; // synced copies kept on this device; oldest-used go first
  const VIDEO_CACHE_CAP_BYTES = 2 * 1024 * 1024 * 1024; // synced video parts kept on this device (parts are never held in memory whole)
  const VERIFY_EVERY = 12;                   // video parts sent between two checks of what the bucket really holds
  const VERIFY_ROUNDS = 4;                   // how many times a part the bucket lost is sent again before giving up
  let cacheCap = CACHE_CAP_BYTES;
  let videoCap = VIDEO_CACHE_CAP_BYTES;
  const isPartName = (name) => /\.\d{5}$/.test(name);
  const baseOf = (name) => String(name).split('.')[0];
  // Bases of videos that are being added to a note right now. Their parts are on this device but the note
  // doesn't list them yet, so a save of an older version must not clean them up as strays.
  const heldBases = new Set();
  const DB_NAME = 'keepsake-media';
  const INFO = 'info';   // light: { id, noteId, name, size, used, pending, kind, sha, pinned }  (pinned = part of the master's full offline copy: never evicted)
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
      req.onblocked = () => { dbPromise = null; reject(new Error('IndexedDB blocked')); };
    });
    return dbPromise;
  }

  async function run(stores, mode, fn) {
    const db = await openDB();
    let tx;
    try { tx = db.transaction(stores, mode); }
    catch (e) {
      if (e && e.name === 'InvalidStateError') { dbPromise = null; const db2 = await openDB(); tx = db2.transaction(stores, mode); }
      else throw e;
    }
    return new Promise((resolve, reject) => {
      let result;
      try { result = fn(tx); } catch (e) { try { tx.abort(); } catch (e2) { /* done */ } reject(e); return; }
      tx.oncomplete = () => resolve(result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error || new Error('Transaction aborted'));
    });
  }

  async function req(store, method, arg) {
    const db = await openDB();
    let tx;
    try { tx = db.transaction(store, 'readonly'); }
    catch (e) {
      if (e && e.name === 'InvalidStateError') { dbPromise = null; const db2 = await openDB(); tx = db2.transaction(store, 'readonly'); }
      else throw e;
    }
    return new Promise((resolve, reject) => {
      const r = tx.objectStore(store)[method](arg);
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
  }

  const idOf = (noteId, name) => noteId + '/' + name;

  // `extra` = { kind: 'photo' | 'audio', sha } - what the file is, and its SHA-256 (computed here
  // for anything still waiting to upload, so a copy that gets damaged on this device is caught
  // before it is ever sent).
  const isBlob = (x) => typeof root.Blob === 'function' && x instanceof root.Blob;

  function blobBytes(blob) {
    if (typeof blob.arrayBuffer === 'function') return blob.arrayBuffer();
    return new Promise((resolve, reject) => {
      const r = new root.FileReader();
      r.onload = () => resolve(r.result);
      r.onerror = () => reject(r.error || new Error('Could not read media'));
      r.readAsArrayBuffer(blob);
    });
  }

  // `bytes` is a Uint8Array, or a Blob (a video part: the browser keeps those on disk, not in memory).
  async function cachePut(noteId, name, bytes, pending, extra) {
    const id = idOf(noteId, name);
    const x = extra || {};
    const blobIn = isBlob(bytes);
    const size = blobIn ? bytes.size : bytes.length;
    let sha = x.sha || '';
    if (!sha && pending) sha = await sha256Hex(blobIn ? new Uint8Array(await blobBytes(bytes)) : bytes);
    const prev = await req(INFO, 'get', id).catch(() => null);
    const info = {
      id, noteId, name, size, used: Date.now(), pending: !!pending,
      kind: x.kind || (prev && prev.kind) || '',
      sha: sha || (prev && prev.size === size ? prev.sha : '') || '',
    };
    const plainSha = x.plainSha || (prev && prev.plainSha) || '';
    if (plainSha) info.plainSha = plainSha;
    const mime = x.t || (prev && prev.t) || '';
    if (mime) info.t = mime;
    const iv = x.iv !== undefined ? x.iv : (prev && prev.iv);
    if (iv) info.iv = iv;
    const keyB64 = x.keyB64 !== undefined ? x.keyB64 : (prev && prev.keyB64);
    if (keyB64) info.keyB64 = keyB64;
    if (x.pinned || (prev && prev.pinned)) info.pinned = true;
    const write = (value) => run([INFO, BLOB], 'readwrite', (tx) => {
      tx.objectStore(BLOB).put({ id, bytes: value });
      tx.objectStore(INFO).put(info);
    });
    const evictForSpace = async (needBytes) => {
      const all = ((await req(INFO, 'getAll')) || []).filter((i) => !i.pinned && !i.pending && !isKeyRecord(i) && i.id !== id);
      if (!all.length) return 0;
      all.sort((a, b) => a.used - b.used);
      const drop = [];
      let freed = 0;
      const target = Math.max(needBytes || 0, 1);
      for (const c of all) {
        drop.push(c);
        freed += c.size || 0;
        if (freed >= target) break;
      }
      await cacheDelete(drop);
      return drop.length;
    };
    const writeWithQuotaRetry = async (value) => {
      try {
        await write(value);
      } catch (e) {
        if (e && e.name === 'QuotaExceededError') {
          const dropped = await evictForSpace(size).catch(() => 0);
          if (dropped > 0) {
            await write(value);
            return;
          }
        }
        throw e;
      }
    };
    if (blobIn) {
      try { await writeWithQuotaRetry(bytes); }
      catch (e) {
        if (e && (e.name === 'DataCloneError' || e.name === 'NotSupportedError')) {
          await writeWithQuotaRetry(await blobBytes(bytes)); // a browser that can't keep a Blob in IndexedDB: keep its bytes
        } else {
          throw e;
        }
      }
    } else {
      // Structured cloning copies a typed array's whole underlying buffer, so only
      // hand over the buffer itself when the array covers all of it.
      const whole = bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength;
      await writeWithQuotaRetry(whole ? bytes.buffer : bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
    }
    if (!pending && !info.pinned) scheduleEvict();
  }

  async function cacheRecord(noteId, name) {
    const id = idOf(noteId, name);
    const rec = await req(BLOB, 'get', id);
    if (!rec) return null;
    run(INFO, 'readwrite', (tx) => {
      const st = tx.objectStore(INFO);
      const r = st.get(id);
      r.onsuccess = () => { if (r.result) st.put({ ...r.result, used: Date.now() }); };
    }).catch(() => {});
    return rec.bytes;
  }

  async function cacheGet(noteId, name) {
    const raw = await cacheRecord(noteId, name);
    if (!raw) return null;
    return new Uint8Array(isBlob(raw) ? await blobBytes(raw) : raw);
  }

  // The stored bytes as a Blob - what playback and uploads of video parts use, so nothing is copied into memory.
  async function cacheGetBlob(noteId, name) {
    const raw = await cacheRecord(noteId, name);
    if (!raw) return null;
    return isBlob(raw) ? raw : new root.Blob([raw]);
  }

  async function infoGet(noteId, name) { return (await req(INFO, 'get', idOf(noteId, name))) || null; }

  const isKeyRecord = (i) => i && i.kind === 'key';
  const keyRecordId = (noteId) => noteId + '/_key';

  async function infoForNote(noteId) {
    const all = (await req(INFO, 'getAll')) || [];
    return all.filter((i) => i.noteId === noteId && !isKeyRecord(i));
  }

  async function saveNoteKey(noteId, keyB64) {
    if (!noteId || !keyB64) return;
    noteKeys.set(noteId, keyB64);
    try {
      await run(INFO, 'readwrite', (tx) => {
        tx.objectStore(INFO).put({ id: keyRecordId(noteId), noteId, name: '_key', size: 0, used: Date.now(), pending: false, kind: 'key', keyB64 });
      });
    } catch (e) { /* best-effort persistence */ }
  }

  async function loadNoteKey(noteId) {
    let keyB64 = noteKeys.get(noteId) || null;
    if (keyB64) return keyB64;
    try {
      const rec = await req(INFO, 'get', keyRecordId(noteId));
      if (rec && rec.keyB64) { noteKeys.set(noteId, rec.keyB64); return rec.keyB64; }
    } catch (e) { /* best-effort */ }
    return null;
  }

  async function markSynced(noteId, name) {
    const id = idOf(noteId, name);
    await run(INFO, 'readwrite', (tx) => {
      const st = tx.objectStore(INFO);
      const r = st.get(id);
      r.onsuccess = () => { if (r.result) st.put({ ...r.result, pending: false, used: Date.now() }); };
    });
  }

  async function cacheDelete(entries) {
    if (!entries.length) return;
    await run([INFO, BLOB], 'readwrite', (tx) => {
      for (const e of entries) { tx.objectStore(INFO).delete(e.id); tx.objectStore(BLOB).delete(e.id); }
    });
  }

  // Batch eviction checks so a large download doesn't rescan the entire index on every file.
  let evictTimer = null;
  let evictWrites = 0;
  function scheduleEvict() {
    evictWrites++;
    if (evictWrites >= 25) {
      evictWrites = 0;
      if (evictTimer) { root.clearTimeout(evictTimer); evictTimer = null; }
      evict().catch(() => {});
      return;
    }
    if (evictTimer) return;
    evictTimer = root.setTimeout(() => {
      evictTimer = null;
      evictWrites = 0;
      evict().catch(() => {});
    }, 1500);
  }

  // Keeps this device's copies under the cap by dropping the ones used longest ago.
  // Files still waiting to upload are never dropped.
  async function evict() {
    const all = ((await req(INFO, 'getAll')) || []).filter((i) => !i.pinned && !isKeyRecord(i));   // the full offline copy is outside the caps
    // Photos/audio and video parts have a cap each, so a few big videos never push the photos out.
    const trim = (items, cap) => {
      let total = items.reduce((n, i) => n + i.size, 0);
      const drop = [];
      if (total <= cap) return drop;
      for (const c of items.filter((i) => !i.pending).sort((a, b) => a.used - b.used)) {
        if (total <= cap) break;
        drop.push(c);
        total -= c.size;
      }
      return drop;
    };
    const drop = trim(all.filter((i) => i.kind !== 'video'), cacheCap).concat(trim(all.filter((i) => i.kind === 'video'), videoCap));
    await cacheDelete(drop);
  }

  async function cacheBytesUsed() {
    const all = (await req(INFO, 'getAll')) || [];
    return all.filter((i) => !isKeyRecord(i) && i.kind !== 'video' && !i.pinned).reduce((n, i) => n + i.size, 0);
  }

  // The master's full offline copy: pinned files are never dropped to make room.
  async function pin(noteId, name) {
    const id = idOf(noteId, name);
    await run(INFO, 'readwrite', (tx) => {
      const st = tx.objectStore(INFO);
      const r = st.get(id);
      r.onsuccess = () => { if (r.result && !r.result.pinned) st.put({ ...r.result, pinned: true }); };
    });
  }
  async function allInfo() { return ((await req(INFO, 'getAll')) || []).filter((i) => !isKeyRecord(i)); }
  // Older copies were saved without saying what they are; the Offline copy section works it out once and records it.
  async function setKinds(updates) {
    if (!updates.length) return;
    await run(INFO, 'readwrite', (tx) => {
      const st = tx.objectStore(INFO);
      for (const u of updates) {
        const id = u.info && u.info.id;
        if (!id) continue;
        const r = st.get(id);
        r.onsuccess = () => { if (r.result && !r.result.kind) st.put({ ...r.result, kind: u.kind }); };
      }
    });
  }
  // Everything saved here for offline use, pinned or not, except files still waiting to upload.
  async function deleteSynced() {
    const gone = (await allInfo()).filter((i) => !i.pending);
    for (let i = 0; i < gone.length; i += 200) await cacheDelete(gone.slice(i, i + 200));
    return gone.length;
  }

  /* ------------------------------------------------------------ talking to the bucket */

  async function downloadBytes(noteId, name, opts) {
    const bytes = await root.KSB2.getBytesOrNull(root.KSB2.mediaKey(noteId, name), opts);
    if (!bytes) {
      const err = new Error('A photo or audio clip is missing from your bucket');
      err.status = 404;
      throw err;
    }
    return bytes;
  }

  function uploadBytes(noteId, name, bytes, sha, onProgress) {
    return root.KSB2.putBytes(root.KSB2.mediaKey(noteId, name), bytes, sha, onProgress ? (loaded, total) => onProgress(loaded, total) : null);
  }

  /* ------------------------------------------------------------------- settings */

  // Photos and audio always live in the bucket once it is set up.
  function available() { return !!(root.KSB2 && root.KSB2.config.configured()); }
  function enabled() { return available(); }

  /* ----------------------------------------------- references <-> data URLs */

  // For each note, remember which data URL (and plaintext SHA-256) was uploaded as which file,
  // so renaming a note, adding new photos, or locking/unlocking never re-uploads existing files.
  const indexes = new Map();   // noteId -> Map(dataUrl -> entry)
  const shaIndexes = new Map(); // noteId -> Map(plainSha -> entry)
  const noteKeys = new Map();  // noteId -> base64 AES key

  function indexFor(noteId) {
    let idx = indexes.get(noteId);
    if (!idx) {
      idx = new Map();
      indexes.set(noteId, idx);
      while (indexes.size > 20) {
        const oldest = indexes.keys().next().value;
        indexes.delete(oldest);
        shaIndexes.delete(oldest);
      }
    } else {
      indexes.delete(noteId);
      indexes.set(noteId, idx);
    }
    return idx;
  }

  function shaIndexFor(noteId) {
    let idx = shaIndexes.get(noteId);
    if (!idx) {
      idx = new Map();
      shaIndexes.set(noteId, idx);
    }
    return idx;
  }

  function isRef(s) { return typeof s === 'string' && s.startsWith(REF_PREFIX) && BASE_RE.test(s.slice(REF_PREFIX.length)); }
  function refName(s) { return s.slice(REF_PREFIX.length); }

  // content: { title, body, html, images: [dataUrl], audio: { id: {data, dur, name} }, drawing }
  // -> { content (references instead of data), keep: [names], bytes: total stored in B2 }
  async function externalize(noteId, content, locked, onPrepare) {
    const none = { content, keep: [], kinds: {}, sizes: {}, bytes: 0, counts: null };
    if (!enabled()) return none;

    const images = content.images || [];
    const audio = content.audio || {};
    const videos = content.videos || {};
    const videoIds = Object.keys(videos).filter((id) => videos[id] && Array.isArray(videos[id].parts));
    const existingManifest = (content._lazyManifest && typeof content._lazyManifest === 'object') ? content._lazyManifest : ((content.media && typeof content.media === 'object') ? content.media : null);
    const wantsImage = images.some((s) => parseDataURL(s) || isRef(s));
    const audioIds = Object.keys(audio).filter((id) => audio[id] && parseDataURL(audio[id].data));
    if (!wantsImage && !audioIds.length && !videoIds.length) return none;

    // Every note gets a persistent per-note mediaKey from its first media save, so all new media is
    // encrypted at rest from the start. Locking or unlocking a note later only re-writes the small
    // note JSON (wrapping or unwrapping mediaKey) and NEVER re-encrypts or re-uploads media files.
    const anyEncVideo = videoIds.some((id) => videos[id].enc);
    const anyEncLazyPhoto = images.some((s) => isRef(s) && existingManifest && existingManifest[refName(s)] && existingManifest[refName(s)].iv);
    let keyB64 = await loadNoteKey(noteId);
    if (!keyB64 && content._lazyMediaKey) {
      keyB64 = content._lazyMediaKey;
      await saveNoteKey(noteId, keyB64);
    }
    if (!keyB64) {
      if (anyEncLazyPhoto || anyEncVideo) {
        throw uploadError('Missing encryption key for existing media \u2014 please reopen the note before saving.', { userMessage: true });
      }
      keyB64 = await genKeyB64();
      await saveNoteKey(noteId, keyB64);
    }
    const key = keyB64 ? await importKey(keyB64) : null;
    const idx = indexFor(noteId);
    const sIdx = shaIndexFor(noteId);
    // Hydrate plainSha index from local IndexedDB INFO records so reloads or cache evictions never
    // lose track of already-prepared or already-uploaded files for this note.
    try {
      const existingInfos = await infoForNote(noteId);
      for (const inf of existingInfos) {
        if (!inf || !inf.plainSha || isPartName(inf.name)) continue;
        if (!sIdx.has(inf.plainSha)) {
          sIdx.set(inf.plainSha, {
            name: inf.name,
            t: inf.t || (inf.kind === 'audio' ? 'audio/mpeg' : 'image/jpeg'),
            n: inf.size,
            h: inf.sha || '',
            iv: inf.iv || null,
            enc: !!inf.iv,
            keyB64: inf.iv ? (inf.keyB64 || keyB64) : null,
            plainSha: inf.plainSha,
          });
        }
      }
    } catch (e) { /* best-effort */ }

    const manifest = {};
    const kinds = {};
    const sizes = {};
    let usedKey = false;
    async function refFor(dataUrl, kind) {
      let e = idx.get(dataUrl);
      let decoded = null;
      let plainSha = e && e.plainSha ? e.plainSha : '';
      // If not found by exact dataUrl string, match by plaintext SHA-256 (survives reloads,
      // drafts, renames, lock toggles, and mid-upload edits without ever re-uploading).
      if (!e) {
        decoded = await dataUrlToBytes(dataUrl);
        plainSha = await sha256Hex(decoded.bytes);
        const bySha = sIdx.get(plainSha);
        if (bySha && (!bySha.enc || !bySha.keyB64 || bySha.keyB64 === keyB64)) {
          e = bySha;
          idx.set(dataUrl, e);
        }
      }
      // Reuse any existing valid reference (including already-uploaded legacy plaintext files
      // when locking mid-upload/later) so locking/unlocking/renaming/adding photos NEVER restarts
      // from zero. Brand-new files are always encrypted with the note's persistent key.
      const reusable = !!(e && (!e.enc || !e.keyB64 || e.keyB64 === keyB64));
      if (!reusable) {
        const { type, bytes } = decoded || await dataUrlToBytes(dataUrl);
        if (!plainSha) plainSha = await sha256Hex(bytes);
        const enc = await encryptBytes(key, bytes);
        const stored = enc.bytes;
        const iv = enc.iv;
        if (stored.length > MAX_ITEM_BYTES) {
          const err = new Error('A photo or audio clip is over the 90 MB limit');
          err.tooBig = true;
          throw err;
        }
        const name = randomName();
        const sha = await sha256Hex(stored);
        await cachePut(noteId, name, stored, true, { kind, sha, plainSha, t: type, iv, keyB64 });
        e = { name, t: type, n: stored.length, h: sha, iv, enc: true, keyB64, plainSha };
        idx.set(dataUrl, e);
        sIdx.set(plainSha, e);
      } else if (!(await infoGet(noteId, e.name))) {
        // An earlier save already made this file, but this device no longer holds a copy (it was
        // cleaned up, or dropped to stay under the size cap). Put one back, byte for byte - same key,
        // same iv, same plaintext gives the same stored bytes - so that if the bucket has lost the
        // file too, uploadPending can send it again instead of the note pointing at nothing.
        const { type, bytes } = decoded || await dataUrlToBytes(dataUrl);
        if (!plainSha) plainSha = await sha256Hex(bytes);
        let stored = bytes;
        if (e.iv) stored = new Uint8Array(await root.crypto.subtle.encrypt({ name: 'AES-GCM', iv: b64ToBytes(e.iv) }, key, bytes));
        if (stored.length === e.n) await cachePut(noteId, e.name, stored, false, { kind, sha: e.h || '', plainSha, t: e.t || type, iv: e.iv || null, keyB64: e.iv ? keyB64 : null });
      }
      if (e.iv) usedKey = true;
      // n = size and h = SHA-256 of the stored bytes: checked again whenever the file is downloaded.
      const entry = { t: e.t, n: e.n };
      if (e.h) entry.h = e.h;
      if (e.iv) entry.iv = e.iv;
      manifest[e.name] = entry;
      kinds[e.name] = kind;
      sizes[e.name] = e.n;
      return REF_PREFIX + e.name;
    }

    const out = { ...content };
    delete out._lazyManifest;
    delete out._lazyMediaKey;
    out.images = [];
    let prepared = 0;
    const prepTotal = images.filter((s) => parseDataURL(s)).length + audioIds.length;
    const tick = () => { prepared++; if (onPrepare) onPrepare(prepared, prepTotal); };
    for (const s of images) {
      if (parseDataURL(s)) {
        out.images.push(await refFor(s, 'photo'));
        tick();
      } else if (isRef(s)) {
        const name = refName(s);
        const em = existingManifest && existingManifest[name];
        if (em) {
          const entry = { t: em.t, n: em.n };
          if (em.h) entry.h = em.h;
          if (em.iv) { entry.iv = em.iv; usedKey = true; }
          manifest[name] = entry;
          kinds[name] = 'photo';
          sizes[name] = em.n;
        }
        out.images.push(s);
      } else {
        out.images.push(s);
      }
    }
    if (Object.keys(audio).length) {
      out.audio = {};
      for (const id of Object.keys(audio)) {
        const clip = audio[id];
        if (clip && parseDataURL(clip.data)) { out.audio[id] = { ...clip, data: await refFor(clip.data, 'audio') }; tick(); } else out.audio[id] = clip;
      }
    }
    out.media = manifest;
    const keep = Object.keys(manifest);
    let bytes = keep.reduce((n, k) => n + manifest[k].n, 0);

    // Videos: each is already a list of parts on this device (video.js made them when it was added). All that
    // is left to do here is make sure they are in the right form - encrypted if the note is locked - and list
    // every part, so the save knows what to send and the bucket's cleanup knows what to keep.
    const releaseBases = [];
    if (videoIds.length) {
      out.videos = {};
      for (const id of videoIds) {
        const v = await root.KSVideo.prepare(noteId, videos[id], {
          locked, key, keyB64, deferRelease: true, releaseBases,
          onProgress: (done, total) => { if (onPrepare) onPrepare(done, total, 'video'); },
        });
        out.videos[id] = v;
        v.parts.forEach((p, i) => {
          const name = v.base + '.' + String(i).padStart(5, '0');
          keep.push(name);
          kinds[name] = 'video';
          sizes[name] = p.n;
          bytes += p.n;
        });
      }
    }
    if (keyB64 && (locked || usedKey || anyEncVideo || Object.values(out.videos || {}).some((v) => v && v.enc))) out.mediaKey = keyB64;
    const counts = { photos: out.images.filter((s) => isRef(s)).length, clips: audioIds.length, videos: videoIds.length };
    return { content: out, keep, kinds, sizes, bytes, counts, releaseBases };
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
    // The key is remembered first: a note with only videos has no photo manifest but still needs it to play.
    if (content && content.mediaKey) await saveNoteKey(noteId, content.mediaKey);
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

    const nameList = Array.from(names);
    let nextIdx = 0;
    const workerCount = Math.min(5, nameList.length);
    await Promise.all(Array.from({ length: workerCount }, async () => {
      while (nextIdx < nameList.length) {
        const name = nameList[nextIdx++];
        const entryMeta = manifest[name];
        if (!entryMeta) throw new Error('A photo or audio clip in this note has no record \u2014 the note looks damaged.');
        let stored = await cacheGet(noteId, name).catch(() => null);
        let fromCache = !!stored;
        // Verify size AND SHA-256 of cached media so bit-rot self-heals instead of bricking locked notes.
        if (stored) {
          const badSize = !!(entryMeta.n && stored.length !== entryMeta.n);
          const badHash = !badSize && !!(entryMeta.h && (await sha256Hex(stored)) !== entryMeta.h);
          if (badSize || badHash) {
            const info = await infoGet(noteId, name).catch(() => null);
            if (info && info.pending) throw new Error('A photo or clip waiting to upload is damaged on this device.');
            await cacheDelete([{ id: idOf(noteId, name) }]).catch(() => {});
            stored = null;
            fromCache = false;
          }
        }
        const fetchFresh = async () => {
          if (!announced && o.onDownload) { announced = true; o.onDownload(); }
          let bytes;
          try { bytes = await downloadBytes(noteId, name); } catch (e) {
            if (e.isNetworkError) throw notAvailableOffline(e);
            throw e;
          }
          if (entryMeta.n && bytes.length !== entryMeta.n) throw new Error('A photo or audio clip came back the wrong size \u2014 try again.');
          if (entryMeta.h && await sha256Hex(bytes) !== entryMeta.h) throw new Error('A photo or audio clip came back damaged \u2014 try again.');
          await cachePut(noteId, name, bytes, false, { sha: entryMeta.h || '', kind: /^audio\//i.test(entryMeta.t || '') ? 'audio' : 'photo' }).catch(() => {});
          return bytes;
        };
        if (!stored) stored = await fetchFresh();
        let plain = stored;
        if (entryMeta.iv) {
          if (!key) throw new Error('This note\u2019s media is encrypted but its key is missing.');
          try {
            plain = await decryptBytes(key, entryMeta.iv, stored);
          } catch (decErr) {
            if (!fromCache) throw decErr;
            const info = await infoGet(noteId, name).catch(() => null);
            if (info && info.pending) throw decErr;
            await cacheDelete([{ id: idOf(noteId, name) }]).catch(() => {});
            stored = await fetchFresh();
            plain = await decryptBytes(key, entryMeta.iv, stored);
          }
        }
        const plainSha = await sha256Hex(plain);
        dataByName[name] = { url: await bytesToDataUrl(plain, entryMeta.t), entry: { name, t: entryMeta.t, n: entryMeta.n, h: entryMeta.h || '', iv: entryMeta.iv || null, enc: !!entryMeta.iv, keyB64: entryMeta.iv ? content.mediaKey : null, plainSha } };
      }
    }));

    const idx = indexFor(noteId);
    const sIdx = shaIndexFor(noteId);
    if (content.mediaKey) await saveNoteKey(noteId, content.mediaKey);
    const pick = (s) => {
      if (!isRef(s)) return s;
      const d = dataByName[refName(s)];
      if (!d) throw new Error('A photo or audio clip in this note could not be found.');
      idx.set(d.url, d.entry);
      if (d.entry.plainSha) sIdx.set(d.entry.plainSha, d.entry);
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

  // Deduplicates concurrent lazy loads of the same photo while scrolling.
  const inFlightLoads = new Map();

  // Loads and decrypts ONE media item on demand (from local cache if available, otherwise from B2).
  // Returns { blob, type, bytes, entry } so the UI can display a fast blob: URL without bloating RAM.
  async function loadOne(noteId, name, entryMeta, keyB64) {
    if (!entryMeta) throw new Error('A photo or audio clip in this note has no record \u2014 the note looks damaged.');
    const flightKey = noteId + '/' + name;
    if (inFlightLoads.has(flightKey)) return inFlightLoads.get(flightKey);
    const p = (async () => {
      const kB64 = keyB64 || await loadNoteKey(noteId);
      const key = entryMeta.iv ? (kB64 ? await importKey(kB64) : null) : null;
      if (entryMeta.iv && !key) throw new Error('This note\u2019s media is encrypted but its key is missing.');
      let stored = await cacheGet(noteId, name).catch(() => null);
      let fromCache = !!stored;
      if (stored) {
        const badSize = !!(entryMeta.n && stored.length !== entryMeta.n);
        const badHash = !badSize && !!(entryMeta.h && (await sha256Hex(stored)) !== entryMeta.h);
        if (badSize || badHash) {
          const info = await infoGet(noteId, name).catch(() => null);
          if (info && info.pending) throw new Error('A photo or clip waiting to upload is damaged on this device.');
          await cacheDelete([{ id: idOf(noteId, name) }]).catch(() => {});
          stored = null;
          fromCache = false;
        }
      }
      const fetchFresh = async () => {
        let bytes;
        try { bytes = await downloadBytes(noteId, name); } catch (e) {
          if (e.isNetworkError) throw notAvailableOffline(e);
          throw e;
        }
        if (entryMeta.n && bytes.length !== entryMeta.n) throw new Error('A photo or audio clip came back the wrong size \u2014 try again.');
        if (entryMeta.h && await sha256Hex(bytes) !== entryMeta.h) throw new Error('A photo or audio clip came back damaged \u2014 try again.');
        await cachePut(noteId, name, bytes, false, { sha: entryMeta.h || '', kind: /^audio\//i.test(entryMeta.t || '') ? 'audio' : 'photo', t: entryMeta.t || '', iv: entryMeta.iv || null, keyB64: entryMeta.iv ? kB64 : null }).catch(() => {});
        return bytes;
      };
      if (!stored) stored = await fetchFresh();
      let plain = stored;
      if (entryMeta.iv) {
        try {
          plain = await decryptBytes(key, entryMeta.iv, stored);
        } catch (decErr) {
          if (!fromCache) throw decErr;
          const info = await infoGet(noteId, name).catch(() => null);
          if (info && info.pending) throw decErr;
          await cacheDelete([{ id: idOf(noteId, name) }]).catch(() => {});
          stored = await fetchFresh();
          plain = await decryptBytes(key, entryMeta.iv, stored);
        }
      }
      const type = entryMeta.t || 'image/jpeg';
      const blob = new root.Blob([plain], { type });
      return { blob, type, size: plain.length };
    })().finally(() => { inFlightLoads.delete(flightKey); });
    inFlightLoads.set(flightKey, p);
    return p;
  }

  // Instant-open inflation: keeps photos as lightweight "ks-media:<name>" refs so notes with
  // dozens/hundreds of photos (especially locked notes) open immediately and load photos only as
  // they scroll into view. Audio clips (small, few) are still inflated upfront.
  async function inflateLazy(noteId, content, opts) {
    if (content && content.mediaKey) await saveNoteKey(noteId, content.mediaKey);
    const manifest = content && content.media;
    if (!manifest || typeof manifest !== 'object') return content;
    const out = { ...content };
    const keyB64 = content.mediaKey || null;
    // Inflate any audio clips immediately (usually 0-3 clips), leave photos lazy.
    if (content.audio && Object.keys(content.audio).length) {
      out.audio = {};
      const idx = indexFor(noteId);
      const sIdx = shaIndexFor(noteId);
      for (const id of Object.keys(content.audio)) {
        const clip = content.audio[id];
        if (clip && isRef(clip.data)) {
          const name = refName(clip.data);
          const em = manifest[name];
          const loaded = await loadOne(noteId, name, em, keyB64);
          const bytes = new Uint8Array(await blobBytes(loaded.blob));
          const url = await bytesToDataUrl(bytes, em.t);
          const plainSha = await sha256Hex(bytes);
          const entry = { name, t: em.t, n: em.n, h: em.h || '', iv: em.iv || null, enc: !!em.iv, keyB64: em.iv ? keyB64 : null, plainSha };
          idx.set(url, entry);
          sIdx.set(plainSha, entry);
          out.audio[id] = { ...clip, data: url };
        } else {
          out.audio[id] = clip;
        }
      }
    }
    out._lazyManifest = { ...manifest };
    out._lazyMediaKey = keyB64;
    delete out.media;
    delete out.mediaKey;
    return out;
  }

  /* ----------------------------------------------------------------- uploading */

  function uploadError(message, extra) {
    const err = new Error(message);
    Object.assign(err, extra || {});
    return err;
  }

  // What is still to send for `names`: { name: kind } for every file that exists only on this
  // device. (Also what the progress display counts.)
  async function pendingKinds(noteId, names, kinds) {
    const out = {};
    for (const name of names || []) {
      if (!NAME_RE.test(name)) continue;
      const info = await infoGet(noteId, name);
      if (info && info.pending) out[name] = info.kind || (kinds && kinds[name]) || 'photo';
    }
    return out;
  }

  // For the progress display: each of `names` as { kind, size, pending }. A file this device no longer
  // holds a record of was uploaded earlier (files waiting to upload are never dropped).
  async function describe(noteId, names, kinds) {
    const out = {};
    for (const name of names || []) {
      if (!NAME_RE.test(name)) continue;
      const info = await infoGet(noteId, name);
      out[name] = { kind: (info && info.kind) || (kinds && kinds[name]) || 'photo', size: info ? info.size : 0, pending: !!(info && info.pending) };
    }
    return out;
  }

  // Sends the files in `names` that the bucket does not have yet, ONE AT A TIME, and only then returns.
  //
  //   - It first asks the bucket what it already holds, so after an interruption (app closed,
  //     connection lost, even between the last byte of a file and this device writing that down) it
  //     carries on with the next file instead of starting over. A file cut off mid-send is sent again
  //     in full - S3 stores a file whole or not at all, so there is never a half-written copy.
  //   - Before sending, the copy on this device is checked against the SHA-256 taken when it was made.
  //   - After sending, the bucket is asked what it stored; the size has to match before the file is
  //     marked as uploaded.
  //   - A file that is neither on this device nor correctly in the bucket stops the save with a clear
  //     error: a note is never written referring to a file that is not there.
  //
  // opts: { sizes: {name: bytes}, onPlan({todo}), onFileStart, onFileProgress, onFileDone }
  async function uploadPending(noteId, names, opts) {
    const o = opts || {};
    const sizes = o.sizes || {};
    const wanted = (names || []).filter((n) => NAME_RE.test(n));
    if (!wanted.length) return 0;

    let remote = null;
    try { remote = new Map((await list(noteId)).map((i) => [i.name, i.size])); }
    catch (e) { if (e.isNetworkError) throw e; remote = null; } // can't list: fall back to "send what is pending"

    const todo = [];
    const missing = [];
    const todoParts = []; // video parts: sent after the photos and clips, section by section
    for (const name of wanted) {
      const info = await infoGet(noteId, name);
      if (isPartName(name)) {
        // Every part of every video is checked against the bucket on EVERY save: one the bucket has lost (or
        // holds at the wrong size) is sent again from this device's copy, not just the ones still marked pending.
        const want = info ? info.size : sizes[name];
        const there = remote ? remote.get(name) : undefined;
        if (remote && there !== undefined && (!want || there === want)) {
          if (info && info.pending) await markSynced(noteId, name);
        } else if (info && (remote || info.pending)) todoParts.push(info);
        else if (remote && !info) missing.push(name);
        continue;
      }
      const want = info ? info.size : sizes[name];
      if (remote) {
        const there = remote.get(name);
        if (there !== undefined && (!want || there === want)) {
          if (info && info.pending) await markSynced(noteId, name); // it got there; only the note-keeping was missed
          continue;
        }
        if (!info) { missing.push(name); continue; }
        todo.push(info);
      } else if (info && info.pending) {
        todo.push(info);
      }
    }
    if (missing.length) {
      throw uploadError(missing.length === 1
        ? 'A photo, clip or video part is missing from both this device and your bucket, so this note can\u2019t be saved safely.'
        : missing.length + ' photos, clips or video parts are missing from both this device and your bucket, so this note can\u2019t be saved safely.',
      { missingMedia: missing });
    }
    if (o.onPlan) o.onPlan({ todo: todo.concat(todoParts).map((i) => ({ name: i.name, size: i.size, kind: i.kind || 'photo' })) });

    let uploadedCount = 0;
    for (let i = 0; i < todo.length; i++) {
      if (o.shouldYield && o.shouldYield()) return { uploaded: uploadedCount, yielded: true };
      const info = todo[i];
      const kind = info.kind || 'photo';
      if (o.onFileStart) o.onFileStart({ name: info.name, kind, size: info.size, index: i, count: todo.length });
      const bytes = await cacheGet(noteId, info.name);
      if (!bytes) throw uploadError('A photo or clip waiting to upload is missing from this device.');
      if (bytes.length !== info.size) throw uploadError('A photo or clip waiting to upload is damaged on this device (wrong size).');
      const sha = await sha256Hex(bytes);
      if (info.sha && info.sha !== sha) throw uploadError('A photo or clip waiting to upload is damaged on this device.');
      await uploadBytes(noteId, info.name, bytes, sha, (loaded, total) => {
        if (o.onFileProgress) o.onFileProgress({ name: info.name, kind, loaded, total: total || bytes.length });
      });
      await root.KSB2.verifyStored(root.KSB2.mediaKey(noteId, info.name), bytes.length);
      await markSynced(noteId, info.name);
      uploadedCount++;
      if (o.onFileDone) o.onFileDone({ name: info.name, kind, size: info.size, index: i, count: todo.length });
      if (o.shouldYield && o.shouldYield()) return { uploaded: uploadedCount, yielded: true };
    }
    if (todoParts.length) {
      const vr = await sendVideoParts(noteId, todoParts, o);
      if (vr && vr.yielded) return { uploaded: uploadedCount + (vr.uploaded || 0), yielded: true };
    }
    if (todo.length || todoParts.length) scheduleEvict();
    return todo.length + todoParts.length;
  }

  // Sends video parts one at a time. A part is only counted as done once a listing of the bucket shows it there at
  // the right size - checked every few parts rather than after each one, so a 500 MB video isn't 125 extra
  // round trips. Anything the bucket turns out not to hold is sent again, up to VERIFY_ROUNDS times. If the
  // connection drops (or the phone goes to sleep) half way, the parts sent so far stay in the bucket, and the next
  // run starts from the list above: only what is missing goes again.
  async function sendVideoParts(noteId, infos, o) {
    let queue = infos.slice();
    let sent = 0;
    let started = 0;
    const total = infos.length;
    for (let round = 0; round < VERIFY_ROUNDS && queue.length; round++) {
      const failed = [];
      let batch = [];
      const check = async () => {
        if (!batch.length) return;
        const here = new Map((await list(noteId)).map((i) => [i.name, i.size]));
        for (const info of batch) {
          if (here.get(info.name) === info.size) {
            await markSynced(noteId, info.name);
            if (o.onFileDone) o.onFileDone({ name: info.name, kind: 'video', size: info.size, index: sent, count: total });
            sent++;
          } else failed.push(info);
        }
        batch = [];
      };
      for (let i = 0; i < queue.length; i++) {
        if (o.shouldYield && o.shouldYield()) { await check(); return { uploaded: sent, yielded: true }; }
        const info = queue[i];
        if (o.onFileStart) o.onFileStart({ name: info.name, kind: 'video', size: info.size, index: Math.min(started++, total - 1), count: total });
        const blob = await cacheGetBlob(noteId, info.name);
        if (!blob) throw uploadError('A video part waiting to upload is missing from this device.');
        const bytes = new Uint8Array(await blobBytes(blob));
        if (bytes.length !== info.size) throw uploadError('A video part waiting to upload is damaged on this device (wrong size).');
        const sha = await sha256Hex(bytes);
        if (info.sha && info.sha !== sha) throw uploadError('A video part waiting to upload is damaged on this device.');
        await uploadBytes(noteId, info.name, bytes, sha, (loaded, tot) => {
          if (o.onFileProgress) o.onFileProgress({ name: info.name, kind: 'video', loaded, total: tot || bytes.length });
        });
        batch.push(info);
        if (batch.length >= VERIFY_EVERY) await check();
        if (o.shouldYield && o.shouldYield()) { await check(); return { uploaded: sent, yielded: true }; }
      }
      await check();
      queue = failed;
    }
    if (queue.length) {
      throw uploadError('Backblaze didn\u2019t keep ' + queue.length + ' part' + (queue.length === 1 ? '' : 's') + ' of a video even after sending ' + (queue.length === 1 ? 'it' : 'them') + ' again. Try again in a moment.', { verifyFailed: true });
    }
  }

  // After a note is saved or queued: forget local copies it no longer refers to.
  async function reconcile(noteId, keepNames) {
    const keep = new Set(keepNames || []);
    const mine = await infoForNote(noteId);
    await cacheDelete(mine.filter((i) => !keep.has(i.name) && !heldBases.has(baseOf(i.name))));
  }

  // Video parts nobody refers to any more: ones left by a note that was never saved (or a video added and then
  // abandoned), so gigabytes don't pile up on the device unseen. `knownIds` = every note, draft or queued save
  // this device still has. Only parts older than a day are touched.
  async function sweepOrphans(knownIds) {
    const known = new Set(knownIds || []);
    const cutoff = Date.now() - 24 * 60 * 60 * 1000;
    const all = (await req(INFO, 'getAll')) || [];
    const stray = all.filter((i) => i.kind === 'video' && !known.has(i.noteId) && !heldBases.has(baseOf(i.name)) && i.used < cutoff);
    await cacheDelete(stray);
    return stray.length;
  }

  // The note's media key (persisted in IndexedDB), made on the spot if asked.
  async function noteKey(noteId, create) {
    let keyB64 = await loadNoteKey(noteId);
    if (!keyB64 && create) { keyB64 = await genKeyB64(); await saveNoteKey(noteId, keyB64); }
    return keyB64 ? { keyB64, key: await importKey(keyB64) } : null;
  }

  async function dropNote(noteId) {
    indexes.delete(noteId);
    shaIndexes.delete(noteId);
    noteKeys.delete(noteId);
    const mine = await infoForNote(noteId);
    mine.push({ id: keyRecordId(noteId) });
    await cacheDelete(mine);
  }

  /* ----------------------------------------------------- offline + download helpers */

  async function list(noteId) {
    return root.KSB2.listMedia(noteId);
  }

  // Quietly fetches a note's media so the note opens offline, while there is room.
  async function prefetchNote(noteId, expectedBytes) {
    // Video parts are not fetched ahead: they are far too big, and are brought over when a video is played.
    const have = (await infoForNote(noteId)).filter((i) => i.kind !== 'video');
    if (have.reduce((n, i) => n + i.size, 0) >= expectedBytes) return;
    let used = await cacheBytesUsed();
    const haveNames = new Set(have.map((i) => i.name));
    for (const item of await list(noteId)) {
      if (isPartName(item.name) || haveNames.has(item.name)) continue;
      if (used + item.size > cacheCap) return;
      const bytes = await downloadBytes(noteId, item.name);
      await cachePut(noteId, item.name, bytes, false);
      used += bytes.length;
    }
  }

  // For "Download": adds the stored bytes of every file the note has (still encrypted for a
  // locked note) next to the note, so the downloaded file is a complete backup.
  function rawToB64(raw) {
    if (typeof root.FileReader === 'function' && typeof root.Blob === 'function') {
      const blob = isBlob(raw) ? raw : new root.Blob([raw], { type: 'application/octet-stream' });
      return new Promise((resolve, reject) => {
        const r = new root.FileReader();
        r.onload = () => {
          const s = String(r.result);
          const comma = s.indexOf(',');
          resolve(comma >= 0 ? s.slice(comma + 1) : s);
        };
        r.onerror = () => reject(r.error || new Error('Could not read media'));
        r.readAsDataURL(blob);
      });
    }
    return Promise.resolve(bytesToB64(raw instanceof Uint8Array ? raw : new Uint8Array(raw)));
  }

  async function attachToBundle(noteId, bundle, opts, activeNames) {
    const o = opts || {};
    let items;
    try { items = await list(noteId); } catch (e) {
      if (!e.isNetworkError) throw e;
      // Offline: whatever this device holds for the note is what can go in the file.
      items = (await infoForNote(noteId)).map((i) => ({ name: i.name, size: i.size }));
    }
    // Videos are far too big to put inside one file: the note's list of parts goes in, the parts stay in the bucket.
    const videoItems = items.filter((i) => isPartName(i.name));
    if (videoItems.length) {
      const vbytes = videoItems.reduce((n, i) => n + i.size, 0);
      bundle._videoNote = 'This note has ' + Math.round(vbytes / 1048576) + ' MB of video in Backblaze, kept as ' + videoItems.length + ' parts under media/' + noteId + '/ (each part is named <video>.<part number>). They are not included here.';
      items = items.filter((i) => !isPartName(i.name));
    }
    const filterNames = activeNames || o.activeNames;
    if (filterNames) {
      const validNames = new Set(filterNames);
      items = items.filter((i) => validNames.has(i.name));
    } else if (bundle && bundle.content && bundle.content.media && typeof bundle.content.media === 'object') {
      const validNames = new Set(Object.keys(bundle.content.media));
      items = items.filter((i) => validNames.has(i.name));
    }
    if (!items.length) return bundle;
    const total = items.reduce((n, i) => n + i.size, 0);
    const limit = o.maxBytes || 50 * 1024 * 1024;
    if (total > limit) {
      bundle._mediaNote = 'This note has ' + Math.round(total / 1048576) + ' MB of photos and audio in Backblaze, too large to include here. They are in your bucket under media/' + noteId + '/.';
      return bundle;
    }
    if (o.onDownload) o.onDownload();
    const media = {};
    for (const item of items) {
      let raw = await cacheRecord(noteId, item.name).catch(() => null);
      const rawSize = raw ? (isBlob(raw) ? raw.size : raw.byteLength) : 0;
      if (raw && item.size && rawSize !== item.size) raw = null;
      if (!raw) raw = await downloadBytes(noteId, item.name);
      media[item.name] = await rawToB64(raw);
    }
    bundle.media = media;
    bundle._mediaHint = 'Each entry is a file from the note, base64-encoded. In the note, "ks-media:<name>" refers to media[<name>]. For a locked note these are encrypted: decrypt with AES-GCM using the note\u2019s mediaKey and each file\u2019s iv.';
    return bundle;
  }

  root.KSMedia = {
    REF_PREFIX, NAME_RE, MAX_ITEM_BYTES, CACHE_CAP_BYTES, VIDEO_CACHE_CAP_BYTES,
    available, enabled,
    isRef, refName, loadOne, inflateLazy, externalize, inflate, uploadPending, pendingKinds, describe, reconcile, dropNote,
    prefetchNote, attachToBundle, cacheBytesUsed,
    sweepOrphans, noteKey,
    hold(base) { heldBases.add(base); }, release(base) { heldBases.delete(base); },
    // What video.js builds on: the local store of parts and the plumbing around it.
    store: {
      cachePut, cacheGet, cacheGetBlob, infoGet, infoForNote, markSynced, cacheDelete, blobBytes, pin, allInfo, setKinds, deleteSynced,
      sha256Hex, randomName, genKeyB64, importKey, encryptBytes, decryptBytes, downloadBytes, list, b64ToBytes,
    },
    _test: { setCap(n) { cacheCap = n; }, resetMemory() { indexes.clear(); shaIndexes.clear(); noteKeys.clear(); }, parseDataURL, bytesToDataUrl, cachePut, cacheGet, infoGet, infoForNote, evict, indexes, shaIndexes, noteKeys },
  };
})(typeof window !== 'undefined' ? window : globalThis);
