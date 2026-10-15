/* Keepsake — media.js
 * Photos, audio, and sliced video packets kept as separate files in your Backblaze B2 bucket instead of inside the note.
 *
 * How it fits together
 *   - In the editor nothing changes: photos, clips, and videos are data: URLs.
 *   - When a note is SAVED, every data: URL is swapped for a short reference ("ks-media:<name>")
 *     and the bytes are queued for upload. A manifest in the note says what each reference is.
 *     For a locked note the bytes are encrypted first, with a random key that lives inside the
 *     note's own encrypted content, so the bucket only ever holds ciphertext for those.
 *   - Videos (and large media) are sliced into multiple tagged sections/packets
 *     ("<name>_s0001of0004_<sha8>") with per-packet SHA-256 hashes and byte offsets. Each packet
 *     is uploaded and verified individually so the phone sleeping mid-upload never loses progress,
 *     and any lost or damaged packet is detected and re-uploaded automatically.
 *   - When a note is OPENED, the references are swapped back for data: URLs (from this device's
 *     copy if it has one, otherwise downloaded — packet by packet for sliced videos — from the bucket).
 *   - Uploads and downloads go straight to the bucket through b2.js.
 *
 * Self-contained on purpose: its own small IndexedDB ("keepsake-media"), its own helpers.
 */
(function (root) {
  'use strict';

  const REF_PREFIX = 'ks-media:';
  const NAME_RE = /^[a-f0-9]{32}$/;
  const PACKET_NAME_RE = /^[a-f0-9]{32}_s\d{4}of\d{4}_[a-f0-9]{8}$/;
  const MAX_ITEM_BYTES = 90 * 1024 * 1024; // per file: a photo, clip or video is held in memory while a note is open
  const CACHE_CAP_BYTES = 300 * 1024 * 1024; // synced copies kept on this device; oldest-used go first
  // Maximum size of a single video upload packet (2 MB). Smaller videos are still sliced into
  // at least 3–6 tagged packets so they never have to go in one monolithic request.
  const VIDEO_MAX_PACKET_BYTES = 2 * 1024 * 1024;
  const VIDEO_MIN_PACKETS = 3;
  const PACKET_MAX_RETRIES = 3;
  let cacheCap = CACHE_CAP_BYTES;
  const DB_NAME = 'keepsake-media';
  const INFO = 'info';   // light: { id, noteId, name, size, used, pending, kind, sha, packets }
  const BLOB = 'blob';   // heavy: { id, bytes }

  /* ------------------------------------------------------------------ helpers */

  function hex(buf) {
    return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
  }

  function randomName() {
    return hex(root.crypto.getRandomValues(new Uint8Array(16)));
  }

  function pad4(n) {
    return String(n).padStart(4, '0');
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
    if (root.crypto && root.crypto.subtle) return hex(await root.crypto.subtle.digest('SHA-256', bytes));
    if (root.KSB2 && root.KSB2.sha256Hex) return root.KSB2.sha256Hex(bytes);
    return "";
  }

  // Slices `bytes` into tagged packets for section-by-section cloud upload.
  // Each packet gets its own deterministic ID (<name>_s0001of0004_<sha8>), offset, length, and full SHA-256.
  async function sliceIntoPackets(name, bytes, isVideo) {
    if (!isVideo && bytes.length <= VIDEO_MAX_PACKET_BYTES) return null;
    const totalLen = bytes.length;
    if (totalLen === 0) return null;
    let chunkSize = VIDEO_MAX_PACKET_BYTES;
    if (totalLen <= VIDEO_MAX_PACKET_BYTES * VIDEO_MIN_PACKETS) {
      // Ensure even smaller videos are sliced into multiple tagged packets (at least 3 sections when >= 3 bytes)
      const targetCount = totalLen < 3 ? 1 : Math.min(6, Math.max(VIDEO_MIN_PACKETS, Math.ceil(totalLen / (384 * 1024))));
      chunkSize = Math.max(1, Math.ceil(totalLen / targetCount));
    }
    const count = Math.max(1, Math.ceil(totalLen / chunkSize));
    const packets = [];
    for (let idx = 0; idx < count; idx++) {
      const offset = idx * chunkSize;
      const end = Math.min(totalLen, offset + chunkSize);
      const slice = bytes.subarray(offset, end);
      const h = await sha256Hex(slice);
      const tag = `s${pad4(idx + 1)}of${pad4(count)}_${h.slice(0, 8)}`;
      const id = `${name}_${tag}`;
      packets.push({
        id,
        tag,
        idx,
        total: count,
        offset,
        n: slice.length,
        h,
      });
    }
    return packets;
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

  function createMemMediaDB() {
    const stores = { [INFO]: new Map(), [BLOB]: new Map() };
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

  function openDB() {
    if (dbPromise) return dbPromise;
    dbPromise = new Promise((resolve) => {
      try {
        if (!root.indexedDB) { resolve(createMemMediaDB()); return; }
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
        req.onerror = () => resolve(createMemMediaDB());
      } catch (e) {
        resolve(createMemMediaDB());
      }
    });
    return dbPromise;
  }
  function _unusedOldOpenDB() {
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

  // `extra` = { kind: 'photo' | 'audio' | 'video', sha, packets } - what the file is, its SHA-256,
  // and (for videos) its sliced packet manifest.
  async function cachePut(noteId, name, bytes, pending, extra) {
    const id = idOf(noteId, name);
    const x = extra || {};
    const sha = x.sha || (pending ? await sha256Hex(bytes) : '');
    const packets = Array.isArray(x.packets)
      ? x.packets.map((p) => ({ ...p, synced: pending ? !!p.synced : true }))
      : null;
    await run([INFO, BLOB], 'readwrite', (tx) => {
      // Structured cloning copies a typed array's whole underlying buffer, so only
      // hand over the buffer itself when the array covers all of it.
      const whole = bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength;
      tx.objectStore(BLOB).put({ id, bytes: whole ? bytes.buffer : bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) });
      const infoRec = { id, noteId, name, size: bytes.length, used: Date.now(), pending: !!pending, kind: x.kind || '', sha };
      if (packets) infoRec.packets = packets;
      tx.objectStore(INFO).put(infoRec);
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
    if (info) {
      const packets = Array.isArray(info.packets) ? info.packets.map((p) => ({ ...p, synced: true, lost: false })) : info.packets;
      await run(INFO, 'readwrite', (tx) => {
        tx.objectStore(INFO).put({ ...info, pending: false, packets, used: Date.now() });
      });
    }
  }

  async function markPacketState(noteId, name, pktIdx, synced, lost) {
    const info = await infoGet(noteId, name);
    if (!info || !Array.isArray(info.packets)) return;
    const packets = info.packets.map((p, i) => (i === pktIdx ? { ...p, synced: !!synced, lost: !!lost } : p));
    await run(INFO, 'readwrite', (tx) => {
      tx.objectStore(INFO).put({ ...info, packets, used: Date.now() });
    });
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

  async function noteBytes(noteId) {
    const items = await infoForNote(noteId);
    return items.reduce((n, i) => n + (i.size || 0), 0);
  }

  /* ------------------------------------------------------------ talking to the bucket */

  async function downloadBytes(noteId, name) {
    const bytes = await root.KSB2.getBytesOrNull(root.KSB2.mediaKey(noteId, name));
    if (!bytes) {
      const err = new Error('A photo, video, or audio clip is missing from your bucket');
      err.status = 404;
      throw err;
    }
    return bytes;
  }

  function uploadBytes(noteId, name, bytes, sha, onProgress) {
    return root.KSB2.putBytes(root.KSB2.mediaKey(noteId, name), bytes, sha, onProgress ? (loaded, total) => onProgress(loaded, total) : null);
  }

  /* ------------------------------------------------------------------- settings */

  // Photos, audio, and videos always live in the bucket once it is set up.
  function available() { return !!(root.indexedDB || (root.KSB2 && root.KSB2.config.configured())); }
  function enabled() { return available(); }

  /* ----------------------------------------------- references <-> data URLs */

  // For each note, remember which data URL was uploaded as which file, so saving the
  // same photo/video again is free. Only the last couple of notes are kept (the strings are big).
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

  // content: { title, body, html, images: [dataUrl], audio: { id: {data, dur, name} }, videos: { id: {data, dur, ...} }, drawing }
  // -> { content (references instead of data), keep: [names], kinds, sizes, packets, bytes: total stored in B2 }
  async function externalize(noteId, content, locked, onPrepare) {
    const none = { content, keep: [], kinds: {}, sizes: {}, packets: {}, bytes: 0 };
    if (!enabled()) return none;

    const images = content.images || [];
    const audio = content.audio || {};
    const videos = content.videos || {};
    const wantsImage = images.some((s) => parseDataURL(s));
    const audioIds = Object.keys(audio).filter((id) => audio[id] && parseDataURL(audio[id].data));
    const videoIds = Object.keys(videos).filter((id) => videos[id] && parseDataURL(videos[id].data));
    if (!wantsImage && !audioIds.length && !videoIds.length) return none;

    let keyB64 = null;
    if (locked) {
      keyB64 = noteKeys.get(noteId) || null;
      if (!keyB64) { keyB64 = await genKeyB64(); noteKeys.set(noteId, keyB64); }
    }
    const key = locked ? await importKey(keyB64) : null;
    const idx = indexFor(noteId);
    const manifest = {};

    const kinds = {};
    const sizes = {};
    const packetsByName = {};
    async function refFor(dataUrl, kind) {
      let e = idx.get(dataUrl);
      if (!(e && e.enc === locked && (!locked || e.keyB64 === keyB64))) {
        const { type, bytes } = await dataUrlToBytes(dataUrl);
        let stored = bytes;
        let iv = null;
        if (locked) { const enc = await encryptBytes(key, bytes); stored = enc.bytes; iv = enc.iv; }
        if (stored.length > MAX_ITEM_BYTES) {
          const err = new Error('A photo, video, or audio clip is over the 90 MB limit');
          err.tooBig = true;
          throw err;
        }
        const name = randomName();
        const sha = await sha256Hex(stored);
        const packets = await sliceIntoPackets(name, stored, kind === 'video');
        await cachePut(noteId, name, stored, true, { kind, sha, packets });
        e = { name, t: type, n: stored.length, h: sha, iv, enc: locked, keyB64: locked ? keyB64 : null, k: kind, packets };
        idx.set(dataUrl, e);
      } else if (!(await infoGet(noteId, e.name))) {
        // An earlier save already made this file, but this device no longer holds a copy (it was
        // cleaned up, or dropped to stay under the size cap). Put one back, byte for byte - same key,
        // same iv, same plaintext gives the same stored bytes - so that if the bucket has lost the
        // file or any of its packets too, uploadPending can send it again instead of the note pointing at nothing.
        const { bytes } = await dataUrlToBytes(dataUrl);
        let stored = bytes;
        if (locked && e.iv) stored = new Uint8Array(await root.crypto.subtle.encrypt({ name: 'AES-GCM', iv: b64ToBytes(e.iv) }, key, bytes));
        if (stored.length === e.n) {
          const packets = e.packets || await sliceIntoPackets(e.name, stored, kind === 'video');
          e.packets = packets;
          await cachePut(noteId, e.name, stored, false, { kind, sha: e.h || '', packets });
        }
      }
      // n = size and h = SHA-256 of the stored bytes: checked again whenever the file is downloaded.
      const entry = { t: e.t, n: e.n, k: kind };
      if (e.h) entry.h = e.h;
      if (e.iv) entry.iv = e.iv;
      if (e.packets && e.packets.length) {
        entry.packets = e.packets.map((p) => ({
          id: p.id, tag: p.tag, idx: p.idx, total: p.total, offset: p.offset, n: p.n, h: p.h,
        }));
        packetsByName[e.name] = entry.packets;
      }
      manifest[e.name] = entry;
      kinds[e.name] = kind;
      sizes[e.name] = e.n;
      return REF_PREFIX + e.name;
    }

    const out = { ...content };
    out.images = [];
    let prepared = 0;
    const prepTotal = images.filter((s) => parseDataURL(s)).length + audioIds.length + videoIds.length;
    const tick = () => { prepared++; if (onPrepare) onPrepare(prepared, prepTotal); };
    for (const s of images) {
      if (parseDataURL(s)) { out.images.push(await refFor(s, 'photo')); tick(); } else out.images.push(s);
    }
    if (Object.keys(audio).length) {
      out.audio = {};
      for (const id of Object.keys(audio)) {
        const clip = audio[id];
        if (clip && parseDataURL(clip.data)) { out.audio[id] = { ...clip, data: await refFor(clip.data, 'audio') }; tick(); } else out.audio[id] = clip;
      }
    }
    if (Object.keys(videos).length) {
      out.videos = {};
      for (const id of Object.keys(videos)) {
        const vid = videos[id];
        if (vid && parseDataURL(vid.data)) {
          const ref = await refFor(vid.data, 'video');
          const mName = refName(ref);
          out.videos[id] = {
            ...vid,
            data: ref,
            mediaName: mName,
            packets: packetsByName[mName] || null,
          };
          tick();
        } else {
          out.videos[id] = vid;
        }
      }
    }
    out.media = manifest;
    if (locked) out.mediaKey = keyB64;
    const keep = Object.keys(manifest);
    return { content: out, keep, kinds, sizes, packets: packetsByName, bytes: keep.reduce((n, k) => n + manifest[k].n, 0) };
  }

  function notAvailableOffline(cause) {
    const err = new Error('Photos, videos, and audio aren\u2019t on this device yet \u2014 open this note once while connected.');
    err.notCached = true;
    err.cause = cause;
    return err;
  }

  // Downloads a sliced/packeted file section by section, verifying each packet's size and SHA-256
  // and re-downloading any damaged packet before reassembling the complete stored bytes.
  async function downloadPacketedBytes(noteId, name, m) {
    const totalBytes = m.n || m.packets.reduce((s, p) => s + p.n, 0);
    const out = new Uint8Array(totalBytes);
    let writePos = 0;
    for (let i = 0; i < m.packets.length; i++) {
      const pkt = m.packets[i];
      let pktBytes = null;
      let lastErr = null;
      for (let attempt = 0; attempt < PACKET_MAX_RETRIES; attempt++) {
        try {
          pktBytes = await downloadBytes(noteId, pkt.id);
          if (pkt.n && pktBytes.length !== pkt.n) {
            throw new Error(`Packet ${pkt.idx + 1} of ${pkt.total} came back the wrong size`);
          }
          if (pkt.h && await sha256Hex(pktBytes) !== pkt.h) {
            throw new Error(`Packet ${pkt.idx + 1} of ${pkt.total} came back damaged`);
          }
          lastErr = null;
          break;
        } catch (e) {
          lastErr = e;
          if (e.isNetworkError && attempt === PACKET_MAX_RETRIES - 1) throw notAvailableOffline(e);
        }
      }
      if (lastErr || !pktBytes) {
        // Fallback: check if whole object was stored under `name` directly
        if (i === 0) {
          try {
            const whole = await downloadBytes(noteId, name);
            if (!m.n || whole.length === m.n) return whole;
          } catch (e2) { /* rethrow original packet error */ }
        }
        throw lastErr || new Error('Could not download video packet');
      }
      const dstOffset = typeof pkt.offset === 'number' ? pkt.offset : writePos;
      out.set(pktBytes, dstOffset);
      writePos = dstOffset + pktBytes.length;
    }
    return out;
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
    for (const id of Object.keys(content.videos || {})) {
      const d = content.videos[id] && content.videos[id].data;
      if (isRef(d)) names.add(refName(d));
    }

    for (const name of names) {
      const m = manifest[name];
      if (!m) throw new Error('A photo, video, or audio clip in this note has no record \u2014 the note looks damaged.');
      let stored = await cacheGet(noteId, name).catch(() => null);
      // A copy on this device that is the wrong size is damaged: drop it and fetch a fresh one
      // (unless it is still waiting to upload - then it is the only copy there is).
      if (stored && m.n && stored.length !== m.n) {
        const info = await infoGet(noteId, name).catch(() => null);
        if (info && info.pending) throw new Error('A photo, video, or clip waiting to upload is damaged on this device.');
        await cacheDelete([{ id: idOf(noteId, name) }]).catch(() => {});
        stored = null;
      }
      if (!stored) {
        if (!announced && o.onDownload) { announced = true; o.onDownload(); }
        if (Array.isArray(m.packets) && m.packets.length) {
          stored = await downloadPacketedBytes(noteId, name, m);
        } else {
          try { stored = await downloadBytes(noteId, name); } catch (e) {
            if (e.isNetworkError) throw notAvailableOffline(e);
            throw e;
          }
        }
        if (m.n && stored.length !== m.n) throw new Error('A photo, video, or audio clip came back the wrong size \u2014 try again.');
        // Files saved by this version carry their SHA-256; a download that does not match is refused
        // rather than shown (or, worse, saved back over the good copy).
        if (m.h && await sha256Hex(stored) !== m.h) throw new Error('A photo, video, or audio clip came back damaged \u2014 try again.');
        await cachePut(noteId, name, stored, false, { kind: m.k || '', sha: m.h || '', packets: m.packets || null }).catch(() => {});
      }
      let plain = stored;
      if (m.iv) {
        if (!key) throw new Error('This note\u2019s media is encrypted but its key is missing.');
        plain = await decryptBytes(key, m.iv, stored);
      }
      dataByName[name] = {
        url: await bytesToDataUrl(plain, m.t),
        entry: {
          name, t: m.t, n: m.n, h: m.h || '', iv: m.iv || null,
          enc: !!m.iv, keyB64: m.iv ? content.mediaKey : null,
          k: m.k || '', packets: m.packets || null,
        },
      };
    }

    const idx = indexFor(noteId);
    if (content.mediaKey) noteKeys.set(noteId, content.mediaKey);
    const pick = (s) => {
      if (!isRef(s)) return s;
      const d = dataByName[refName(s)];
      if (!d) throw new Error('A photo, video, or audio clip in this note could not be found.');
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
    if (content.videos) {
      out.videos = {};
      for (const id of Object.keys(content.videos)) {
        const vid = content.videos[id];
        if (vid && isRef(vid.data)) {
          const mName = refName(vid.data);
          const m = manifest[mName];
          out.videos[id] = {
            ...vid,
            data: pick(vid.data),
            mediaName: mName,
            packets: (m && m.packets) || vid.packets || null,
          };
        } else {
          out.videos[id] = vid;
        }
      }
    }
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

  // For the progress display: each of `names` as { kind, size, pending, packets }. A file this device no longer
  // holds a record of was uploaded earlier (files waiting to upload are never dropped).
  async function describe(noteId, names, kinds) {
    const out = {};
    for (const name of names || []) {
      if (!NAME_RE.test(name)) continue;
      const info = await infoGet(noteId, name);
      out[name] = {
        kind: (info && info.kind) || (kinds && kinds[name]) || 'photo',
        size: info ? info.size : 0,
        pending: !!(info && info.pending),
        packets: info && Array.isArray(info.packets) ? info.packets : null,
      };
    }
    return out;
  }

  // Sends the files in `names` that the bucket does not have yet, ONE AT A TIME, and for sliced
  // videos, ONE SECTION PACKET AT A TIME, verifying each packet before moving on.
  //
  //   - It first asks the bucket what it already holds, so after an interruption (phone went to sleep,
  //     app closed, connection lost) it carries on with the next unsent packet/file instead of starting
  //     over. Any packet missing from the bucket or stored with the wrong byte size (lost/corrupted data)
  //     is automatically flagged and re-uploaded.
  //   - Before sending a file or packet, the copy on this device is checked against its SHA-256.
  //   - After sending a file or packet, the bucket is asked what it stored (`verifyStored`); the size
  //     has to match before that packet or file is marked as uploaded. If a packet was lost or truncated
  //     in transit, it is immediately re-uploaded.
  //
  // opts: { sizes: {name: bytes}, onPlan({todo}), onFileStart, onFileProgress, onPacketStatus, onFileDone }
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
    for (const name of wanted) {
      const info = await infoGet(noteId, name);
      const want = info ? info.size : sizes[name];
      const hasPackets = !!(info && Array.isArray(info.packets) && info.packets.length);

      if (hasPackets) {
        if (remote) {
          let allPacketsThere = true;
          const updatedPackets = info.packets.map((pkt) => {
            const remoteSize = remote.get(pkt.id);
            const ok = remoteSize !== undefined && remoteSize === pkt.n;
            if (!ok) allPacketsThere = false;
            // If it was previously marked synced locally, or wrong size in remote, flag as lost so we re-upload it
            const wasLost = (pkt.synced && !ok) || (remoteSize !== undefined && remoteSize !== pkt.n);
            return { ...pkt, synced: ok, lost: wasLost };
          });
          info.packets = updatedPackets;
          if (allPacketsThere) {
            if (info.pending) await markSynced(noteId, name);
            continue;
          }
          todo.push(info);
        } else if (info.pending || info.packets.some((p) => !p.synced)) {
          todo.push(info);
        }
        continue;
      }

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
        ? 'A photo, video, or clip is missing from both this device and your bucket, so this note can\u2019t be saved safely.'
        : missing.length + ' media files are missing from both this device and your bucket, so this note can\u2019t be saved safely.',
      { missingMedia: missing });
    }
    if (o.onPlan) {
      o.onPlan({
        todo: todo.map((i) => ({
          name: i.name,
          size: i.size,
          kind: i.kind || 'photo',
          packets: Array.isArray(i.packets) ? i.packets : null,
        })),
      });
    }

    for (let i = 0; i < todo.length; i++) {
      const info = todo[i];
      const kind = info.kind || 'photo';
      const packets = Array.isArray(info.packets) && info.packets.length ? info.packets : null;
      if (o.onFileStart) {
        o.onFileStart({
          name: info.name,
          kind,
          size: info.size,
          index: i,
          count: todo.length,
          packetCount: packets ? packets.length : 1,
        });
      }
      const bytes = await cacheGet(noteId, info.name);
      if (!bytes) throw uploadError('A photo, video, or clip waiting to upload is missing from this device.');
      if (bytes.length !== info.size) throw uploadError('A photo, video, or clip waiting to upload is damaged on this device (wrong size).');
      const sha = await sha256Hex(bytes);
      if (info.sha && info.sha !== sha) throw uploadError('A photo, video, or clip waiting to upload is damaged on this device.');

      if (packets) {
        // Upload section by section (packet by packet), skipping already-verified sections and
        // automatically re-uploading any lost or corrupted sections.
        let bytesCompleted = packets.reduce((acc, p) => acc + (p.synced ? p.n : 0), 0);
        for (let pIdx = 0; pIdx < packets.length; pIdx++) {
          const pkt = packets[pIdx];
          if (pkt.synced) {
            if (o.onPacketStatus) {
              o.onPacketStatus({
                name: info.name, kind, packetIndex: pIdx, packetCount: packets.length,
                packetId: pkt.id, tag: pkt.tag, state: 'synced', reupload: false,
              });
            }
            continue;
          }
          const slice = bytes.subarray(pkt.offset, pkt.offset + pkt.n);
          const pktSha = await sha256Hex(slice);
          if (pkt.h && pkt.h !== pktSha) {
            throw uploadError(`Video packet ${pIdx + 1} of ${packets.length} is damaged on this device.`);
          }
          let pktDone = false;
          let lastPktErr = null;
          for (let attempt = 0; attempt < PACKET_MAX_RETRIES; attempt++) {
            const isReupload = !!(pkt.lost || attempt > 0);
            if (o.onPacketStatus) {
              o.onPacketStatus({
                name: info.name, kind, packetIndex: pIdx, packetCount: packets.length,
                packetId: pkt.id, tag: pkt.tag, state: isReupload ? 'reuploading' : 'uploading', reupload: isReupload,
              });
            }
            if (o.onFileProgress) {
              o.onFileProgress({
                name: info.name, kind, loaded: bytesCompleted, total: bytes.length,
                packetIndex: pIdx, packetCount: packets.length, packetId: pkt.id, tag: pkt.tag, reupload: isReupload,
              });
            }
            try {
              await uploadBytes(noteId, pkt.id, slice, pktSha, (pktLoaded) => {
                if (o.onFileProgress) {
                  o.onFileProgress({
                    name: info.name, kind,
                    loaded: Math.min(bytes.length, bytesCompleted + pktLoaded),
                    total: bytes.length,
                    packetIndex: pIdx, packetCount: packets.length, packetId: pkt.id, tag: pkt.tag, reupload: isReupload,
                  });
                }
              });
              await root.KSB2.verifyStored(root.KSB2.mediaKey(noteId, pkt.id), pkt.n);
              pktDone = true;
              lastPktErr = null;
              break;
            } catch (pktErr) {
              lastPktErr = pktErr;
              pkt.lost = true;
              await markPacketState(noteId, info.name, pIdx, false, true).catch(() => {});
              if (attempt === PACKET_MAX_RETRIES - 1) throw pktErr;
            }
          }
          if (!pktDone && lastPktErr) throw lastPktErr;
          pkt.synced = true;
          pkt.lost = false;
          bytesCompleted += pkt.n;
          await markPacketState(noteId, info.name, pIdx, true, false);
          if (o.onPacketStatus) {
            o.onPacketStatus({
              name: info.name, kind, packetIndex: pIdx, packetCount: packets.length,
              packetId: pkt.id, tag: pkt.tag, state: 'synced', reupload: false,
            });
          }
          if (o.onFileProgress) {
            o.onFileProgress({
              name: info.name, kind, loaded: bytesCompleted, total: bytes.length,
              packetIndex: pIdx, packetCount: packets.length, packetId: pkt.id, tag: pkt.tag, reupload: false,
            });
          }
        }
        await markSynced(noteId, info.name);
      } else {
        await uploadBytes(noteId, info.name, bytes, sha, (loaded, total) => {
          if (o.onFileProgress) o.onFileProgress({ name: info.name, kind, loaded, total: total || bytes.length });
        });
        await root.KSB2.verifyStored(root.KSB2.mediaKey(noteId, info.name), bytes.length);
        await markSynced(noteId, info.name);
      }
      if (o.onFileDone) o.onFileDone({ name: info.name, kind, size: info.size, index: i, count: todo.length, packetCount: packets ? packets.length : 1 });
    }
    return todo.length;
  }

  // Inspects the local & remote packet status for a specific media item, and optionally repairs/re-uploads any missing packets.
  async function inspectAndRepairPackets(noteId, name, opts) {
    const o = opts || {};
    const info = await infoGet(noteId, name);
    if (!info) return { found: false, packets: [], repaired: 0 };
    let packets = Array.isArray(info.packets) ? info.packets.map((p) => ({ ...p })) : null;
    if (!packets || !packets.length) {
      const bytes = await cacheGet(noteId, name);
      if (bytes) {
        packets = await sliceIntoPackets(name, bytes, true);
        if (packets) await cachePut(noteId, name, bytes, info.pending, { kind: info.kind || 'video', sha: info.sha, packets });
      }
    }
    if (!packets || !packets.length) return { found: true, packets: [], repaired: 0 };

    let remote = null;
    if (enabled() && (!root.navigator || root.navigator.onLine !== false)) {
      try { remote = new Map((await list(noteId)).map((i) => [i.name, i.size])); } catch (e) { remote = null; }
    }

    let lostCount = 0;
    for (const pkt of packets) {
      if (remote) {
        const rSize = remote.get(pkt.id);
        const ok = rSize !== undefined && rSize === pkt.n;
        pkt.cloudVerified = ok;
        if (!ok) {
          pkt.synced = false;
          pkt.lost = true;
          lostCount++;
        } else {
          pkt.synced = true;
          pkt.lost = false;
        }
      }
    }

    const verifiedAt = Date.now();
    if (remote && lostCount === 0) {
      await run(INFO, 'readwrite', (tx) => {
        tx.objectStore(INFO).put({ ...info, pending: false, packets, verifiedAt, used: Date.now() });
      }).catch(() => {});
    }

    let repaired = 0;
    if (o.repair && lostCount > 0 && enabled()) {
      await run(INFO, 'readwrite', (tx) => {
        tx.objectStore(INFO).put({ ...info, pending: true, packets, used: Date.now() });
      });
      await uploadPending(noteId, [name], {
        onFileProgress: o.onProgress,
        onPacketStatus: o.onPacketStatus,
      });
      repaired = lostCount;
      const refreshed = await infoGet(noteId, name);
      if (refreshed && Array.isArray(refreshed.packets)) packets = refreshed.packets;
      await run(INFO, 'readwrite', (tx) => {
        tx.objectStore(INFO).put({ ...(refreshed || info), pending: false, packets, verifiedAt: Date.now(), used: Date.now() });
      }).catch(() => {});
    }

    return { found: true, packets, lostCount, repaired, remoteChecked: !!remote, verifiedAt };
  }

  let bgVerifyInFlight = false;

  // Quietly checks and verifies uploaded/pending video packets in the background, and automatically
  // re-uploads any lost, missing, or size-mismatched packets without interrupting the user.
  async function backgroundVerifyAndRepair(opts) {
    const o = opts || {};
    if (bgVerifyInFlight && !o.force) return { skipped: true, checked: 0, repaired: 0 };
    if (!root.KSB2 || !root.KSB2.config.configured()) return { skipped: true, checked: 0, repaired: 0 };
    if (root.navigator && root.navigator.onLine === false) return { skipped: true, checked: 0, repaired: 0 };

    bgVerifyInFlight = true;
    let checked = 0;
    let repaired = 0;
    try {
      const all = (await req(INFO, 'getAll')) || [];
      const candidates = all.filter((i) => {
        if (o.noteId && i.noteId !== o.noteId) return false;
        return i.kind === 'video' || (Array.isArray(i.packets) && i.packets.length > 0);
      });
      for (const item of candidates) {
        checked++;
        try {
          const res = await inspectAndRepairPackets(item.noteId, item.name, {
            repair: true,
            onProgress: o.onProgress,
            onPacketStatus: (ps) => {
              if (o.onPacketStatus) o.onPacketStatus({ ...ps, noteId: item.noteId });
            },
          });
          if (res && res.repaired > 0) repaired += res.repaired;
          if (o.onItemVerified) {
            o.onItemVerified({
              noteId: item.noteId,
              name: item.name,
              packets: res.packets,
              repaired: res.repaired || 0,
              verifiedAt: res.verifiedAt || Date.now(),
            });
          }
        } catch (e) {
          if (e && e.isNetworkError) break;
        }
      }
      return { skipped: false, checked, repaired, verifiedAt: Date.now() };
    } finally {
      bgVerifyInFlight = false;
    }
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
      // Skip individual packet objects during raw listing prefetch; packeted files are reassembled by inflate()
      if (PACKET_NAME_RE.test(item.name)) continue;
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
      bundle._mediaNote = 'This note has ' + Math.round(total / 1048576) + ' MB of photos, videos and audio in Backblaze, too large to include here. They are in your bucket under media/' + noteId + '/.';
      return bundle;
    }
    if (o.onDownload) o.onDownload();
    const media = {};
    // Also include local cached full copies for packeted videos
    const localInfos = await infoForNote(noteId);
    for (const info of localInfos) {
      const bytes = await cacheGet(noteId, info.name).catch(() => null);
      if (bytes) media[info.name] = bytesToB64(bytes);
    }
    for (const item of items) {
      if (media[item.name] || media[item.name.slice(0, 32)]) continue;
      let bytes = await cacheGet(noteId, item.name).catch(() => null);
      if (!bytes) bytes = await downloadBytes(noteId, item.name);
      media[item.name] = bytesToB64(bytes);
    }
    bundle.media = media;
    bundle._mediaHint = 'Each entry is a file or packet from the note, base64-encoded. In the note, "ks-media:<name>" refers to media[<name>]. For a locked note these are encrypted: decrypt with AES-GCM using the note\u2019s mediaKey and each file\u2019s iv.';
    return bundle;
  }

  root.KSMedia = {
    REF_PREFIX, NAME_RE, PACKET_NAME_RE, MAX_ITEM_BYTES, CACHE_CAP_BYTES, VIDEO_MAX_PACKET_BYTES,
    available, enabled,
    externalize, inflate, uploadPending, pendingKinds, describe, reconcile, dropNote,
    prefetchNote, attachToBundle, cacheBytesUsed, noteBytes, sliceIntoPackets, inspectAndRepairPackets, backgroundVerifyAndRepair,
    _test: { setCap(n) { cacheCap = n; }, resetMemory() { indexes.clear(); noteKeys.clear(); }, parseDataURL, bytesToDataUrl, cachePut, cacheGet, infoGet, infoForNote, evict, indexes, noteKeys },
  };
})(typeof window !== 'undefined' ? window : globalThis);
