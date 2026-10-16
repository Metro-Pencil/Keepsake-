/* Keepsake — video.js
 * Videos in notes. A video is never held in memory and never sent as one big file:
 *
 *   - ADDING: the file is (optionally) compressed, then cut into 4 MB sections. Each section is checksummed
 *     (SHA-256) and kept on this device the moment it is cut, in the same local store photos use (media.js).
 *   - TAGGING: every section is named <video id>.<section number> (for example 3fa9…c1.00007), so the bucket
 *     itself says which video a section belongs to and where it goes. The note holds the list: how many
 *     sections, each one's size and checksum (and, for a locked note, its own random IV).
 *   - UPLOADING: media.js sends the sections one at a time. Whatever the bucket already has is skipped, a section
 *     the bucket lost is sent again, and a phone that sleeps half way loses at most the section in flight.
 *   - PLAYING: sections already on this device are used as they are; any that aren't are fetched from the bucket,
 *     checked against their checksum, kept for next time, and joined into one playable Blob.
 *
 * A locked note's sections are encrypted (AES-GCM) with the same per-note key its photos and audio use.
 */
(function (root) {
  'use strict';

  const CHUNK_BYTES = 4 * 1024 * 1024;
  const MAX_VIDEO_BYTES = 2 * 1024 * 1024 * 1024;
  const MAX_PARTS = 1024;
  const VIDEO_ID_RE = /^v[a-z0-9]{6,31}$/;
  const BASE_RE = /^[a-f0-9]{32}$/;
  const MB = 1024 * 1024;

  // What "Compressed" means. maxDim is the longest side; the bitrates are targets for the encoder.
  const PRESETS = {
    standard: { label: 'Standard', maxDim: 1280, vbps: 1200000, abps: 64000,  fps: 30, ref: 1280 * 720,  hint: 'Up to 720p. About 9 MB per minute.' },
    high:     { label: 'High',     maxDim: 1920, vbps: 3000000, abps: 128000, fps: 30, ref: 1920 * 1080, hint: 'Up to 1080p. About 23 MB per minute.' },
  };

  const pad = (i) => String(i).padStart(5, '0');
  const partName = (base, i) => base + '.' + pad(i);
  const even = (n) => Math.max(2, Math.round(n / 2) * 2);
  const store = () => root.KSMedia.store;

  function userError(message, extra) {
    const err = new Error(message);
    err.userMessage = true;
    return Object.assign(err, extra || {});
  }

  function newVideoId() {
    return 'v' + Array.from(root.crypto.getRandomValues(new Uint8Array(8)), (x) => x.toString(16).padStart(2, '0')).join('');
  }

  const storedBytes = (entry) => (entry && Array.isArray(entry.parts) ? entry.parts.reduce((n, p) => n + (p.n || 0), 0) : 0);

  /* ------------------------------------------------------------ what a note may hold */

  // The record a note keeps for a video, cleaned: only well-formed ones are ever used.
  function sanitize(raw) {
    if (!raw || typeof raw !== 'object' || !BASE_RE.test(String(raw.base || ''))) return null;
    if (!Array.isArray(raw.parts) || !raw.parts.length || raw.parts.length > MAX_PARTS) return null;
    const parts = [];
    for (const p of raw.parts) {
      if (!p || !Number.isFinite(p.n) || p.n <= 0 || p.n > CHUNK_BYTES + 64) return null;
      const part = { n: Math.floor(p.n) };
      if (typeof p.h === 'string' && /^[a-f0-9]{64}$/.test(p.h)) part.h = p.h;
      if (typeof p.iv === 'string' && /^[A-Za-z0-9+/=]{8,32}$/.test(p.iv)) part.iv = p.iv;
      parts.push(part);
    }
    const enc = !!raw.enc;
    if (enc && parts.some((p) => !p.iv)) return null;
    const num = (v, max) => (Number.isFinite(v) && v > 0 ? Math.min(v, max) : 0);
    return {
      base: raw.base,
      name: typeof raw.name === 'string' ? raw.name.slice(0, 120) : '',
      t: /^video\/[a-z0-9.+-]{2,40}$/i.test(raw.t || '') ? raw.t.toLowerCase() : 'video/mp4',
      dur: num(raw.dur, 86400 * 2),
      w: Math.floor(num(raw.w, 16384)),
      h: Math.floor(num(raw.h, 16384)),
      size: Math.floor(num(raw.size, MAX_VIDEO_BYTES * 2)),
      cs: CHUNK_BYTES,
      parts,
      enc,
      mode: raw.mode === 'compressed' ? 'compressed' : 'original',
      poster: typeof raw.poster === 'string' && /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]{0,400000}$/.test(raw.poster) ? raw.poster : '',
    };
  }

  function sanitizeMap(map) {
    const out = {};
    if (!map || typeof map !== 'object') return out;
    for (const id of Object.keys(map)) {
      if (!VIDEO_ID_RE.test(id)) continue;
      const v = sanitize(map[id]);
      if (v) out[id] = v;
    }
    return out;
  }

  /* ----------------------------------------------------------------------- capability */

  const MIME_CHOICES = [
    'video/mp4;codecs=avc1.42E01E,mp4a.40.2', 'video/mp4',
    'video/webm;codecs=vp9,opus', 'video/webm;codecs=vp8,opus', 'video/webm',
  ];

  function pickMime() {
    if (typeof root.MediaRecorder !== 'function' || typeof root.MediaRecorder.isTypeSupported !== 'function') return '';
    return MIME_CHOICES.find((t) => { try { return root.MediaRecorder.isTypeSupported(t); } catch (e) { return false; } }) || '';
  }

  function canCompress() {
    return !!pickMime() && !!root.HTMLCanvasElement && 'captureStream' in root.HTMLCanvasElement.prototype;
  }

  /* ------------------------------------------------------------------------- probing */

  function posterFrom(v, w, h) {
    try {
      const cw = Math.min(640, w);
      const ch = Math.max(1, Math.round(h * cw / w));
      const c = root.document.createElement('canvas');
      c.width = cw; c.height = ch;
      c.getContext('2d').drawImage(v, 0, 0, cw, ch);
      return c.toDataURL('image/jpeg', 0.72);
    } catch (e) { return ''; }
  }

  // Reads a video's length, size and a poster frame. { ok:false } when this browser can't decode it.
  function probe(file) {
    return new Promise((resolve) => {
      const doc = root.document;
      const url = root.URL.createObjectURL(file);
      const v = doc.createElement('video');
      v.muted = true; v.playsInline = true; v.preload = 'auto';
      let finished = false;
      let seekTimer = 0;
      const finish = (info) => {
        if (finished) return;
        finished = true;
        clearTimeout(timer); clearTimeout(seekTimer);
        v.onerror = v.onloadedmetadata = v.onseeked = v.ondurationchange = null;
        v.removeAttribute('src');
        try { v.load(); } catch (e) { /* done anyway */ }
        root.URL.revokeObjectURL(url);
        resolve(info);
      };
      const timer = setTimeout(() => finish({ ok: false, dur: 0, w: 0, h: 0, poster: '' }), 15000);
      v.onerror = () => finish({ ok: false, dur: 0, w: 0, h: 0, poster: '' });
      const grab = () => {
        const dur = isFinite(v.duration) ? v.duration : 0;
        const w = v.videoWidth; const h = v.videoHeight;
        if (!w || !h) { finish({ ok: false, dur: 0, w: 0, h: 0, poster: '' }); return; }
        const done = () => finish({ ok: true, dur, w, h, poster: posterFrom(v, w, h) });
        v.onseeked = done;
        seekTimer = setTimeout(done, 2500); // a frame that never arrives shouldn't hold the dialog up
        try { v.currentTime = dur > 0.2 ? Math.min(1, dur * 0.1) : 0.01; } catch (e) { done(); }
      };
      v.onloadedmetadata = () => {
        if (v.duration === Infinity) {
          // A recording with no length written into it: seeking far past the end makes the browser work it out.
          v.ondurationchange = () => { if (isFinite(v.duration)) { v.ondurationchange = null; v.currentTime = 0; setTimeout(grab, 30); } };
          try { v.currentTime = 1e101; } catch (e) { grab(); }
        } else grab();
      };
      v.src = url;
    });
  }

  /* ------------------------------------------------------------------------ estimates */

  function outputSize(info, preset) {
    const scale = Math.min(1, preset.maxDim / Math.max(info.w, info.h));
    return { w: even(info.w * scale), h: even(info.h * scale) };
  }

  function videoBitrate(out, preset) {
    return Math.round(preset.vbps * Math.max(0.35, Math.min(1, (out.w * out.h) / preset.ref)));
  }

  // What Compressed will most likely come to, from the length and the strength chosen. It is an estimate - an encoder
  // aims for a bitrate rather than guaranteeing one - so the dialog says "about", and the real figure is shown
  // as soon as the video has been compressed. `shrinks` is false when the video is already as small as that.
  function estimate(info, size, preset) {
    if (!info || !info.ok || !(info.dur > 0)) return { known: false, shrinks: false, bytes: size };
    const out = outputSize(info, preset);
    const bytes = Math.round((videoBitrate(out, preset) + preset.abps) * info.dur / 8 * 1.04);
    const shrinks = bytes < size * 0.9;
    return { known: true, shrinks, bytes: shrinks ? bytes : size, w: out.w, h: out.h, seconds: info.dur };
  }

  /* ---------------------------------------------------------- WebM: write the length in */

  // A recording made in the browser has no length inside it, and a player can't seek in a file whose length it doesn't
  // know. This writes the length into the file's header (a few bytes, in front of the video data). It only touches
  // the simple layout browsers produce, and returns the file unchanged if it sees anything else.
  async function fixWebmDuration(blob, seconds) {
    try {
      if (!/webm/i.test(blob.type) || !(seconds > 0)) return blob;
      const head = new Uint8Array(await store().blobBytes(blob.slice(0, 65536)));
      const readId = (p) => {
        const first = head[p]; let len = 1; let mask = 0x80;
        while (len <= 4 && !(first & mask)) { len++; mask >>= 1; }
        if (len > 4 || p + len > head.length) return null;
        let id = 0; for (let i = 0; i < len; i++) id = id * 256 + head[p + i];
        return { id, len };
      };
      const readSize = (p) => {
        const first = head[p]; let len = 1; let mask = 0x80;
        while (len <= 8 && !(first & mask)) { len++; mask >>= 1; }
        if (len > 8 || p + len > head.length) return null;
        let val = first & (mask - 1); let unknown = val === mask - 1;
        for (let i = 1; i < len; i++) { val = val * 256 + head[p + i]; if (head[p + i] !== 0xFF) unknown = false; }
        return { size: val, len, unknown };
      };
      let pos = 0;
      const ebml = readId(pos); if (!ebml || ebml.id !== 0x1A45DFA3) return blob;
      const ebmlSize = readSize(pos + ebml.len); if (!ebmlSize || ebmlSize.unknown) return blob;
      pos += ebml.len + ebmlSize.len + ebmlSize.size;
      const seg = readId(pos); if (!seg || seg.id !== 0x18538067) return blob;
      const segSize = readSize(pos + seg.len); if (!segSize) return blob;
      const segSizePos = pos + seg.len;
      pos += seg.len + segSize.len;
      while (pos < head.length) {
        const id = readId(pos); if (!id) return blob;
        const size = readSize(pos + id.len); if (!size || size.unknown) return blob;
        if (id.id === 0x114D9B74 || id.id === 0x1F43B675) return blob; // a seek index, or video data before the header: leave it
        if (id.id !== 0x1549A966) { pos += id.len + size.len + size.size; continue; }
        // Info element: find TimecodeScale, and see whether a length is there already
        const infoStart = pos; const bodyStart = pos + id.len + size.len; const bodyEnd = bodyStart + size.size;
        if (bodyEnd > head.length) return blob;
        let scale = 1000000; let p = bodyStart;
        while (p < bodyEnd) {
          const cid = readId(p); if (!cid) return blob;
          const csz = readSize(p + cid.len); if (!csz || csz.unknown) return blob;
          const dataAt = p + cid.len + csz.len;
          if (cid.id === 0x2AD7B1) { scale = 0; for (let i = 0; i < csz.size; i++) scale = scale * 256 + head[dataAt + i]; }
          if (cid.id === 0x4489) { // a Duration is there: keep it unless it says zero
            const dv = new DataView(head.buffer, head.byteOffset + dataAt, csz.size);
            const have = csz.size === 8 ? dv.getFloat64(0) : csz.size === 4 ? dv.getFloat32(0) : 0;
            if (have > 0) return blob;
          }
          p = dataAt + csz.size;
        }
        const ticks = seconds * 1e9 / (scale || 1000000);
        const dur = new Uint8Array(11);
        dur[0] = 0x44; dur[1] = 0x89; dur[2] = 0x88;
        new DataView(dur.buffer).setFloat64(3, ticks);
        const newSize = size.size + dur.length;
        let sl = size.len;
        while (newSize >= Math.pow(2, 7 * sl) - 1) sl++;
        const header = new Uint8Array(id.len + sl);
        header.set(head.subarray(infoStart, infoStart + id.len), 0);
        let v = newSize;
        for (let i = sl - 1; i >= 0; i--) { header[id.len + i] = v % 256; v = Math.floor(v / 256); }
        header[id.len] |= 1 << (8 - sl);
        const grown = (header.length - (id.len + size.len)) + dur.length;
        const outHead = new Uint8Array(head.subarray(0, infoStart));
        if (!segSize.unknown) { // the whole file's size grows by what was added: write it back in place if it still fits
          const nv = segSize.size + grown;
          if (nv >= Math.pow(2, 7 * segSize.len) - 1) return blob;
          let q = nv;
          for (let i = segSize.len - 1; i >= 0; i--) { outHead[segSizePos + i] = q % 256; q = Math.floor(q / 256); }
          outHead[segSizePos] |= 1 << (8 - segSize.len);
        }
        return new root.Blob([outHead, header, head.subarray(bodyStart, bodyEnd), dur, blob.slice(bodyEnd)], { type: blob.type });
      }
      return blob;
    } catch (e) { return blob; }
  }

  /* ---------------------------------------------------------------------- compressing */

  // Re-encodes a video smaller. A browser can only do this by playing the video and recording what it plays, so it
  // takes as long as the video lasts and the screen has to stay on (the app asks the device not to sleep meanwhile).
  // Resolves with the compressed Blob; rejects with {cancelled:true} when `shouldStop()` turns true.
  function compress(file, preset, opts) {
    const o = opts || {};
    const info = o.info || {};
    return new Promise((resolve, reject) => {
      const doc = root.document;
      const mime = pickMime();
      if (!mime || !(info.w > 0) || !(info.dur > 0)) { reject(userError('This browser can\u2019t compress this video.')); return; }
      const out = outputSize(info, preset);
      const canvas = doc.createElement('canvas');
      canvas.width = out.w; canvas.height = out.h;
      const ctx = canvas.getContext('2d', { alpha: false });
      const url = root.URL.createObjectURL(file);
      const v = doc.createElement('video');
      v.playsInline = true; v.preload = 'auto'; v.src = url;
      // Some browsers only keep decoding a video that is part of the page.
      v.style.cssText = 'position:fixed;left:0;top:0;width:2px;height:2px;opacity:0.01;pointer-events:none';
      doc.body.appendChild(v);

      let actx = null; let dest = null; let rec = null; let raf = 0; let tick = 0;
      let settled = false; let lastTime = -1; let lastMove = Date.now();
      const chunks = [];

      const cleanup = () => {
        cancelAnimationFrame(raf); clearInterval(tick);
        doc.removeEventListener('visibilitychange', onVisibility);
        try { if (rec && rec.state !== 'inactive') rec.stop(); } catch (e) { /* already stopped */ }
        try { v.pause(); } catch (e) { /* done */ }
        v.removeAttribute('src');
        try { v.load(); } catch (e) { /* done */ }
        v.remove();
        if (actx) { try { actx.close(); } catch (e) { /* done */ } }
        root.URL.revokeObjectURL(url);
      };
      const fail = (err) => { if (settled) return; settled = true; cleanup(); reject(err); };

      const onVisibility = () => {
        // A hidden page stops painting, which would record a frozen picture: wait, and carry on when it is back.
        if (doc.hidden) { try { v.pause(); if (rec && rec.state === 'recording') rec.pause(); } catch (e) { /* ignore */ } }
        else { try { if (rec && rec.state === 'paused') rec.resume(); v.play().catch(() => {}); } catch (e) { /* ignore */ } }
      };
      doc.addEventListener('visibilitychange', onVisibility);

      v.onerror = () => fail(userError('This browser couldn\u2019t play that video to compress it.'));
      v.onloadedmetadata = async () => {
        try {
          // Sound: the video's audio goes into the recording, and nowhere else - nothing plays aloud meanwhile.
          const AC = root.AudioContext || root.webkitAudioContext;
          let audioTracks = [];
          if (AC) {
            try {
              actx = new AC();
              if (actx.state === 'suspended') await actx.resume().catch(() => {});
              const src = actx.createMediaElementSource(v);
              dest = actx.createMediaStreamDestination();
              src.connect(dest);
              audioTracks = dest.stream.getAudioTracks();
            } catch (e) { actx = null; dest = null; }
          }
          const stream = canvas.captureStream(preset.fps);
          audioTracks.forEach((t) => stream.addTrack(t));
          rec = new root.MediaRecorder(stream, { mimeType: mime, videoBitsPerSecond: videoBitrate(out, preset), audioBitsPerSecond: preset.abps });
          rec.ondataavailable = (e) => { if (e.data && e.data.size) chunks.push(e.data); };
          rec.onerror = () => fail(userError('The browser stopped recording the compressed video.'));
          rec.onstop = async () => {
            if (settled) return;
            settled = true;
            cleanup();
            let blob = new root.Blob(chunks, { type: mime.split(';')[0] });
            blob = await fixWebmDuration(blob, info.dur);
            resolve(blob);
          };
          v.onended = () => { try { rec.stop(); } catch (e) { fail(userError('Compressing stopped early.')); } };
          const paint = () => {
            if (settled) return;
            if (!v.paused && !v.ended && v.readyState >= 2) ctx.drawImage(v, 0, 0, out.w, out.h);
            raf = requestAnimationFrame(paint);
          };
          rec.start(1000);
          await v.play();
          paint();
          tick = setInterval(() => {
            if (o.shouldStop && o.shouldStop()) { fail({ cancelled: true, message: 'Cancelled' }); return; }
            if (o.onProgress) o.onProgress(Math.min(1, v.currentTime / info.dur));
            if (v.currentTime !== lastTime) { lastTime = v.currentTime; lastMove = Date.now(); }
            else if (!doc.hidden && !v.paused && Date.now() - lastMove > 25000) fail(userError('Compressing got stuck \u2014 try again, or keep the original.'));
          }, 400);
        } catch (e) {
          fail(userError('This browser couldn\u2019t start compressing that video.'));
        }
      };
    });
  }

  /* ------------------------------------------------------- cutting into tagged sections */

  async function ensureRoom(bytes) {
    try {
      if (root.navigator.storage && root.navigator.storage.persist) root.navigator.storage.persist().catch(() => {});
      if (root.navigator.storage && root.navigator.storage.estimate) {
        const { quota, usage } = await root.navigator.storage.estimate();
        if (quota && usage != null && quota - usage < bytes * 1.05 + 50 * MB) {
          throw userError('There isn\u2019t enough free space on this device to hold this video while it uploads (it needs about ' + Math.ceil(bytes / MB) + ' MB, and about ' + Math.max(0, Math.floor((quota - usage) / MB)) + ' MB is free).');
        }
      }
    } catch (e) { if (e && e.userMessage) throw e; }
  }

  // Cuts `source` (a File or Blob) into sections and keeps each on this device, ready to upload.
  //   meta: { name, type, dur, w, h, poster, mode }   opts: { noteId, enc: {key}|null, onProgress(done,total), shouldStop }
  // Resolves with the note's record of the video (see sanitize). Until the note is saved, the video's base stays
  // "held" so a save of an older version of the note can't clean its sections up.
  async function ingest(source, meta, opts) {
    const o = opts || {};
    const st = store();
    const size = source.size;
    if (!(size > 0)) throw userError('That video file is empty.');
    if (size > MAX_VIDEO_BYTES) throw userError('A video can be up to 2 GB \u2014 this one is ' + (size / MB / 1024).toFixed(1) + ' GB.');
    await ensureRoom(size);
    const base = st.randomName();
    root.KSMedia.hold(base);
    const count = Math.ceil(size / CHUNK_BYTES);
    const parts = [];
    try {
      for (let i = 0; i < count; i++) {
        if (o.shouldStop && o.shouldStop()) throw Object.assign(new Error('Cancelled'), { cancelled: true });
        const slice = source.slice(i * CHUNK_BYTES, Math.min(size, (i + 1) * CHUNK_BYTES));
        const plain = new Uint8Array(await st.blobBytes(slice));
        let stored = plain; let iv = null;
        if (o.enc) { const e = await st.encryptBytes(o.enc.key, plain); stored = e.bytes; iv = e.iv; }
        const sha = await st.sha256Hex(stored);
        await st.cachePut(o.noteId, partName(base, i), o.enc ? stored : slice, true, { kind: 'video', sha });
        parts.push(iv ? { n: stored.length, h: sha, iv } : { n: stored.length, h: sha });
        if (o.onProgress) o.onProgress(i + 1, count);
      }
    } catch (e) {
      await st.cacheDelete(parts.map((_, i) => ({ id: o.noteId + '/' + partName(base, i) }))).catch(() => {});
      root.KSMedia.release(base);
      throw e;
    }
    return {
      base, name: String(meta.name || '').slice(0, 120), t: /^video\//i.test(meta.type || '') ? meta.type.toLowerCase().split(';')[0] : 'video/mp4',
      dur: meta.dur || 0, w: meta.w || 0, h: meta.h || 0, size, cs: CHUNK_BYTES, parts, enc: !!o.enc,
      mode: meta.mode === 'compressed' ? 'compressed' : 'original', poster: meta.poster || '',
    };
  }

  /* ---------------------------------------------------- getting a video ready to be saved */

  // Called when a note is saved. A video added to a note that wasn't locked is stored plain; if the note is locked
  // now, its sections are encrypted (one at a time; from this device, or from the bucket if they are no longer here)
  // under new names, and the plain ones are left to be cleaned up. A video that is already encrypted stays so.
  // Returns the record to put in the note.
  async function prepare(noteId, entry, ctx) {
    const st = store();
    const c = ctx || {};
    const v = sanitize(entry);
    if (!v) throw userError('A video in this note looks damaged and can\u2019t be saved.');
    if (!c.locked || v.enc) { root.KSMedia.release(v.base); return { ...v, poster: entry.poster || v.poster }; }
    if (!c.key) throw userError('This note is locked, but its key isn\u2019t ready \u2014 try again.');
    const base = st.randomName();
    root.KSMedia.hold(base);
    const parts = [];
    try {
      for (let i = 0; i < v.parts.length; i++) {
        const name = partName(v.base, i);
        let plain = null;
        const blob = await st.cacheGetBlob(noteId, name);
        if (blob) plain = new Uint8Array(await st.blobBytes(blob));
        else {
          try { plain = await st.downloadBytes(noteId, name); }
          catch (e) {
            if (e.isNetworkError) throw userError('To lock this note, its video has to be re-encrypted, and part of it isn\u2019t on this device any more. Connect to the internet and try again.');
            throw userError('A part of a video is missing from this device and from your bucket, so the note can\u2019t be locked safely.');
          }
        }
        if (plain.length !== v.parts[i].n || (v.parts[i].h && (await st.sha256Hex(plain)) !== v.parts[i].h)) throw userError('A part of a video is damaged \u2014 the note can\u2019t be locked safely.');
        const e = await st.encryptBytes(c.key, plain);
        const sha = await st.sha256Hex(e.bytes);
        await st.cachePut(noteId, partName(base, i), e.bytes, true, { kind: 'video', sha });
        parts.push({ n: e.bytes.length, h: sha, iv: e.iv });
        if (c.onProgress) c.onProgress(i + 1, v.parts.length);
      }
    } catch (e) {
      await st.cacheDelete(parts.map((_, i) => ({ id: noteId + '/' + partName(base, i) }))).catch(() => {});
      root.KSMedia.release(base);
      throw e;
    }
    root.KSMedia.release(v.base);
    root.KSMedia.release(base);
    return { ...v, base, parts, enc: true, poster: entry.poster || v.poster };
  }

  /* ------------------------------------------------------------------------ playing */

  // Makes the video playable: sections on this device are used as they are, the rest are fetched (three at a time),
  // checked, kept for next time and, for a locked note, decrypted. Resolves with { url, blob, revoke }.
  //   opts: { onProgress(done, total, bytesDone, bytesTotal), isCancelled() }
  async function open(noteId, entry, opts) {
    const st = store();
    const o = opts || {};
    const v = sanitize(entry);
    if (!v) throw userError('This video looks damaged and can\u2019t be played.');
    let key = null;
    if (v.enc) {
      const nk = await root.KSMedia.noteKey(noteId, false);
      if (!nk) throw userError('This video is encrypted and its key isn\u2019t available \u2014 close the note and open it again.');
      key = nk.key;
    }
    const total = v.parts.length;
    const totalBytes = storedBytes(v);
    const blobs = new Array(total);
    let next = 0; let done = 0; let bytesDone = 0; let failure = null;

    async function loadPart(i) {
      const p = v.parts[i]; const name = partName(v.base, i);
      let blob = await st.cacheGetBlob(noteId, name);
      if (blob && blob.size !== p.n) { await st.cacheDelete([{ id: noteId + '/' + name }]).catch(() => {}); blob = null; } // damaged copy: fetch a fresh one
      if (!blob) {
        let bytes;
        try { bytes = await st.downloadBytes(noteId, name); }
        catch (e) {
          if (e.isNetworkError) throw userError('This video isn\u2019t on this device yet, and there\u2019s no connection to fetch it.');
          throw userError('Part ' + (i + 1) + ' of this video is missing from your bucket.');
        }
        if (bytes.length !== p.n) throw userError('Part ' + (i + 1) + ' of this video came back the wrong size \u2014 try again.');
        if (p.h && (await st.sha256Hex(bytes)) !== p.h) throw userError('Part ' + (i + 1) + ' of this video came back damaged \u2014 try again.');
        blob = new root.Blob([bytes]);
        await st.cachePut(noteId, name, blob, false, { kind: 'video', sha: p.h || '' }).catch(() => {});
      }
      if (v.enc) {
        const plain = await st.decryptBytes(key, p.iv, new Uint8Array(await st.blobBytes(blob)));
        return new root.Blob([plain]);
      }
      return blob;
    }
    async function worker() {
      while (!failure) {
        const i = next++;
        if (i >= total) return;
        if (o.isCancelled && o.isCancelled()) { failure = Object.assign(new Error('Cancelled'), { cancelled: true }); return; }
        try { blobs[i] = await loadPart(i); } catch (e) { failure = e; return; }
        done++; bytesDone += v.parts[i].n;
        if (o.onProgress) o.onProgress(done, total, bytesDone, totalBytes);
      }
    }
    await Promise.all([worker(), worker(), worker()]);
    if (failure) throw failure;
    const blob = new root.Blob(blobs, { type: v.t });
    const url = root.URL.createObjectURL(blob);
    return { url, blob, revoke() { root.URL.revokeObjectURL(url); } };
  }

  // Where every part of a video stands, checked against the bucket right now:
  //   saved   - in the bucket at the right size
  //   waiting - on this device, not uploaded yet (it goes up when the note is saved)
  //   lost    - the bucket should have it (it was sent before) but doesn't, or holds the wrong size; this device has
  //             a copy, so it can be sent again
  //   gone    - in neither place: can't be recovered
  //   unknown - the bucket couldn't be reached (the state shown is what this device remembers)
  async function inspect(noteId, entry) {
    const st = store();
    const v = sanitize(entry);
    if (!v) throw userError('This video looks damaged.');
    const infos = new Map((await st.infoForNote(noteId)).filter((i) => i.name.startsWith(v.base + '.')).map((i) => [i.name, i]));
    let remote = null;
    try { remote = new Map((await st.list(noteId)).map((i) => [i.name, i.size])); } catch (e) { remote = null; }
    const parts = v.parts.map((p, i) => {
      const name = partName(v.base, i);
      const info = infos.get(name);
      const there = remote ? remote.get(name) : undefined;
      let state;
      if (!remote) state = info && info.pending ? 'waiting' : 'unknown';
      else if (there === p.n) state = 'saved';
      else if (info) state = there === undefined && info.pending ? 'waiting' : 'lost';
      else state = 'gone';
      return { index: i, n: p.n, state };
    });
    const count = (k) => parts.filter((x) => x.state === k).length;
    return { parts, online: !!remote, saved: count('saved'), waiting: count('waiting'), lost: count('lost'), gone: count('gone'), unknown: count('unknown') };
  }

  // Sends every part the bucket doesn't have (waiting or lost) from the copy on this device, one at a time and
  // confirmed, exactly as a save does. Resolves with how many were sent. Rejects if a part exists nowhere.
  async function repair(noteId, entry, opts) {
    const o = opts || {};
    const v = sanitize(entry);
    if (!v) throw userError('This video looks damaged.');
    const names = v.parts.map((_, i) => partName(v.base, i));
    const sizes = {};
    names.forEach((n, i) => { sizes[n] = v.parts[i].n; });
    let planned = 0; let done = 0;
    await root.KSMedia.uploadPending(noteId, names, {
      sizes,
      onPlan: (plan) => { planned = plan.todo.length; if (o.onProgress) o.onProgress(0, planned); },
      onFileDone: () => { done++; if (o.onProgress) o.onProgress(done, planned); },
    });
    return planned;
  }

  // Throws away a video that was cut up but never made it into a note.
  async function discard(noteId, entry) {
    root.KSMedia.release(entry.base);
    await store().cacheDelete(entry.parts.map((_, i) => ({ id: noteId + '/' + partName(entry.base, i) }))).catch(() => {});
  }

  // How much of a video is on this device and how much is still waiting to upload (for the badge on its card).
  async function status(noteId, entry) {
    const st = store();
    const mine = (await st.infoForNote(noteId)).filter((i) => i.name.startsWith(entry.base + '.'));
    return { total: entry.parts.length, local: mine.length, pending: mine.filter((i) => i.pending).length };
  }

  root.KSVideo = {
    CHUNK_BYTES, MAX_VIDEO_BYTES, PRESETS, partName, newVideoId, storedBytes, VIDEO_ID_RE,
    sanitize, sanitizeMap, canCompress, probe, estimate, compress, ingest, prepare, open, status, discard, inspect, repair,
    hold(base) { root.KSMedia.hold(base); }, release(base) { root.KSMedia.release(base); },
    _test: { fixWebmDuration, outputSize, videoBitrate, pickMime },
  };
})(typeof window !== 'undefined' ? window : globalThis);
