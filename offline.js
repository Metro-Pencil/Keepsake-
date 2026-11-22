/* ---------------------------------------------------------------------------
 * offline.js - an offline copy of the notebook that is made ONLY when you press Download.
 *
 * Nothing in the app downloads notes, photos, audio or video by itself any more - not at start-up, not when the
 * connection comes back, not for a master. This section is the one place that does, and only while you have
 * pressed its button and the app stays open.
 *
 * What a run does, in this order:
 *
 *   1. Text      - every note's text (and a released time-lock password) is saved on this device. All of it is
 *                  done before anything else starts, so every note opens at once, even with no connection.
 *   2. Media     - ONLY the types you ticked: Images, Audio, Videos. Each ticked type is downloaded in turn.
 *                  A type that is not ticked is not saved: it is fetched live from Backblaze when you open a note.
 *
 * It works in small pieces so it can be stopped at any moment and carry on later:
 *
 *   - One file at a time. A file over 8 MB is fetched in 4 MB slices (an HTTP range request); each slice is saved
 *     on the device as it arrives, so an interrupted big file continues from its last slice, not from zero.
 *     (If the bucket's CORS rule turns out to refuse range requests, it falls back to whole files.)
 *   - Each finished file is stored in the device's media store, marked "pinned" so the usual size caps never
 *     drop it.
 *   - Nothing else is remembered about where it was: pressing Download again lists the bucket again and skips
 *     whatever is already on the device.
 *
 * Anything already saved on this device counts as downloaded - including notes and photos kept while you used
 * the app - because it opens with no connection. The section shows exactly what is on the device, per type.
 *
 * A master can limit what a device may open (devices.js). Notes this device may not open are never downloaded.
 * "Delete offline data" removes everything saved for offline use except edits and uploads that have not reached
 * the bucket yet.
 * ------------------------------------------------------------------------- */
(function (root) {
  'use strict';

  const LS_KEY = 'ks_offline';
  const DB_NAME = 'keepsake-offline';
  const CHUNK = 4 * 1024 * 1024;        // size of one slice of a big file
  const WHOLE_MAX = 8 * 1024 * 1024;    // files up to this size are fetched in one go
  const PART_RE = /\.\d{5}$/;
  const KINDS = ['image', 'audio', 'video'];
  const LABEL = { image: 'Images', audio: 'Audio', video: 'Videos' };
  const STORE_KIND = { image: 'photo', audio: 'audio', video: 'video' };   // what media.js calls them
  const STEPS = ['list', 'text', 'plan', 'image', 'audio', 'video'];
  const STEP_LABEL = { list: 'Looking at your notes', text: 'Text of every note', plan: 'Checking which files are needed', image: 'Images', audio: 'Audio', video: 'Videos' };

  /* ------------------------------------------------------------------ helpers */

  const doc = () => root.document;
  const el = (id) => doc() && doc().getElementById(id);
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  function lsGet(k) { try { return root.localStorage.getItem(k) || ''; } catch (e) { return ''; } }
  function lsSet(k, v) { try { root.localStorage.setItem(k, v); } catch (e) { /* private mode */ } }
  function getState() { try { return JSON.parse(lsGet(LS_KEY)) || {}; } catch (e) { return {}; } }
  function patch(p) { const s = { ...getState(), ...p }; lsSet(LS_KEY, JSON.stringify(s)); return s; }
  const say = (m) => { if (root.toast) root.toast(m); };
  const mb = (n) => (n >= 1073741824 ? (n / 1073741824).toFixed(2) + ' GB' : n >= 10485760 ? Math.round(n / 1048576) + ' MB' : n >= 1024 ? (n / 1048576).toFixed(1) + ' MB' : n + ' B');
  const plural = (n, one, many) => n + ' ' + (n === 1 ? one : many);
  const when = (ts) => new Date(ts).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
  const selection = () => { const k = getState().kinds || {}; return { image: !!k.image, audio: !!k.audio, video: !!k.video }; };

  // Notes this device is allowed to open (a master can switch normal or locked notes off per device).
  const allowed = (meta) => !(root.KSDevices && root.KSDevices.allows) || !(root.KSDevices.access && root.KSDevices.access().known) || root.KSDevices.allows(meta);

  // Older versions kept an "on" switch that made the sync start by itself. It is gone: clear it once.
  (function dropAutoSwitch() {
    const s = getState();
    if ('on' in s || 'paused' in s || 'totals' in s) { delete s.on; delete s.paused; delete s.totals; lsSet(LS_KEY, JSON.stringify(s)); }
  })();

  /* ------------------------------------------- the progress store (IndexedDB) */

  let dbp = null;
  function openDB() {
    if (dbp) return dbp;
    dbp = new Promise((resolve, reject) => {
      const r = root.indexedDB.open(DB_NAME, 1);
      r.onupgradeneeded = () => {
        const db = r.result;
        if (!db.objectStoreNames.contains('notes')) db.createObjectStore('notes', { keyPath: 'id' });     // (no longer used; kept so existing databases still open)
        if (!db.objectStoreNames.contains('partial')) db.createObjectStore('partial', { keyPath: 'id' }); // an unfinished big file: { id, size, next, chunks: [Blob] }
      };
      r.onsuccess = () => { const db = r.result; db.onversionchange = () => { db.close(); dbp = null; }; db.onclose = () => { dbp = null; }; resolve(db); };
      r.onerror = () => { dbp = null; reject(r.error); };
      r.onblocked = () => { dbp = null; reject(new Error('Offline storage is blocked by another open tab.')); };
    });
    return dbp;
  }
  async function dbReq(store, mode, fn) {
    const db = await openDB();
    let tx;
    try { tx = db.transaction(store, mode); }
    catch (e) { if (e && e.name === 'InvalidStateError') { dbp = null; const db2 = await openDB(); tx = db2.transaction(store, mode); } else throw e; }
    return new Promise((resolve, reject) => {
      const out = fn(tx.objectStore(store));
      tx.oncomplete = () => resolve(out && out.result !== undefined ? out.result : undefined);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error || new Error('Aborted'));
    });
  }
  const dbGet = async (store, key) => (await dbReq(store, 'readonly', (s) => s.get(key))) || null;
  const dbAll = async (store) => (await dbReq(store, 'readonly', (s) => s.getAll())) || [];
  const dbPut = (store, v) => dbReq(store, 'readwrite', (s) => s.put(v));
  const dbDel = (store, key) => dbReq(store, 'readwrite', (s) => s.delete(key));
  const dbClear = (store) => dbReq(store, 'readwrite', (s) => s.clear());

  /* ------------------------------------------------------------------- status */

  // phase: idle | running | paused | done      reason (when paused): stopped | offline | error
  const blankStage = (extra) => ({ state: 'pending', done: 0, total: 0, bytes: 0, bytesTotal: 0, ...(extra || {}) });
  function blankStages() { const o = {}; STEPS.forEach((k) => { o[k] = blankStage(); }); return o; }
  const status = { phase: 'idle', reason: '', stages: blankStages(), current: '', partial: 0, problems: 0, error: '', startedAt: 0, picked: { image: false, audio: false, video: false } };
  let running = null;
  let stopFlag = false;
  let runAbort = null;
  const isQuotaError = (e) => !!(e && (e.name === 'QuotaExceededError' || e.code === 22));
  const emit = () => { try { root.dispatchEvent(new root.CustomEvent('ks-offline')); } catch (e) { /* UI only */ } };
  const go = () => !stopFlag;
  function stage(k, state, extra) { Object.assign(status.stages[k], { state }, extra || {}); emit(); }

  /* ----------------------------------------------------------------- fetching */

  let rangeBrokenSession = false;

  async function clearPartial(pid, count) {
    await dbDel('partial', pid).catch(() => {});
    for (let i = 0; i < (count || 0); i++) await dbDel('partial', pid + '#' + i).catch(() => {});
  }

  // One media file, whole or in slices. Returns { data, cleanup } (data is Uint8Array or Blob;
  // cleanup clears any partial chunks after the caller persists data), or null if told to stop.
  async function fetchFile(noteId, name, size, signal) {
    const B = root.KSB2;
    const key = B.mediaKey(noteId, name);
    const reqOpts = signal ? { signal } : undefined;
    const whole = async () => {
      const bytes = await B.getBytesOrNull(key, reqOpts);
      if (!bytes) { const e = new Error('Missing from the bucket'); e.status = 404; throw e; }
      if (bytes.length !== size) throw new Error('Wrong size');
      return { data: bytes, cleanup: null };
    };
    if (size <= WHOLE_MAX || rangeBrokenSession || !B.getRange) return whole();

    const pid = noteId + '/' + name;
    let part = await dbGet('partial', pid);
    if (!part || part.size !== size || typeof part.count !== 'number') {
      if (part && part.count) await clearPartial(pid, part.count);
      part = { id: pid, size, next: 0, count: 0 };
    }
    status.partial = part.next;
    while (part.next < size) {
      if (!go()) return null;
      const end = Math.min(part.next + CHUNK, size) - 1;
      let r;
      try { r = await B.getRange(key, part.next, end, reqOpts); }
      catch (e) {
        if (!go() || (e && (e.name === 'AbortError' || e.isAbortError))) return null;
        if (e.isNetworkError && part.next === 0 && root.navigator.onLine) {
          // Retry getRange once before assuming range requests are blocked in this session.
          try { r = await B.getRange(key, part.next, end, reqOpts); }
          catch (e2) {
            if (!go() || (e2 && (e2.name === 'AbortError' || e2.isAbortError))) return null;
            if (e2.isNetworkError && root.navigator.onLine) {
              const res = await whole();             // throws the network error again if we really are offline
              rangeBrokenSession = true;             // session-only: don't lock out ranges forever
              return res;
            }
            throw e2;
          }
        } else {
          throw e;
        }
      }
      if (!r) { await clearPartial(pid, part.count); const e = new Error('Missing from the bucket'); e.status = 404; throw e; }
      if (!r.partial) {
        if (r.bytes.length === size) return { data: r.bytes, cleanup: () => clearPartial(pid, part.count) };
        throw new Error('Wrong size');
      }
      if (r.bytes.length !== end - part.next + 1) throw new Error('A slice came back the wrong size');
      const chunkRec = { id: pid + '#' + part.count, blob: new root.Blob([r.bytes]) };
      const nextPart = { ...part, count: part.count + 1, next: end + 1 };
      await dbReq('partial', 'readwrite', (s) => {
        s.put(chunkRec);
        s.put(nextPart);
      });
      part = nextPart;
      status.partial = part.next; emit();
    }
    const blobs = [];
    for (let i = 0; i < part.count; i++) {
      const c = await dbGet('partial', pid + '#' + i);
      if (!c || !c.blob) { await clearPartial(pid, part.count); throw new Error('Partial download chunk missing'); }
      blobs.push(c.blob);
    }
    const blob = new root.Blob(blobs);
    if (blob.size !== size) { await clearPartial(pid, part.count); throw new Error('Wrong size'); }
    const count = part.count;
    return { data: blob, cleanup: () => clearPartial(pid, count) };
  }

  /* ------------------------------------------------------------ what a file is */

  // Names in the bucket are random, so what a file IS comes from the note. A plain note lists its photos and audio
  // clips; a locked note's list is encrypted, so it falls back to the counts the note keeps in the clear: if it has
  // only photos (or only clips) every file is that. A locked note with both cannot be told apart: 'mixed'.
  async function kindsFor(meta, names) {
    const out = new Map();
    const REF = (root.KSMedia && root.KSMedia.REF_PREFIX) || 'ks-media:';
    const counts = meta && meta.counts ? meta.counts : null;
    let plain = null;
    if (meta && meta.lockType === 'none') { try { plain = await root.getCachedContent(meta.id); } catch (e) { plain = null; } }
    const imgs = new Set(), auds = new Set();
    if (plain) {
      for (const s of plain.images || []) if (typeof s === 'string' && s.startsWith(REF)) imgs.add(s.slice(REF.length));
      for (const id of Object.keys(plain.audio || {})) { const d = plain.audio[id] && plain.audio[id].data; if (typeof d === 'string' && d.startsWith(REF)) auds.add(d.slice(REF.length)); }
    }
    for (const n of names) {
      if (PART_RE.test(n)) out.set(n, 'video');
      else if (imgs.has(n)) out.set(n, 'image');
      else if (auds.has(n)) out.set(n, 'audio');
      else if (plain && plain.media && plain.media[n]) out.set(n, /^audio\//i.test(plain.media[n].t || '') ? 'audio' : 'image');
      else if (plain) out.set(n, 'orphan');                                   // in the bucket, but no version of the note shows it
      else if (counts && !counts.clips) out.set(n, 'image');
      else if (counts && !counts.photos && counts.clips > 0) out.set(n, 'audio');
      else out.set(n, 'mixed');
    }
    return out;
  }

  /* ----------------------------------------------------- one note's text */

  // The note's text (and, once its unlock date has passed, the released second password). Returns the number of
  // problems (0 or 1). A network error is thrown so the run can stop and say so.
  async function syncText(meta) {
    const B = root.KSB2;
    let problems = 0;
    let activeMeta = meta;
    const cached = await root.getCachedMeta(meta.id);
    if (!cached || !cached.hasContent || cached.contentUpdatedAt !== meta.updatedAt) {
      const { meta: freshMeta, content } = await B.getNote(meta.id);
      activeMeta = freshMeta || meta;
      // Re-check outbox right before caching so a concurrent local edit is never overwritten.
      if (root.hasPendingChange && await root.hasPendingChange(activeMeta.id)) return problems;
      if (!allowed(activeMeta)) return problems;
      const latestCached = await root.getCachedMeta(activeMeta.id);
      if (!(latestCached && latestCached.hasContent && latestCached.contentUpdatedAt >= activeMeta.updatedAt)) {
        await root.cacheNote(activeMeta, content);
        const chk = await root.getCachedMeta(activeMeta.id);
        if (!chk || !chk.hasContent) problems++;
      }
    }
    if (activeMeta.lockType === 'time' && activeMeta.unlockAt && root.lockNow() >= activeMeta.unlockAt) {
      const c2 = await root.getCachedMeta(activeMeta.id);
      if (!(c2 && c2.vault && c2.vaultUpdatedAt === activeMeta.updatedAt)) {
        try {
          const { password2 } = await B.getVault(activeMeta.id);
          if (password2) await root.cacheVault(activeMeta.id, password2, activeMeta.updatedAt);
          else problems++;
        } catch (e) {
          if (e.isNetworkError) throw e;
          problems++;
        }
      }
    }
    return problems;
  }

  /* ------------------------------------------------------------------ the run */

  // A run stopped before the end. reason: stopped (you pressed Stop) | offline | error
  function halt(reason, message) {
    for (const k of STEPS) if (status.stages[k].state === 'running') status.stages[k].state = 'paused';
    status.current = '';
    status.partial = 0;
    status.phase = 'paused'; status.reason = reason; status.error = message || '';
    emit();
  }

  async function loop(picked, signal) {
    const B = root.KSB2;
    const S = root.KSMedia && root.KSMedia.store;
    Object.assign(status, { phase: 'running', reason: '', stages: blankStages(), current: '', partial: 0, problems: 0, error: '', startedAt: Date.now(), picked: { ...picked } });
    KINDS.forEach((k) => { if (!picked[k]) status.stages[k].state = 'skipped'; });
    if (!KINDS.some((k) => picked[k])) status.stages.plan.state = 'skipped';
    emit();
    if (!root.navigator.onLine) { halt('offline', 'There is no connection right now.'); return; }

    /* 1. the notes this device may open */
    stage('list', 'running');
    const listed = (await B.listNotes()).notes;
    const notes = listed.filter(allowed);
    stage('list', 'done', { done: notes.length, total: notes.length });
    const outbox = new Set(await root.getOutboxIds());

    /* 2. all the text, before anything else */
    stage('text', 'running', { done: 0, total: notes.length });
    const metaById = new Map(notes.map((m) => [m.id, m]));
    for (const meta of notes) {
      if (!go()) { halt('stopped'); return; }
      if (!allowed(meta)) { status.stages.text.done++; emit(); continue; }
      status.current = meta.title || (meta.lockType === 'none' ? 'Untitled note' : 'Locked note'); emit();
      if (!outbox.has(meta.id) && !(root.hasPendingChange && await root.hasPendingChange(meta.id))) {                       // a note with a newer local edit waiting to upload keeps that edit
        try { status.problems += await syncText(meta); }
        catch (e) {
          if (e.isNetworkError || !root.navigator.onLine) { halt('offline', 'The connection dropped while saving text.'); return; }
          if (e.notConfigured) throw e;
          status.problems++;
        }
      }
      status.stages.text.done++; emit();
    }
    stage('text', 'done');
    if (root.rerenderFromLocal) { try { await root.rerenderFromLocal(); } catch (e) { /* UI only */ } }

    /* 3. which media files are needed, and what each one is */
    const work = { image: [], audio: [], video: [] };
    if (KINDS.some((k) => picked[k]) && S) {
      const cand = notes.filter((m) => (m.mediaSize > 0) || !!(m.counts && ((m.counts.photos || 0) + (m.counts.clips || 0) + (m.counts.videos || 0) > 0)) || (m.mediaSize === undefined && !m.counts));
      stage('plan', 'running', { done: 0, total: cand.length });
      const firstWanted = picked.image ? 'image' : 'audio';
      const infoByNote = new Map();                       // read the device's file list once, not once per note
      for (const i of await S.allInfo()) { if (!infoByNote.has(i.noteId)) infoByNote.set(i.noteId, []); infoByNote.get(i.noteId).push(i); }
      for (const meta of cand) {
        if (!go()) { halt('stopped'); return; }
        if (!allowed(meta)) { status.stages.plan.done++; emit(); continue; }
        status.current = meta.title || (meta.lockType === 'none' ? 'Untitled note' : 'Locked note'); emit();
        let items;
        try { items = await B.listMedia(meta.id); }
        catch (e) {
          if (e.isNetworkError || !root.navigator.onLine) { halt('offline', 'The connection dropped while checking files.'); return; }
          status.problems++; status.stages.plan.done++; continue;
        }
        const kinds = await kindsFor(meta, items.map((i) => i.name));
        const listedNames = new Set(items.map((i) => i.name));
        for (const it of items) {
          let k = kinds.get(it.name);
          if (k === 'orphan') continue;
          if (k === 'mixed') { if (!picked.image && !picked.audio) continue; k = firstWanted; }   // cannot be told apart: saved with Images, or Audio if only Audio is ticked
          if (!picked[k]) continue;
          work[k].push({ noteId: meta.id, title: meta.title || '', name: it.name, size: it.size, mixed: kinds.get(it.name) === 'mixed' });
        }
        // Files kept here that Backblaze no longer has (deleted elsewhere) are tidied away.
        for (const h of infoByNote.get(meta.id) || []) if (!listedNames.has(h.name) && !h.pending) await S.cacheDelete([h]).catch(() => {});
        status.stages.plan.done++; emit();
      }
      stage('plan', 'done');
      KINDS.forEach((k) => { if (picked[k]) { status.stages[k].total = work[k].length; status.stages[k].bytesTotal = work[k].reduce((n, w) => n + w.size, 0); } });
      emit();
    }

    /* 4. each ticked type, one after the other */
    for (const k of KINDS) {
      if (!picked[k] || !S) continue;
      const st = status.stages[k];
      stage(k, 'running');
      for (const w of work[k]) {
        if (!go()) { halt('stopped'); return; }
        const wMeta = metaById.get(w.noteId);
        if (wMeta && !allowed(wMeta)) { st.done++; emit(); continue; }
        status.current = (w.title || 'Untitled note'); emit();
        const have = await S.infoGet(w.noteId, w.name).catch(() => null);
        if (have && have.size === w.size) {
          if (!have.pinned) await S.pin(w.noteId, w.name);
        } else {
          status.partial = 0;
          let fetched;
          try { fetched = await fetchFile(w.noteId, w.name, w.size, signal); }
          catch (e) {
            if (isQuotaError(e)) { halt('error', 'Device storage is full — free space or untick Videos.'); return; }
            if (!go() || (e && (e.name === 'AbortError' || e.isAbortError))) { halt('stopped'); return; }
            if (e.isNetworkError || !root.navigator.onLine) { halt('offline', 'The connection dropped while downloading ' + LABEL[k].toLowerCase() + '.'); return; }
            status.partial = 0; status.problems++; st.done++; emit(); continue;       // this one file is the problem; carry on with the rest
          }
          if (fetched === null) { halt('stopped'); return; }
          try {
            await S.cachePut(w.noteId, w.name, fetched.data, false, { kind: w.mixed ? '' : STORE_KIND[k], pinned: true });
          } catch (e) {
            if (isQuotaError(e)) { halt('error', 'Device storage is full — free space or untick Videos.'); return; }
            throw e;
          }
          if (fetched.cleanup) await fetched.cleanup();
        }
        st.done++; st.bytes += w.size; status.partial = 0; emit();
      }
      stage(k, 'done');
    }

    for (const p of await dbAll('partial')) if (!notes.some((n) => n.id === p.id.split('/')[0])) await dbDel('partial', p.id);
    patch({ completedAt: Date.now(), problems: status.problems, kinds: picked });
    status.phase = 'done'; status.current = ''; status.partial = 0;
    emit();
  }

  function run(picked) {
    if (running) return running;
    stopFlag = false;
    runAbort = typeof root.AbortController === 'function' ? new root.AbortController() : null;
    if (root.KeepAwake) root.KeepAwake.acquire();
    running = (async () => {
      try { await loop(picked, runAbort ? runAbort.signal : undefined); }
      catch (e) {
        if (isQuotaError(e)) halt('error', 'Device storage is full — free space or untick Videos.');
        else if (!go() || (e && (e.name === 'AbortError' || e.isAbortError))) halt('stopped');
        else if (e && (e.isNetworkError)) halt('offline', 'The connection dropped.');
        else halt('error', (e && e.message) || 'Something went wrong');
      } finally {
        if (root.KeepAwake) root.KeepAwake.release();
        runAbort = null;
        running = null;
        emit();
        refreshHave(true);
      }
    })();
    return running;
  }

  /* ----------------------------------------------------------- public actions */

  async function askPersist() {
    try { return !!(root.navigator.storage && root.navigator.storage.persist && await root.navigator.storage.persist()); } catch (e) { return false; }
  }

  // The only way a download begins: the Download / Continue button. `picked` = which media types to include.
  async function start(picked) {
    if (running) return running;
    const p = { image: !!(picked && picked.image), audio: !!(picked && picked.audio), video: !!(picked && picked.video) };
    patch({ kinds: p });
    const job = run(p);
    askPersist().then((persisted) => patch({ persisted })).catch(() => {});
    return job;
  }
  function stop() {
    stopFlag = true;
    if (runAbort) { try { runAbort.abort(); } catch (e) {} }
  }

  /* --------------------------------------------------- what is on this device */

  // Counts what is on this device right now, per type. Cached copies count: they open with no connection.
  // { notes, textHave, kinds: { image|audio|video|mixed: { files, bytes } }, totals: { image, audio, known } }
  async function inventory() {
    const empty = () => ({ files: 0, bytes: 0 });
    const out = { notes: 0, textHave: 0, kinds: { image: empty(), audio: empty(), video: empty(), mixed: empty() }, totals: { image: 0, audio: 0, video: 0, known: true } };
    let cached = [];
    try { cached = (await root.getAllCachedNotes()).filter((c) => c && c.meta && allowed(c.meta)); } catch (e) { /* storage unavailable */ }
    out.notes = cached.length;
    const byId = new Map(cached.map((c) => [c.id, c]));
    for (const c of cached) {
      if (c.hasContent) out.textHave++;
      const k = c.meta.counts;
      if (k) { out.totals.image += k.photos || 0; out.totals.audio += k.clips || 0; out.totals.video += k.videos || 0; }
      else if (c.meta.mediaSize > 0) out.totals.known = false;
    }
    let infos = [];
    try { if (root.KSMedia) infos = (await root.KSMedia.store.allInfo()).filter((i) => byId.has(i.noteId)); } catch (e) { /* storage unavailable */ }
    // Files saved before types were recorded: work each one out once, then remember it.
    const need = new Map();
    for (const i of infos) if (!i.kind && !PART_RE.test(i.name)) { if (!need.has(i.noteId)) need.set(i.noteId, []); need.get(i.noteId).push(i); }
    const writeBack = [];
    const resolved = new Map();
    for (const [noteId, list] of need) {
      const kinds = await kindsFor(byId.get(noteId).meta, list.map((i) => i.name));
      for (const i of list) {
        const k = kinds.get(i.name);
        resolved.set(i.id, k);
        if (k === 'image' || k === 'audio') writeBack.push({ info: i, kind: STORE_KIND[k] });
      }
    }
    if (writeBack.length && root.KSMedia.store.setKinds) root.KSMedia.store.setKinds(writeBack).catch(() => {});
    for (const i of infos) {
      let k = PART_RE.test(i.name) || i.kind === 'video' ? 'video' : i.kind === 'photo' ? 'image' : i.kind === 'audio' ? 'audio' : resolved.get(i.id);
      if (k !== 'image' && k !== 'audio' && k !== 'video') k = 'mixed';
      out.kinds[k].files++; out.kinds[k].bytes += i.size;
    }
    return out;
  }

  // Removes everything kept for offline use: every saved copy of photos/audio/video, and the saved text of every
  // note. Edits and uploads still waiting to reach the bucket are kept. The note list stays, so the app still
  // shows your notes; opening one fetches it again.
  async function deleteAll() {
    stop();
    if (running) { try { await running; } catch (e) { /* ended */ } }
    if (root.KSMedia) await root.KSMedia.store.deleteSynced();
    await dbClear('notes'); await dbClear('partial');
    if (root.clearCachedNoteContents) await root.clearCachedNoteContents();
    lsSet(LS_KEY, '{}');
    Object.assign(status, { phase: 'idle', reason: '', stages: blankStages(), current: '', partial: 0, problems: 0, error: '' });
    emit();
    if (root.rerenderFromLocal) { try { await root.rerenderFromLocal(); } catch (e) { /* UI only */ } }
  }

  /* ---------------------------------------------------------------------- UI */

  let haveCache = null;
  let haveAt = 0;
  let haveBusy = false;

  // The "on this device" numbers. Cheap to ask for once; while a run is going it is refreshed every few seconds.
  async function refreshHave(force) {
    if (haveBusy || !el('off-have')) return;
    if (!force && Date.now() - haveAt < 3500) return;
    haveBusy = true;
    try { haveCache = await inventory(); haveAt = Date.now(); paintHave(); }
    catch (e) { /* storage unavailable */ }
    finally { haveBusy = false; }
  }

  function paintHave() {
    const inv = haveCache; if (!inv || !el('off-have')) return;
    const set = (id, text) => { const n = el(id); if (n) n.textContent = text; };
    const row = (id, show) => { const n = el(id); if (n) n.hidden = !show; };
    const all = inv.notes;
    set('off-have-text', inv.textHave + ' of ' + plural(all, 'note', 'notes'));
    const t = inv.totals;
    const files = (k, total) => {
      const v = inv.kinds[k];
      if (!v.files) return t.known && total ? 'None of ' + total + ' yet' : 'None';
      return (t.known && total >= v.files ? v.files + ' of ' + plural(total, 'file', 'files') : plural(v.files, 'file', 'files')) + ' · ' + mb(v.bytes);
    };
    set('off-have-image', files('image', t.image));
    set('off-have-audio', files('audio', t.audio));
    set('off-have-video', inv.kinds.video.files ? plural(inv.kinds.video.files, 'part', 'parts') + ' · ' + mb(inv.kinds.video.bytes) + (t.video ? ' (' + plural(t.video, 'video', 'videos') + ' in your notes)' : '') : (t.video ? 'None of ' + plural(t.video, 'video', 'videos') + ' yet' : 'None'));
    row('off-have-mixed-row', inv.kinds.mixed.files > 0); row('off-have-mixed-row-t', inv.kinds.mixed.files > 0);
    set('off-have-mixed', plural(inv.kinds.mixed.files, 'file', 'files') + ' · ' + mb(inv.kinds.mixed.bytes));
    // Ticks show the size of each type once it is known: what the bucket holds beats a guess.
    KINDS.forEach((k) => { const n = el('off-pick-' + k); if (n) n.textContent = t.known && (k === 'video' ? t.video : t[k]) ? plural(k === 'video' ? t.video : t[k], k === 'video' ? 'video' : 'file', k === 'video' ? 'videos' : 'files') + ' in your notes' : ''; });
  }

  async function paintStorage() {
    const n = el('off-space'); if (!n) return;
    try {
      const e = await root.navigator.storage.estimate();
      n.textContent = 'Keepsake uses ' + mb(e.usage) + ' on this device · ' + mb(Math.max(0, e.quota - e.usage)) + ' free.';
    } catch (e) { n.textContent = ''; }
  }

  // The headline for the status card, from the run (if there is one) or from what is on the device.
  function view() {
    const st = status.stages;
    const picked = status.picked;
    const mediaKinds = KINDS.filter((k) => picked[k]);
    // overall progress: list 2, text 18, plan 5, media 75 (by bytes). No media ticked: text takes the rest.
    const frac = (s) => (s.total ? s.done / s.total : s.state === 'done' ? 1 : 0);
    let pct = 0;
    if (mediaKinds.length) {
      const bt = mediaKinds.reduce((n, k) => n + st[k].bytesTotal, 0);
      const bd = mediaKinds.reduce((n, k) => n + st[k].bytes, 0) + status.partial;
      const mediaFrac = bt ? Math.min(1, bd / bt) : (st.plan.state === 'done' ? 1 : 0);
      pct = (st.list.state === 'done' ? 2 : 0) + frac(st.text) * 18 + frac(st.plan) * 5 + mediaFrac * 75;
    } else {
      pct = (st.list.state === 'done' ? 2 : 0) + frac(st.text) * 98;
    }
    pct = status.phase === 'done' ? 100 : Math.max(0, Math.min(99.5, pct));
    const doneSteps = STEPS.filter((k) => st[k].state === 'done' || st[k].state === 'skipped').length;
    const s = getState();
    if (status.phase === 'running') return { state: 'running', title: 'Downloading', detail: doneSteps + ' of ' + STEPS.length + ' steps done', pct };
    if (status.phase === 'paused') {
      const why = status.reason === 'stopped' ? 'Stopped' : status.reason === 'offline' ? 'Paused: no connection' : 'Paused: something went wrong';
      return { state: status.reason === 'stopped' ? 'paused' : 'error', title: why, detail: (status.error ? status.error + ' ' : '') + 'Press Continue to carry on where it stopped.', pct };
    }
    if (status.phase === 'done') {
      const bad = status.problems ? ' ' + plural(status.problems, 'item', 'items') + ' could not be fetched; they are tried again next time.' : '';
      return { state: 'done', title: 'Finished', detail: 'Everything you chose is on this device (' + when(s.completedAt || Date.now()) + ').' + bad, pct: 100 };
    }
    const inv = haveCache;
    if (inv && inv.textHave === 0 && !KINDS.some((k) => inv.kinds[k].files) && !inv.kinds.mixed.files) return { state: 'idle', title: 'Nothing downloaded', detail: 'Notes and files are fetched live until you press Download.', pct: 0 };
    if (inv && inv.notes && inv.textHave >= inv.notes) return { state: 'idle', title: 'Text is on this device', detail: s.completedAt ? 'Last full download ' + when(s.completedAt) + '.' : 'Every note opens with no connection. Pick files below to save more.', pct: 0 };
    return { state: 'idle', title: 'Partly downloaded', detail: 'What was saved while you used the app opens with no connection. Press Download to save the rest.', pct: 0 };
  }

  function stepDetail(k) {
    const s = status.stages[k];
    if (s.state === 'skipped') return k === 'plan' ? 'Not needed' : 'Not ticked — loads live';
    if (s.state === 'pending') return '';
    if (k === 'list') return s.state === 'done' ? plural(s.total, 'note', 'notes') : '';
    if (k === 'text') return s.done + ' of ' + s.total;
    if (k === 'plan') return s.total ? s.done + ' of ' + s.total + ' notes' : '';
    return s.total ? s.done + ' of ' + plural(s.total, 'file', 'files') + ' · ' + mb(s.bytes + (s.state === 'running' ? status.partial : 0)) + ' of ' + mb(s.bytesTotal) : (s.state === 'done' ? 'Nothing to download' : '');
  }

  const ICON = { pending: '○', running: '', done: '✓', skipped: '–', paused: '⏸' };

  // Updates the live parts in place - no rebuild, so a tick box or button never loses focus mid-run.
  function paintLive() {
    const card = el('off-status'); if (!card) return;
    const v = view();
    card.dataset.state = v.state;
    const set = (id, t) => { const n = el(id); if (n && n.textContent !== t) n.textContent = t; };
    set('off-state', v.title); set('off-detail', v.detail);
    const track = el('off-track'), fill = el('off-fill');
    if (track) { track.hidden = status.phase === 'idle'; track.setAttribute('aria-valuenow', String(Math.round(v.pct))); }
    if (fill) fill.style.transform = 'scaleX(' + (v.pct / 100).toFixed(4) + ')';
    set('off-cur', status.phase === 'running' && status.current ? 'Now: ' + status.current : '');
    const steps = el('off-steps');
    if (steps) {
      steps.hidden = status.phase === 'idle';
      STEPS.forEach((k) => {
        const li = el('off-step-' + k); if (!li) return;
        const s = status.stages[k];
        li.dataset.state = s.state;
        const ic = li.querySelector('.off-step-icon'); if (ic) ic.textContent = ICON[s.state] || '';
        const d = li.querySelector('.off-step-detail'); if (d) d.textContent = stepDetail(k);
      });
    }
    const busy = status.phase === 'running';
    doc().querySelectorAll('#offline-slot [data-k]').forEach((cb) => { cb.disabled = busy; });
    const btns = el('off-buttons');
    const key = status.phase + '|' + status.reason + '|' + (haveCache ? haveCache.textHave + haveCache.kinds.image.files + haveCache.kinds.audio.files + haveCache.kinds.video.files + haveCache.kinds.mixed.files : 0);
    if (btns && btns.dataset.key !== key) { btns.dataset.key = key; paintButtons(btns); }
  }

  function startLabel() {
    const p = pickedNow();
    const names = KINDS.filter((k) => p[k]).map((k) => LABEL[k].toLowerCase());
    return 'Download text' + (names.length ? ' + ' + names.join(' + ') : ' only');
  }

  function paintButtons(box) {
    const inv = haveCache;
    const has = !!inv && (inv.textHave > 0 || KINDS.some((k) => inv.kinds[k].files) || inv.kinds.mixed.files > 0);
    const btn = (k, label, cls, id) => '<button type="button" class="btn ' + (cls || 'btn-ghost') + '" data-o="' + k + '"' + (id ? ' id="' + id + '"' : '') + '>' + label + '</button>';
    let h = '';
    if (status.phase === 'running') h += btn('stop', 'Stop');
    else if (status.phase === 'paused') h += btn('start', 'Continue', 'btn-primary', 'off-go') + btn('delete', 'Delete offline data', 'btn-outline-danger');
    else h += btn('start', status.phase === 'done' ? 'Download again' : startLabel(), 'btn-primary', 'off-go') + (has ? btn('delete', 'Delete offline data', 'btn-outline-danger') : '');
    box.innerHTML = h;
  }

  const pickedNow = () => {
    const out = { image: false, audio: false, video: false };
    if (doc()) doc().querySelectorAll('#offline-slot [data-k]').forEach((cb) => { out[cb.dataset.k] = cb.checked; });
    return out;
  };

  async function renderSettings() {
    const slot = el('offline-slot'); if (!slot) return;
    const sec = el('offline-section'); if (sec) sec.hidden = !(root.KSB2 && root.KSB2.config.configured());
    if (sec && sec.hidden) return;
    const sel = selection();
    const tick = (k, title, note) => '<label class="off-check"><input type="checkbox" data-k="' + k + '"' + (sel[k] ? ' checked' : '') + '><span><b>' + title + '</b><small>' + note + ' <span id="off-pick-' + k + '"></span></small></span></label>';
    slot.innerHTML =
      '<p class="hint">Nothing downloads on its own. Press Download to save notes on this device so they open with no connection. Anything you don’t save is loaded live from Backblaze when you open it.</p>' +
      '<div class="off-status" id="off-status" data-state="idle" role="status" aria-live="polite">' +
        '<div class="off-status-head"><span class="off-dot" aria-hidden="true"></span><div><b id="off-state">Checking…</b><p class="hint" id="off-detail"></p></div></div>' +
        '<div class="off-track" id="off-track" role="progressbar" aria-label="Download progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0" hidden><i class="off-fill" id="off-fill"></i></div>' +
        '<p class="hint off-cur" id="off-cur"></p>' +
        '<ol class="off-steps" id="off-steps" hidden>' + STEPS.map((k) => '<li class="off-step" id="off-step-' + k + '" data-state="pending"><span class="off-step-icon" aria-hidden="true"></span><span class="off-step-name">' + STEP_LABEL[k] + '</span><span class="off-step-detail"></span></li>').join('') + '</ol>' +
      '</div>' +
      '<h4 class="off-h">On this device now</h4>' +
      '<dl class="off-have" id="off-have">' +
        '<dt>Text</dt><dd id="off-have-text">…</dd>' +
        '<dt>Images</dt><dd id="off-have-image">…</dd>' +
        '<dt>Audio</dt><dd id="off-have-audio">…</dd>' +
        '<dt>Videos</dt><dd id="off-have-video">…</dd>' +
        '<dt id="off-have-mixed-row-t" hidden>Other files</dt><dd id="off-have-mixed-row" hidden><span id="off-have-mixed"></span></dd>' +
      '</dl>' +
      '<p class="hint">Notes and files kept while you used the app count too: if it is on this device, it opens offline. <span id="off-space"></span></p>' +
      '<fieldset class="off-pick"><legend class="off-h">Choose what to download</legend>' +
        '<label class="off-check"><input type="checkbox" checked disabled><span><b>Text</b><small>Every note, always first</small></span></label>' +
        tick('image', 'Images', 'Photos in your notes') + tick('audio', 'Audio', 'Voice clips in your notes') + tick('video', 'Videos', 'Large — can use a lot of data and space') +
      '</fieldset>' +
      '<p class="hint">Types you leave unticked are not saved: they load live each time you open a note, so those notes need a connection to show them.</p>' +
      '<div class="btn-row dev-wrap" id="off-buttons"></div>';
    slot.onclick = onClick;
    slot.onchange = onChange;
    haveCache = null; haveAt = 0;
    const b = el('off-buttons'); if (b) { b.dataset.key = ''; paintButtons(b); }
    paintLive();
    await refreshHave(true);
    paintStorage();
    const b2 = el('off-buttons'); if (b2) b2.dataset.key = '';   // the buttons depend on what the device holds, now known
    paintLive();
  }

  function onChange(e) {
    const cb = e.target.closest('[data-k]'); if (!cb) return;
    patch({ kinds: pickedNow() });                      // your ticks are remembered; nothing starts
    const b = el('off-buttons'); if (b) { b.dataset.key = ''; paintLive(); }
  }

  async function onClick(e) {
    const b = e.target.closest('[data-o]'); if (!b) return;
    const act = b.dataset.o;
    const confirm1 = root.openConfirm || (() => { say('Confirmation dialog unavailable — action cancelled.'); });
    const twice = root.openConfirmTwice || (() => { say('Confirmation dialog unavailable — action cancelled.'); });
    try {
      if (act === 'start') {
        const picked = pickedNow();
        const begin = async () => { start(picked); setTimeout(paintLive, 0); };
        if (picked.video) {
          let free = '';
          try { const est = await root.navigator.storage.estimate(); free = ' This device has about ' + mb(Math.max(0, est.quota - est.usage)) + ' free.'; } catch (err) { /* unknown */ }
          confirm1('Download videos too?', 'Videos are the biggest part of a notebook and can use a lot of mobile data.' + free + ' It stops if you press Stop or close the app, and carries on where it left off when you press Continue.', begin, 'Download', true);
        } else begin();
      } else if (act === 'stop') {
        stop(); say('Stopping after the file in progress. What was downloaded stays on this device.');
      } else if (act === 'delete') {
        const inv = haveCache || await inventory();
        const files = inv.kinds.image.files + inv.kinds.audio.files + inv.kinds.video.files + inv.kinds.mixed.files;
        const bytes = inv.kinds.image.bytes + inv.kinds.audio.bytes + inv.kinds.video.bytes + inv.kinds.mixed.bytes;
        twice('Delete the offline data?',
          'This removes ' + plural(files, 'file', 'files') + ' (' + mb(bytes) + ') and the saved text of your notes from this device, and stops any download. Your notes in the bucket are not touched. Edits and uploads that have not reached the bucket yet are kept.',
          'Are you sure?',
          'Last check. After this, notes need a connection to open until you download them again.',
          async () => { await deleteAll(); say('Offline data deleted'); renderSettings(); }, 'Continue', 'Yes, delete it');
      }
    } catch (err) { say(err.message || 'Something went wrong'); }
  }

  /* ----------------------------------------------------------------- start-up */

  // Repaint while the Settings dialog is open. There is deliberately nothing here that starts a download:
  // coming online, returning to the app or logging in as master do not start anything.
  if (root.addEventListener) {
    root.addEventListener('ks-offline', () => {
      const ov = el('overlay-settings');
      if (!ov || ov.classList.contains('hidden')) return;
      paintLive();
      if (status.phase === 'running') refreshHave(false);
    });
  }

  root.KSOffline = { start, stop, deleteAll, inventory, renderSettings, status: () => ({ ...status, ...getState() }), _test: { kindsFor, loop, status, setStop(v) { stopFlag = v; } } };
})(typeof window !== 'undefined' ? window : globalThis);
