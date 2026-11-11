/* ---------------------------------------------------------------------------
 * offline.js - a full offline copy of the notebook, for a device logged in as master.
 *
 * Everything in the bucket - every note's text, photo, audio clip and video part - is brought onto this device
 * and kept there. It works in small pieces so it can be stopped at any moment and carry on later:
 *
 *   - One file at a time. A file over 8 MB is fetched in 4 MB slices (an HTTP range request); each slice is saved
 *     on the device as it arrives, so an interrupted big file continues from its last slice, not from zero.
 *     (If the bucket's CORS rule turns out to refuse range requests, it falls back to whole files.)
 *   - Each finished file is stored in the device's media store, marked "pinned" so the usual size caps never
 *     drop it, and each finished note is recorded in a small progress list (IndexedDB "keepsake-offline").
 *   - Nothing else is remembered about where it was: on the next start it lists the bucket again and skips
 *     whatever is already complete, so a closed app, a dead connection or a reload all resume the same way.
 *
 * It runs while the app is open, pauses by itself when the connection drops or the master login ends, and
 * picks up again when the app opens, comes back to the screen or goes online. "Delete offline data" removes
 * everything saved for offline use except edits and uploads that have not reached the bucket yet.
 * ------------------------------------------------------------------------- */
(function (root) {
  'use strict';

  const LS_KEY = 'ks_offline';
  const DB_NAME = 'keepsake-offline';
  const CHUNK = 4 * 1024 * 1024;        // size of one slice of a big file
  const WHOLE_MAX = 8 * 1024 * 1024;    // files up to this size are fetched in one go
  const PART_RE = /\.\d{5}$/;

  /* ------------------------------------------------------------------ helpers */

  const doc = () => root.document;
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  function lsGet(k) { try { return root.localStorage.getItem(k) || ''; } catch (e) { return ''; } }
  function lsSet(k, v) { try { root.localStorage.setItem(k, v); } catch (e) { /* private mode */ } }
  function getState() { try { return JSON.parse(lsGet(LS_KEY)) || {}; } catch (e) { return {}; } }
  function patch(p) { const s = { ...getState(), ...p }; lsSet(LS_KEY, JSON.stringify(s)); return s; }
  const isMasterNow = () => !!(root.KSDevices && root.KSDevices.isMaster && root.KSDevices.isMaster());
  const say = (m) => { if (root.toast) root.toast(m); };
  const mb = (n) => (n >= 1073741824 ? (n / 1073741824).toFixed(2) + ' GB' : (n / 1048576 >= 10 ? Math.round(n / 1048576) : (n / 1048576).toFixed(1)) + ' MB');
  const when = (ts) => new Date(ts).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });

  /* ------------------------------------------------ the progress list (IndexedDB) */

  let dbp = null;
  function openDB() {
    if (dbp) return dbp;
    dbp = new Promise((resolve, reject) => {
      const r = root.indexedDB.open(DB_NAME, 1);
      r.onupgradeneeded = () => {
        const db = r.result;
        db.createObjectStore('notes', { keyPath: 'id' });     // one per finished note: { id, updatedAt, files, bytes, doneAt }
        db.createObjectStore('partial', { keyPath: 'id' });   // an unfinished big file: { id, size, next, chunks: [Blob] }
      };
      r.onsuccess = () => { const db = r.result; db.onversionchange = () => { db.close(); dbp = null; }; resolve(db); };
      r.onerror = () => { dbp = null; reject(r.error); };
    });
    return dbp;
  }
  async function dbReq(store, mode, fn) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(store, mode);
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

  // phase: idle | running | waiting | paused | done
  const status = { phase: 'idle', done: 0, total: 0, base: 0, live: 0, partial: 0, bytesTotal: 0, current: '', problems: 0, error: '' };
  let running = null;
  let stopFlag = false;
  let held = false;
  const emit = () => { try { root.dispatchEvent(new root.CustomEvent('ks-offline')); } catch (e) { /* UI only */ } };
  function setPhase(p, extra) { Object.assign(status, { phase: p }, extra || {}); emit(); }
  // Keep going only while: not told to stop, switched on, not paused, and this device is still a master.
  const go = () => { const s = getState(); return !stopFlag && !!s.on && !s.paused && isMasterNow(); };
  function halted() {
    const s = getState();
    if (!s.on) setPhase('idle');
    else if (s.paused) setPhase('paused');
    else if (!isMasterNow()) setPhase('paused', { error: 'This device is no longer logged in as master. Log in again to continue.' });
    else setPhase('paused');
  }

  /* ----------------------------------------------------------------- fetching */

  // One media file, whole or in slices. Returns bytes (Uint8Array) or a Blob, or null if told to stop.
  async function fetchFile(noteId, name, size) {
    const B = root.KSB2;
    const key = B.mediaKey(noteId, name);
    const whole = async () => {
      const bytes = await B.getBytesOrNull(key);
      if (!bytes) { const e = new Error('Missing from the bucket'); e.status = 404; throw e; }
      if (bytes.length !== size) throw new Error('Wrong size');
      return bytes;
    };
    if (size <= WHOLE_MAX || getState().rangeBroken || !B.getRange) return whole();

    const pid = noteId + '/' + name;
    let part = await dbGet('partial', pid);
    if (!part || part.size !== size) part = { id: pid, size, next: 0, chunks: [] };
    status.partial = part.next;
    while (part.next < size) {
      if (!go()) return null;
      const end = Math.min(part.next + CHUNK, size) - 1;
      let r;
      try { r = await B.getRange(key, part.next, end); }
      catch (e) {
        // A refused range request looks just like being offline. If a plain request works, ranges are the problem.
        if (e.isNetworkError && part.next === 0 && root.navigator.onLine) {
          const bytes = await whole();               // throws the network error again if we really are offline
          patch({ rangeBroken: true });
          return bytes;
        }
        throw e;
      }
      if (!r) { const e = new Error('Missing from the bucket'); e.status = 404; throw e; }
      if (!r.partial) {                                // the server ignored the range and sent everything
        if (r.bytes.length === size) { await dbDel('partial', pid).catch(() => {}); return r.bytes; }
        throw new Error('Wrong size');
      }
      if (r.bytes.length !== end - part.next + 1) throw new Error('A slice came back the wrong size');
      part.chunks.push(new root.Blob([r.bytes]));
      part.next = end + 1;
      await dbPut('partial', part);                    // saved: a restart carries on from here
      status.partial = part.next; emit();
    }
    const blob = new root.Blob(part.chunks);
    await dbDel('partial', pid).catch(() => {});
    if (blob.size !== size) throw new Error('Wrong size');
    return blob;
  }

  // One note: its text (and released second password), then every file it has. Returns the number of
  // problems (0 = complete), or 'stopped'. A network error is thrown so the run can wait for a connection.
  async function syncNote(meta) {
    const B = root.KSB2;
    let problems = 0, files = 0, bytes = 0;
    const cached = await root.getCachedMeta(meta.id);
    if (!cached || !cached.hasContent || cached.contentUpdatedAt !== meta.updatedAt) {
      const { content } = await B.getNote(meta.id);
      await root.cacheNote(meta, content);
      const chk = await root.getCachedMeta(meta.id);
      if (!chk || !chk.hasContent) problems++;
    }
    if (meta.lockType === 'time' && meta.unlockAt && root.lockNow() >= meta.unlockAt) {
      const c2 = await root.getCachedMeta(meta.id);
      if (!(c2 && c2.vault && c2.vaultUpdatedAt === meta.updatedAt)) {
        try { const { password2 } = await B.getVault(meta.id); if (password2) await root.cacheVault(meta.id, password2, meta.updatedAt); }
        catch (e) { if (e.isNetworkError) throw e; }
      }
    }

    const S = root.KSMedia.store;
    const items = await B.listMedia(meta.id);
    const listed = new Set(items.map((i) => i.name));
    const have = new Map((await S.infoForNote(meta.id)).map((i) => [i.name, i]));
    status.live = 0;
    for (const it of items) {
      if (!go()) return 'stopped';
      const h = have.get(it.name);
      if (h && h.size === it.size) {
        if (!h.pinned) await S.pin(meta.id, it.name);
      } else {
        status.partial = 0;
        let data;
        try { data = await fetchFile(meta.id, it.name, it.size); }
        catch (e) {
          if (e.isNetworkError || !root.navigator.onLine) throw e;
          problems++; continue;                        // this one file is the problem; carry on with the rest
        }
        if (data === null) return 'stopped';
        await S.cachePut(meta.id, it.name, data, false, { kind: PART_RE.test(it.name) ? 'video' : '', pinned: true });
      }
      files++; bytes += it.size; status.live += it.size; status.partial = 0; emit();
    }
    for (const [name, h] of have) if (!listed.has(name) && !h.pending) await S.cacheDelete([h]);   // gone from the bucket
    return problems ? problems : { files, bytes };
  }

  /* ------------------------------------------------------------------ the run */

  async function loop() {
    if (!root.navigator.onLine) { setPhase('waiting'); return; }
    setPhase('running', { current: 'Looking at your notes…', problems: 0, error: '', live: 0, partial: 0 });
    const { notes } = await root.KSB2.listNotes();
    const outbox = new Set(await root.getOutboxIds());
    const marks = new Map((await dbAll('notes')).map((m) => [m.id, m]));
    const weight = (m) => (m.size || 0) + (m.mediaSize || 0);
    const isDone = (m) => { const k = marks.get(m.id); return !!k && k.updatedAt === m.updatedAt; };
    status.total = notes.length;
    status.bytesTotal = notes.reduce((n, m) => n + weight(m), 0);
    status.done = notes.filter(isDone).length;
    status.base = notes.filter(isDone).reduce((n, m) => n + weight(m), 0);
    patch({ totals: { notes: status.total, bytes: status.bytesTotal } });
    emit();

    let problems = 0;
    for (const meta of notes) {
      if (!go()) { halted(); return; }
      if (isDone(meta) || outbox.has(meta.id)) continue;   // done already, or a newer local edit is waiting to upload
      status.current = meta.title || 'Untitled note'; emit();
      let r;
      try { r = await syncNote(meta); }
      catch (e) {
        if (e.isNetworkError || !root.navigator.onLine) { setPhase('waiting'); return; }
        if (e.notConfigured) throw e;
        problems++; continue;
      }
      if (r === 'stopped') { halted(); return; }
      if (typeof r === 'number') { problems += r; continue; }
      await dbPut('notes', { id: meta.id, updatedAt: meta.updatedAt, files: r.files, bytes: r.bytes, doneAt: Date.now() });
      status.done++; status.base += weight(meta); status.live = 0; emit();
    }
    const live = new Set(notes.map((n) => n.id));
    for (const k of marks.keys()) if (!live.has(k)) await dbDel('notes', k);
    for (const p of await dbAll('partial')) if (!live.has(p.id.split('/')[0])) await dbDel('partial', p.id);
    patch({ completedAt: Date.now(), problems });
    setPhase('done', { problems, current: '' });
  }

  function run() {
    if (running) return running;
    stopFlag = false;
    running = (async () => {
      try { await loop(); }
      catch (e) { setPhase('paused', { error: (e && e.message) || 'Something went wrong' }); }
      finally { running = null; emit(); }
    })();
    return running;
  }

  /* ----------------------------------------------------------- public actions */

  async function askPersist() {
    try { return !!(root.navigator.storage && root.navigator.storage.persist && await root.navigator.storage.persist()); } catch (e) { return false; }
  }

  async function start() {
    if (!isMasterNow()) throw new Error('Log in as master to sync everything offline.');
    held = false;
    const persisted = await askPersist();
    patch({ on: true, paused: false, persisted });
    return run();
  }
  function pause() { patch({ paused: true }); stopFlag = true; }
  function unpause() { patch({ on: true, paused: false }); return run(); }
  function stop() { patch({ on: false, paused: false }); stopFlag = true; }
  // Picks the work up again: when the app opens, returns to the screen, goes online, or the master logs in.
  function resume() {
    const s = getState();
    if (!s.on || s.paused || running || !isMasterNow()) return Promise.resolve();
    return run();
  }

  // What would starting involve? { notes, bytes, free }
  async function estimate() {
    const { notes } = await root.KSB2.listNotes();
    let free = null;
    try { const e = await root.navigator.storage.estimate(); free = e.quota - e.usage; } catch (e) { /* unknown */ }
    return { notes: notes.length, bytes: notes.reduce((n, m) => n + (m.size || 0) + (m.mediaSize || 0), 0), free };
  }

  async function summary() {
    let files = 0, bytes = 0, notes = 0;
    try {
      if (root.KSMedia) { const all = (await root.KSMedia.store.allInfo()).filter((i) => !i.pending); files = all.length; bytes = all.reduce((n, i) => n + i.size, 0); }
      notes = (await dbAll('notes')).length;
    } catch (e) { /* storage unavailable */ }
    return { files, bytes, notes };
  }

  // Removes everything kept for offline use: the full copy, the ordinary cached photos/audio/video, and the
  // saved text of every note. Edits and uploads still waiting to reach the bucket are kept. The note list
  // stays, so the app still shows your notes; opening one fetches it again.
  async function deleteAll() {
    stop();
    if (running) { try { await running; } catch (e) { /* ended */ } }
    held = true;                                       // no quiet refill during this session
    if (root.KSMedia) await root.KSMedia.store.deleteSynced();
    await dbClear('notes'); await dbClear('partial');
    if (root.clearCachedNoteContents) await root.clearCachedNoteContents();
    lsSet(LS_KEY, '{}');
    status.done = 0; status.total = 0; status.base = 0; status.live = 0; status.bytesTotal = 0; status.error = '';
    setPhase('idle');
    if (root.rerenderFromLocal) { try { await root.rerenderFromLocal(); } catch (e) { /* UI only */ } }
  }

  // The app's ordinary quiet download of notes checks this, so it doesn't undo a delete straight away.
  const prefetchHeld = () => held;
  const active = () => !!getState().on && isMasterNow();

  /* ---------------------------------------------------------------------- UI */

  let lastKey = '';
  function line() {
    const s = getState();
    const have = status.bytesTotal ? mb(status.base + status.live + status.partial) + ' of ' + mb(status.bytesTotal) : '';
    if (status.phase === 'running') return 'Syncing: ' + status.done + ' of ' + status.total + ' notes' + (have ? ' · ' + have : '');
    if (status.phase === 'waiting') return 'Waiting for a connection — it carries on by itself. ' + status.done + ' of ' + status.total + ' notes so far.';
    if (status.phase === 'paused') return (s.paused ? 'Paused' : 'Stopped') + ': ' + status.done + ' of ' + status.total + ' notes' + (have ? ' · ' + have : '') + '.' + (status.error ? ' ' + status.error : '');
    if (status.phase === 'done') return 'Everything is on this device' + (s.completedAt ? ' (checked ' + when(s.completedAt) + ')' : '') + '.' + (status.problems ? ' ' + status.problems + ' file(s) could not be fetched; they are retried next time.' : '');
    return '';
  }
  function paint() {
    const t = doc() && doc().getElementById('off-text'); if (!t) return;
    t.textContent = line();
    const cur = doc().getElementById('off-cur'); if (cur) cur.textContent = status.phase === 'running' ? status.current : '';
    const bar = doc().querySelector('#off-bar > i');
    if (bar) bar.style.width = (status.bytesTotal ? Math.min(100, (status.base + status.live + status.partial) / status.bytesTotal * 100) : (status.total ? status.done / status.total * 100 : 0)) + '%';
  }

  async function renderSettings() {
    const slot = doc() && doc().getElementById('offline-slot'); if (!slot) return;
    const sec = doc().getElementById('offline-section');
    const master = isMasterNow();
    const s = getState();
    const sum = await summary();
    const has = sum.files > 0 || sum.notes > 0;
    if (sec) sec.hidden = !(master || has || s.on);
    if (sec && sec.hidden) return;
    if (status.phase === 'idle' && s.on && !running) status.phase = s.paused ? 'paused' : 'idle';
    const key = [master, s.on, s.paused, status.phase, has].join('|');
    if (key !== lastKey || !doc().getElementById('off-text')) {
      lastKey = key;
      const btn = (k, label, cls) => '<button class="btn ' + (cls || 'btn-ghost') + '" data-o="' + k + '">' + label + '</button>';
      let html = '', buttons = '';
      if (!s.on) {
        html = '<p class="hint">' + (master
          ? 'Download every note, photo, audio clip and video to this device, a little at a time, so all of it opens with no connection. If the app closes partway it carries on where it stopped. It needs room on this device and uses data.'
          : 'A full offline copy can be started from a device that is logged in as master.') + '</p>';
        if (master) buttons += btn('start', 'Sync all data offline', 'btn-primary');
      } else {
        html = '<div class="off-bar" id="off-bar" role="progressbar" aria-label="Offline sync progress"><i></i></div><p class="hint" id="off-text"></p><p class="hint" id="off-cur"></p>';
        if (status.phase === 'running' || status.phase === 'waiting') buttons += btn('pause', 'Pause');
        else if (s.paused || status.phase === 'paused') buttons += btn('resume', 'Resume', 'btn-primary');
        else buttons += btn('again', 'Check for changes now');
        buttons += btn('stop', 'Stop syncing');
      }
      if (has) buttons += btn('delete', 'Delete offline data', 'btn-danger');
      html += '<div class="btn-row dev-wrap">' + buttons + '</div>';
      html += '<p class="hint" id="off-have"></p>';
      slot.innerHTML = html;
      slot.onclick = onClick;
    }
    const have = doc().getElementById('off-have');
    if (have) have.textContent = has ? 'Saved on this device: ' + sum.notes + ' notes synced · ' + sum.files + ' files (' + mb(sum.bytes) + ').' + (s.persisted ? ' Your browser has agreed to keep it.' : '') : '';
    paint();
  }

  async function onClick(e) {
    const b = e.target.closest('[data-o]'); if (!b) return;
    const act = b.dataset.o;
    const confirm1 = root.openConfirm || ((t, m, fn) => fn());
    const twice = root.openConfirmTwice || ((t, m, t2, m2, fn) => fn());
    try {
      if (act === 'start' || act === 'again') {
        if (act === 'again') { unpause(); renderSettings(); return; }
        b.disabled = true;
        let est;
        try { est = await estimate(); } catch (err) { b.disabled = false; say('Could not reach your bucket: ' + (err.message || 'try again')); return; }
        b.disabled = false;
        const tight = est.free != null && est.bytes > est.free * 0.9;
        confirm1('Sync all data offline?',
          'This downloads ' + est.notes + ' notes, about ' + mb(est.bytes) + ' in all, to this device' + (est.free != null ? ' (about ' + mb(est.free) + ' free)' : '') + '. ' +
          (tight ? 'That may not fit: the sync will stop if the device runs out of room. ' : '') +
          'It runs while the app is open, in small pieces, and carries on where it stopped if the app closes. It uses mobile data if you are not on Wi-Fi.',
          async () => { await start(); renderSettings(); }, 'Start syncing', true);
      } else if (act === 'pause') { pause(); renderSettings(); }
      else if (act === 'resume') { unpause(); renderSettings(); }
      else if (act === 'stop') { stop(); halted(); renderSettings(); say('Sync stopped. What was already downloaded stays on this device.'); }
      else if (act === 'delete') {
        const sum = await summary();
        twice('Delete the offline data?',
          'This removes ' + sum.files + ' files (' + mb(sum.bytes) + ') and the saved text of your notes from this device, and stops the sync. Your notes in the bucket are not touched. Edits and uploads that have not reached the bucket yet are kept.',
          'Are you sure?',
          'Last check. After this, notes need a connection to open until they are downloaded again. The app will rebuild its small ordinary cache the next time it opens online.',
          async () => { await deleteAll(); say('Offline data deleted'); renderSettings(); }, 'Continue', 'Yes, delete it');
      }
    } catch (err) { say(err.message || 'Something went wrong'); }
  }

  /* ----------------------------------------------------------------- start-up */

  if (root.addEventListener) {
    root.addEventListener('online', () => resume());
    let lastFull = 0;
    root.addEventListener('ks-offline', () => {         // cheap repaint of the numbers; the full panel at most every few seconds
      const ov = root.document && root.document.getElementById('overlay-settings');
      if (!ov || ov.classList.contains('hidden')) return;
      if (Date.now() - lastFull > 4000) { lastFull = Date.now(); renderSettings(); } else paint();
    });
    root.addEventListener('ks-master-changed', () => { if (!isMasterNow() && running) stopFlag = true; else resume(); renderSettings(); });
    if (root.document) root.document.addEventListener('visibilitychange', () => { if (root.document.visibilityState === 'visible') resume(); });
  }

  root.KSOffline = { start, pause, unpause, stop, resume, deleteAll, estimate, summary, renderSettings, prefetchHeld, active, status: () => ({ ...status, ...getState() }) };
})(typeof window !== 'undefined' ? window : globalThis);
