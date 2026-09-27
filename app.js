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
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function b64ToBytes(str) {
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

const Config = {
  base() { return localStorage.getItem('ks_apiBase') || ''; },
  token() { return localStorage.getItem('ks_token') || ''; },
  setBase(v) { localStorage.setItem('ks_apiBase', v.trim().replace(/\/+$/, '')); },
  setToken(v) { localStorage.setItem('ks_token', v.trim()); },
  configured() { return !!(this.base() && this.token()); },
};

const API = {
  async request(path, opts = {}) {
    const res = await fetch(Config.base() + path, {
      ...opts,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + Config.token(),
        ...(opts.headers || {}),
      },
    });
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
  // Error carrying .status/.body) but over XHR instead of fetch, so we can
  // report real upload progress for payloads that carry photos.
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
      xhr.onerror = () => reject(new Error('Network error — check your connection'));
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
  saveNote(id, payload, onProgress) { return this.requestWithProgress('/api/notes/' + id, 'PUT', payload, onProgress); },
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
  ctx.drawImage(img, 0, 0, width, height);
  return canvas.toDataURL('image/jpeg', quality);
}

// Workers KV caps each value at 25MB (see README) — content:{id} holds the
// note's title + body + every photo, so this is the ceiling for all of it
// combined, not per photo.
const NOTE_SIZE_LIMIT = 25 * 1024 * 1024;

function estimateContentBytes() {
  const title = document.getElementById('editor-title').value || '';
  const body = document.getElementById('editor-body').value || '';
  let total = title.length + body.length;
  for (const src of editorImages) total += estimateImageBytes(src);
  return total;
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
 * Local draft cache — IndexedDB, not localStorage
 *
 * A note with a few photos can easily be tens of MB, well past
 * localStorage's ~5MB quota, so drafts live in IndexedDB instead. This is
 * a same-device safety net for an *abrupt* close only (crash, dead
 * battery, a swiped-away tab) — anything gentler than that is already
 * covered by the background server sync further down this file. Every
 * draft is cleared the moment its content actually reaches the server.
 * ------------------------------------------------------------------- */

const DRAFT_DB_NAME = 'keepsake-drafts';
const DRAFT_STORE = 'drafts';

function openDraftDB() {
  return new Promise((resolve, reject) => {
    if (!window.indexedDB) { reject(new Error('IndexedDB unavailable')); return; }
    const req = indexedDB.open(DRAFT_DB_NAME, 1);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(DRAFT_STORE)) {
        req.result.createObjectStore(DRAFT_STORE, { keyPath: 'id' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function saveLocalDraft(id, title, body, images) {
  if (!id) return;
  try {
    const db = await openDraftDB();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(DRAFT_STORE, 'readwrite');
      tx.objectStore(DRAFT_STORE).put({ id, title, body, images, savedAt: Date.now() });
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
  } catch (e) {
    // Best-effort only — local caching should never interrupt the editor.
  }
}

async function loadLocalDraft(id) {
  try {
    const db = await openDraftDB();
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(DRAFT_STORE, 'readonly');
      const req = tx.objectStore(DRAFT_STORE).get(id);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
  } catch (e) { return null; }
}

async function clearLocalDraft(id) {
  if (!id) return;
  try {
    const db = await openDraftDB();
    const tx = db.transaction(DRAFT_STORE, 'readwrite');
    tx.objectStore(DRAFT_STORE).delete(id);
  } catch (e) {
    // Worst case an orphaned draft lingers and gets offered for recovery
    // again later, which is harmless.
  }
}

async function listLocalDraftIds() {
  try {
    const db = await openDraftDB();
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(DRAFT_STORE, 'readonly');
      const req = tx.objectStore(DRAFT_STORE).getAllKeys();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => reject(req.error);
    });
  } catch (e) { return []; }
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
  document.getElementById(id).classList.remove('hidden');
  if (id === 'overlay-editor') applyEditorViewportFix();
}
function hide(id) {
  document.getElementById(id).classList.add('hidden');
  if (id === 'overlay-editor') applyEditorViewportFix();
}

/* ---------------------------------------------------------------------
 * Keyboard viewport fix
 *
 * Mobile browsers (iOS Safari/standalone in particular) resize the
 * *visual* viewport when the keyboard opens but leave the *layout*
 * viewport — the box `position: fixed` elements are pinned to — alone.
 * The full-screen editor is `inset: 0`, so it keeps sizing itself to the
 * old, taller layout viewport, and the sliver between the bottom of the
 * shrunk visible area and the bottom of that old box renders as a plain
 * dark gap behind the keyboard. Keeping the editor's own height and
 * offset in sync with `visualViewport` closes that gap, so the toolbar
 * ends up sitting right above the keyboard with nothing behind it.
 * ------------------------------------------------------------------- */

function applyEditorViewportFix() {
  const el = document.getElementById('overlay-editor');
  if (!el) return;
  const vv = window.visualViewport;
  if (!vv || el.classList.contains('hidden')) {
    el.style.top = '';
    el.style.height = '';
    return;
  }
  el.style.top = vv.offsetTop + 'px';
  el.style.height = vv.height + 'px';
}

function setupKeyboardViewportFix() {
  if (!window.visualViewport) return;
  window.visualViewport.addEventListener('resize', applyEditorViewportFix);
  window.visualViewport.addEventListener('scroll', applyEditorViewportFix);
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
  bar.classList.remove('error');
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
  syncBarHideSoon();
}

function syncBarError(label, onRetry) {
  clearTimeout(syncBarHideTimer);
  const bar = document.getElementById('sync-bar');
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
let editingNoteId = null;        // generated client-side the moment the editor opens — see openEditorWithContent
let noteExistsOnServer = false;  // false until this note's first background save actually succeeds
let editorImages = [];
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

  let pill = '';
  if (meta.lockType === 'quick') {
    pill = `<span class="lock-pill quick">${lockGlyph}Quick lock</span>`;
  } else if (meta.lockType === 'time') {
    const left = fmtCountdown(meta.unlockAt);
    pill = `<span class="lock-pill time">${lockGlyph}${left ? left + ' left' : 'Ready to open'}</span>`;
  }

  const titleText = isLocked ? 'Locked note' : (meta.title || 'Untitled');
  let snippet = meta.preview || '';
  if (isLocked) {
    snippet = meta.lockType === 'time' && !fmtCountdown(meta.unlockAt)
      ? 'Its time lock has ended — open it with your password.'
      : 'Contents hidden until unlocked.';
  }

  return `
    <article class="card ${typeClass}">
      <div class="card-open" data-action="open" data-id="${meta.id}" role="button" tabindex="0">
        ${pill}
        <div class="card-title">${escapeHTML(titleText)}</div>
        <div class="card-snippet">${escapeHTML(snippet)}</div>
        <div class="card-meta">${fmtDate(meta.updatedAt || meta.createdAt)}</div>
      </div>
      <div class="card-actions">
        <button class="icon-btn" data-action="download" data-id="${meta.id}" title="Download" aria-label="Download">${downloadGlyph}</button>
        <span class="spacer"></span>
        <button class="icon-btn" data-action="delete" data-id="${meta.id}" title="Delete" aria-label="Delete">${trashGlyph}</button>
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

// Patches a single note's meta into the cache and re-renders, instead of
// re-fetching and rebuilding the whole grid after every save. This is what
// makes a save actually feel instant in the list, not just in the editor.
function patchNoteInCache(meta) {
  const idx = notesCache.findIndex((m) => m.id === meta.id);
  if (idx === -1) notesCache.unshift(meta); else notesCache[idx] = meta;
  renderNotes();
  renderLocked();
}

async function refreshNotes() {
  if (!notesLoaded) {
    const loading = emptyStateHTML('Loading…', 'Fetching your notes.');
    document.getElementById('grid-notes').innerHTML = loading;
    document.getElementById('grid-locked').innerHTML = loading;
  }
  try {
    const { notes } = await API.listNotes();
    notesCache = notes;
    notesLoaded = true;
    renderNotes();
    renderLocked();
  } catch (e) {
    toast('Could not load notes: ' + e.message);
    if (!notesLoaded) {
      const failed = emptyStateHTML('Could not load notes', e.message);
      document.getElementById('grid-notes').innerHTML = failed;
      document.getElementById('grid-locked').innerHTML = failed;
    }
  }
}

function switchView(view) {
  currentView = view;
  document.getElementById('tab-notes').setAttribute('aria-selected', String(view === 'notes'));
  document.getElementById('tab-locked').setAttribute('aria-selected', String(view === 'locked'));
  document.getElementById('grid-notes').classList.toggle('hidden', view !== 'notes');
  document.getElementById('grid-locked').classList.toggle('hidden', view !== 'locked');
}

/* ---------------------------------------------------------------------
 * Editor
 * ------------------------------------------------------------------- */

function renderEditorThumbs() {
  const wrap = document.getElementById('editor-thumbs');
  wrap.innerHTML = editorImages.map((src, i) => `
    <div class="thumb">
      <img src="${src}" alt="" data-idx="${i}">
      <span class="thumb-size">${formatBytes(estimateImageBytes(src))}</span>
      <button class="thumb-remove" data-idx="${i}" aria-label="Remove image">×</button>
    </div>`).join('');
  wrap.querySelectorAll('.thumb-remove').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      editorImages.splice(Number(btn.dataset.idx), 1);
      renderEditorThumbs();
      onEditorContentChanged();
    });
  });
  wrap.querySelectorAll('img').forEach((img) => {
    img.addEventListener('click', () => openLightbox(Number(img.dataset.idx)));
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

function renderLockSummary() {
  const el = document.getElementById('editor-lock-summary');
  const removeBtn = document.getElementById('btn-remove-lock');
  const active = pendingLock && pendingLock.type !== 'none';
  if (removeBtn) removeBtn.style.display = active ? '' : 'none';
  if (!active) { el.innerHTML = ''; return; }
  el.innerHTML = pendingLock.type === 'quick'
    ? `<p class="hint">Quick lock will be applied when you save.</p>`
    : `<p class="hint">Time-locked until ${fmtDateTime(pendingLock.unlockAt)}.</p>`;
}

function computeEditorSnapshot() {
  return JSON.stringify({
    title: document.getElementById('editor-title').value,
    body: document.getElementById('editor-body').value,
    images: editorImages,
    lock: pendingLock ? { type: pendingLock.type, unlockAt: pendingLock.unlockAt || null } : null,
  });
}

function noteHasContent() {
  const title = document.getElementById('editor-title').value.trim();
  const body = document.getElementById('editor-body').value;
  return !!(title || body || editorImages.length);
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
  document.getElementById('editor-title').value = content.title || '';
  document.getElementById('editor-body').value = content.body || '';
  editorImages = (content.images || []).slice();
  renderEditorThumbs();
  document.getElementById('btn-delete-note').style.display = noteExistsOnServer ? '' : 'none';

  pendingLock = (meta && meta.lockType && meta.lockType !== 'none')
    ? { type: meta.lockType, unlockAt: meta.unlockAt, existing: true }
    : null;
  renderLockSummary();
  lastAutosavedJSON = computeEditorSnapshot();
  seedSyncStateImages(editingNoteId, editorImages);
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
  const draftKey = JSON.stringify({ title: draft.title || '', body: draft.body || '', images: draft.images || [] });
  const serverKey = JSON.stringify({
    title: serverContent.title || '', body: serverContent.body || '', images: serverContent.images || [],
  });
  if (draftKey === serverKey) { clearLocalDraft(noteId); return; }
  if (editingNoteId !== noteId) return; // the user has already moved on

  openConfirm(
    'Restore unsaved draft?',
    'This note has changes from an earlier session that never made it to the server. Restore them?',
    async () => {
      if (editingNoteId !== noteId) return;
      document.getElementById('editor-title').value = draft.title || '';
      document.getElementById('editor-body').value = draft.body || '';
      editorImages = (draft.images || []).slice();
      renderEditorThumbs();
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
  return {
    title: document.getElementById('editor-title').value.trim(),
    body: document.getElementById('editor-body').value,
    images: editorImages.slice(),
    lock: resolveLockForSnapshot(),
  };
}

async function buildSavePayload(snapshot) {
  const { title, body, images, lock } = snapshot;
  const content = { title, body, images };
  let payload;

  if (!lock || lock.type === 'none') {
    payload = { lockType: 'none', title, preview: makePreview(body), content };
  } else if (lock.type === 'quick') {
    if (!lock.password) throw new Error('missing password for quick lock');
    const record = await encryptNote(lock.password, content);
    payload = { lockType: 'quick', content: record };
  } else if (lock.type === 'time') {
    if (!lock.password) throw new Error('missing password for time lock');
    const record = await encryptNote(combine(lock.password, lock.password2), content);
    payload = { lockType: 'time', unlockAt: lock.unlockAt, password2: lock.password2, content: record };
  }

  return { payload, hasImages: images.length > 0 };
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
function seedSyncStateImages(noteId, images) {
  let state = syncStateByNote.get(noteId);
  if (!state) { state = { inFlight: false, queued: null }; syncStateByNote.set(noteId, state); }
  state.lastSyncedImagesJSON = JSON.stringify(images);
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
    built = await buildSavePayload(snapshot);
  } catch (e) {
    state.inFlight = false;
    toast('Could not lock note — try setting the lock again.');
    if (showInBar()) syncBarError('Couldn\u2019t save — check the lock', () => runSync(noteId, snapshot));
    maybeContinueQueued(noteId, state);
    return;
  }

  const { payload, hasImages } = built;

  // The note's photos are stored together with its text in one blob (see
  // worker.js), so every save necessarily re-sends all of it — but that's
  // only worth calling out as "saving photos" when photos are actually
  // part of what changed. Otherwise a plain text edit on a photo-heavy
  // note would misleadingly claim to be re-saving pictures on every
  // autosave tick.
  const imagesJSON = JSON.stringify(snapshot.images);
  const imagesChanged = hasImages && imagesJSON !== state.lastSyncedImagesJSON;

  const onProgress = imagesChanged && showInBar()
    ? (fraction) => syncBarSet(`Saving photos… ${Math.round(fraction * 100)}%`, fraction)
    : null;
  if (showInBar()) syncBarSet(imagesChanged ? 'Saving photos… 0%' : 'Saving…', imagesChanged ? 0 : null);

  try {
    const { note } = await API.saveNote(noteId, payload, onProgress);
    if (noteId === editingNoteId) {
      noteExistsOnServer = true;
      document.getElementById('btn-delete-note').style.display = '';
      document.getElementById('editor-heading').textContent = 'Edit note';
      lastAutosavedJSON = JSON.stringify(snapshot);
    }
    state.lastSyncedImagesJSON = imagesJSON;
    clearLocalDraft(noteId);
    patchNoteInCache(note);
    if (showInBar()) syncBarSuccess('Saved');
  } catch (e) {
    if (showInBar()) {
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

  if (!localDraftThrottle) {
    localDraftThrottle = setTimeout(() => {
      localDraftThrottle = null;
      if (noteHasContent()) {
        saveLocalDraft(
          editingNoteId,
          document.getElementById('editor-title').value,
          document.getElementById('editor-body').value,
          editorImages.slice()
        );
      }
    }, 1000);
  }

  clearTimeout(serverSyncDebounce);
  serverSyncDebounce = setTimeout(triggerAutosave, 2000);

  if (!serverSyncSafetyInterval) {
    serverSyncSafetyInterval = setInterval(triggerAutosave, 15000);
  }
}

function triggerAutosave() {
  if (!editingNoteId || !noteHasContent()) return;
  const snapshot = captureSnapshot();
  const key = JSON.stringify(snapshot);
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
  const overLimit = estimateContentBytes() > NOTE_SIZE_LIMIT;

  if (overLimit && isExplicitSave) {
    toast('This note is over the 25MB limit — remove a photo before saving.');
    return;
  }

  stopAutosaveTimers();

  if (!noteHasContent()) {
    clearLocalDraft(noteId);
    hide('overlay-editor');
    currentUnlockCreds = null;
    return;
  }

  if (overLimit) {
    // Closing (not explicitly saving) with an oversized note: the local
    // draft cache already has it, so nothing is lost — just skip sending a
    // request to the server that KV would reject anyway.
    hide('overlay-editor');
    currentUnlockCreds = null;
    toast('Kept on this device only — this note is over the 25MB limit. Remove a photo to sync it.');
    return;
  }

  const snapshot = captureSnapshot();
  const key = JSON.stringify(snapshot);
  hide('overlay-editor'); // instant — the real work continues below, in the background
  currentUnlockCreds = null;

  if (key === lastAutosavedJSON) return; // autosave already has this exact version covered
  runSync(noteId, snapshot);
}

function saveNote() { closeEditorAndSync(true); }
function attemptCloseEditor() { closeEditorAndSync(false); }

function confirmDelete(id, fromEditor) {
  openConfirm('Delete this note?', 'This can\u2019t be undone.', async () => {
    // Optimistic: drop it from the list immediately rather than waiting on
    // a full refetch, then reconcile quietly if the request turns out to
    // have failed.
    const previous = notesCache;
    notesCache = notesCache.filter((m) => m.id !== id);
    renderNotes();
    renderLocked();
    clearLocalDraft(id);
    if (fromEditor) hide('overlay-editor');
    try {
      await API.deleteNote(id);
      toast('Deleted');
    } catch (e) {
      notesCache = previous;
      renderNotes();
      renderLocked();
      toast('Could not delete: ' + e.message);
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
}

function openLockChooser() {
  resetLockChooser();
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
    document.getElementById('btn-do-unlock').addEventListener('click', async () => {
      const pw = document.getElementById('unlock-password').value;
      try {
        const { content: record } = await API.getNote(meta.id);
        const content = await decryptNote(pw, record);
        currentUnlockCreds = { password: pw };
        hide('overlay-unlock');
        openEditorWithContent(meta, content);
      } catch (e) {
        const err = document.getElementById('unlock-error');
        err.textContent = 'Wrong password.';
        err.style.display = '';
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
    document.getElementById('btn-do-unlock').addEventListener('click', async () => {
      const pw = document.getElementById('unlock-password').value;
      const err = document.getElementById('unlock-error');
      try {
        const { password2 } = await API.getVault(meta.id);
        const { content: record } = await API.getNote(meta.id);
        const content = await decryptNote(combine(pw, password2), record);
        currentUnlockCreds = { password: pw, password2 };
        hide('overlay-unlock');
        openEditorWithContent(meta, content);
      } catch (e) {
        err.textContent = 'Wrong password.';
        err.style.display = '';
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

  document.getElementById('btn-do-unlock').addEventListener('click', async () => {
    const pw = document.getElementById('unlock-password').value;
    const pw2 = document.getElementById('unlock-password2').value;
    const err = document.getElementById('unlock-error');
    try {
      const { content: record } = await API.getNote(meta.id);
      const content = await decryptNote(combine(pw, pw2), record);
      currentUnlockCreds = { password: pw, password2: pw2 };
      hide('overlay-unlock');
      openEditorWithContent(meta, content);
    } catch (e) {
      err.textContent = 'Couldn\u2019t unlock — check both passwords.';
      err.style.display = '';
    }
  });
}

async function handleOpenCard(id) {
  const meta = notesCache.find((m) => m.id === id);
  if (!meta) return;
  if (meta.lockType === 'none') {
    try {
      const { content } = await API.getNote(id);
      currentUnlockCreds = null;
      openEditorWithContent(meta, content);
    } catch (e) {
      toast('Could not load note: ' + e.message);
    }
    return;
  }
  currentUnlockCreds = null;
  openUnlockFlow(meta);
}

async function downloadNote(id) {
  try {
    const bundle = await API.exportNote(id);
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

function openSettings() {
  document.getElementById('settings-api-base').value = Config.base();
  document.getElementById('settings-token').value = Config.token();
  document.getElementById('settings-version').textContent = window.KEEPSAKE_VERSION || '1.2.0';
  show('overlay-settings');
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
    ov.addEventListener('click', (e) => { if (e.target === ov) hide(ov.id); });
  });
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    const openModals = document.querySelectorAll('.overlay:not(.hidden)');
    if (openModals.length) {
      // A modal (settings, lock chooser, unlock, confirm) is on top — close
      // just that, and leave the full-screen editor underneath it alone.
      openModals.forEach((ov) => hide(ov.id));
      return;
    }
    if (!document.getElementById('overlay-editor').classList.contains('hidden')) {
      attemptCloseEditor();
    }
  });

  document.addEventListener('click', (e) => {
    const el = e.target.closest('[data-action]');
    if (!el) return;
    const { action, id } = el.dataset;
    if (action === 'open') handleOpenCard(id);
    if (action === 'download') downloadNote(id);
    if (action === 'delete') confirmDelete(id, false);
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
  document.getElementById('editor-body').addEventListener('input', onEditorContentChanged);

  document.getElementById('btn-attach-image').addEventListener('click', () => {
    document.getElementById('input-image').click();
  });
  document.getElementById('input-image').addEventListener('change', async (e) => {
    const files = Array.from(e.target.files || []);
    if (!files.length) return;

    const attachBtn = document.getElementById('btn-attach-image');
    attachBtn.disabled = true;
    let failed = 0;

    for (let i = 0; i < files.length; i++) {
      syncBarSet(`Adding photo ${i + 1} of ${files.length}…`, i / files.length);
      try {
        const dataUrl = await fileToCompressedDataURL(files[i]);
        editorImages.push(dataUrl);
        renderEditorThumbs(); // show each photo as soon as it's ready, not all at once at the end
        onEditorContentChanged();
      } catch (err) {
        failed++;
      }
      syncBarSet(`Adding photo ${i + 1} of ${files.length}…`, (i + 1) / files.length);
    }

    syncBarHideSoon(700);
    attachBtn.disabled = false;
    e.target.value = '';

    if (failed) {
      toast(failed === 1 ? 'Couldn\u2019t read one of those photos' : `Couldn\u2019t read ${failed} of those photos`);
    }
    if (estimateContentBytes() > NOTE_SIZE_LIMIT) {
      toast('This note is now over the 25MB limit — remove a photo or it won\u2019t save.');
    }
  });

  document.getElementById('btn-open-lock-chooser').addEventListener('click', openLockChooser);

  document.getElementById('choice-quick').addEventListener('click', () => {
    document.getElementById('choice-quick').classList.add('selected');
    document.getElementById('choice-time').classList.remove('selected');
    document.getElementById('quick-lock-fields').style.display = '';
    document.getElementById('time-lock-fields').style.display = 'none';
  });
  document.getElementById('choice-time').addEventListener('click', () => {
    document.getElementById('choice-time').classList.add('selected');
    document.getElementById('choice-quick').classList.remove('selected');
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
    if (unlockAt <= Date.now()) { err.textContent = 'Pick a time in the future.'; err.classList.remove('visually-hidden'); return; }
    pendingLock = { type: 'time', password: pw, unlockAt, existing: false };
    hide('overlay-lock-chooser');
    renderLockSummary();
    onEditorContentChanged();
  });

  document.getElementById('btn-remove-lock').addEventListener('click', () => {
    pendingLock = null;
    renderLockSummary();
    onEditorContentChanged();
  });
}

/* ---------------------------------------------------------------------
 * Init
 * ------------------------------------------------------------------- */

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
    openEditorWithContent(meta, { title: draft.title, body: draft.body, images: draft.images || [] });
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
  document.getElementById('version-badge').textContent = 'v' + (window.KEEPSAKE_VERSION || '1.2.0');

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
