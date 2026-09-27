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
  createNote(payload, onProgress) { return this.requestWithProgress('/api/notes', 'POST', payload, onProgress); },
  updateNote(id, payload, onProgress) { return this.requestWithProgress('/api/notes/' + id, 'PUT', payload, onProgress); },
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
  for (const src of editorImages) total += src.length * 0.75; // base64 -> raw bytes, roughly
  return total;
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

function show(id) { document.getElementById(id).classList.remove('hidden'); }
function hide(id) { document.getElementById(id).classList.add('hidden'); }

function setEditorProgress(label, fraction) {
  document.getElementById('editor-progress').classList.remove('hidden');
  document.getElementById('editor-progress-label').textContent = label;
  document.getElementById('editor-progress-fill').style.width =
    (Math.max(0, Math.min(1, fraction)) * 100) + '%';
}
function hideEditorProgress() {
  document.getElementById('editor-progress').classList.add('hidden');
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
let editingNoteId = null;
let editorImages = [];
let editorSnapshot = '';         // JSON snapshot taken when the editor opens, to detect unsaved changes
let saveInFlight = false;        // guards against double-submitting (e.g. a fast double-tap on Save)
let pendingLock = null;          // { type: 'quick'|'time', password?, password2?, unlockAt?, existing? }
let currentUnlockCreds = null;   // { password, password2? } — kept only for this editing session

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
      <img src="${src}" alt="">
      <button class="thumb-remove" data-idx="${i}" aria-label="Remove image">×</button>
    </div>`).join('');
  wrap.querySelectorAll('.thumb-remove').forEach((btn) => {
    btn.addEventListener('click', () => {
      editorImages.splice(Number(btn.dataset.idx), 1);
      renderEditorThumbs();
    });
  });
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

function editorHasUnsavedChanges() {
  return computeEditorSnapshot() !== editorSnapshot;
}

function openEditorWithContent(meta, content) {
  editingNoteId = meta && meta.id ? meta.id : null;
  document.getElementById('editor-heading').textContent = editingNoteId ? 'Edit note' : 'New note';
  document.getElementById('editor-title').value = content.title || '';
  document.getElementById('editor-body').value = content.body || '';
  editorImages = (content.images || []).slice();
  renderEditorThumbs();
  hideEditorProgress();
  document.getElementById('btn-delete-note').style.display = editingNoteId ? '' : 'none';

  pendingLock = (meta && meta.lockType && meta.lockType !== 'none')
    ? { type: meta.lockType, unlockAt: meta.unlockAt, existing: true }
    : null;
  renderLockSummary();
  editorSnapshot = computeEditorSnapshot();
  show('overlay-editor');
  document.getElementById('editor-title').focus();
}

function attemptCloseEditor() {
  if (editorHasUnsavedChanges()) {
    openConfirm(
      'Discard this note?',
      'Your changes haven\u2019t been saved.',
      async () => { hide('overlay-editor'); },
      'Discard'
    );
  } else {
    hide('overlay-editor');
  }
}

async function saveNote() {
  if (saveInFlight) return; // already saving — ignore a fast double-tap on Save
  const title = document.getElementById('editor-title').value.trim();
  const body = document.getElementById('editor-body').value;
  if (!title && !body && editorImages.length === 0) { toast('Nothing to save'); return; }

  if (estimateContentBytes() > NOTE_SIZE_LIMIT) {
    toast('This note is over the 25MB limit — remove a photo before saving.');
    return;
  }

  saveInFlight = true;
  const saveBtn = document.getElementById('btn-save-note');
  const originalLabel = saveBtn.textContent;
  saveBtn.disabled = true;
  saveBtn.textContent = 'Saving…';

  const content = { title, body, images: editorImages };
  let payload;

  try {
    if (!pendingLock || pendingLock.type === 'none') {
      payload = { lockType: 'none', title, preview: makePreview(body), content };
    } else if (pendingLock.type === 'quick') {
      const password = pendingLock.password || (currentUnlockCreds && currentUnlockCreds.password);
      if (!password) throw new Error('missing password for quick lock');
      const record = await encryptNote(password, content);
      payload = { lockType: 'quick', content: record };
    } else if (pendingLock.type === 'time') {
      const password = pendingLock.password || (currentUnlockCreds && currentUnlockCreds.password);
      let password2 = pendingLock.password2 || (currentUnlockCreds && currentUnlockCreds.password2);
      if (!password) throw new Error('missing password for time lock');
      if (!password2) password2 = generateSecondPassword();
      const record = await encryptNote(combine(password, password2), content);
      payload = { lockType: 'time', unlockAt: pendingLock.unlockAt, password2, content: record };
    }
  } catch (e) {
    toast('Could not lock note — try setting the lock again.');
    saveInFlight = false;
    saveBtn.disabled = false;
    saveBtn.textContent = originalLabel;
    return;
  }

  const hasImages = editorImages.length > 0;
  const onProgress = hasImages
    ? (fraction) => setEditorProgress(`Uploading photos… ${Math.round(fraction * 100)}%`, fraction)
    : null;
  if (hasImages) setEditorProgress('Uploading photos… 0%', 0);

  try {
    if (editingNoteId) {
      await API.updateNote(editingNoteId, payload, onProgress);
    } else {
      await API.createNote(payload, onProgress);
    }
    toast('Saved');
    hide('overlay-editor');
    currentUnlockCreds = null;
    await refreshNotes();
  } catch (e) {
    toast('Could not save: ' + e.message);
  } finally {
    saveInFlight = false;
    saveBtn.disabled = false;
    saveBtn.textContent = originalLabel;
    hideEditorProgress();
  }
}

function confirmDelete(id, fromEditor) {
  openConfirm('Delete this note?', 'This can\u2019t be undone.', async () => {
    try {
      await API.deleteNote(id);
      toast('Deleted');
      if (fromEditor) hide('overlay-editor');
      await refreshNotes();
    } catch (e) {
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
        <p class="hint">Found inside this note's downloaded file. Use the download button on its card if you need to fetch it again.</p>
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
  document.getElementById('settings-version').textContent = window.KEEPSAKE_VERSION || '1.0.4';
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
      setEditorProgress(`Adding photo ${i + 1} of ${files.length}…`, i / files.length);
      try {
        const dataUrl = await fileToCompressedDataURL(files[i]);
        editorImages.push(dataUrl);
        renderEditorThumbs(); // show each photo as soon as it's ready, not all at once at the end
      } catch (err) {
        failed++;
      }
      setEditorProgress(`Adding photo ${i + 1} of ${files.length}…`, (i + 1) / files.length);
    }

    hideEditorProgress();
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
  });

  document.getElementById('btn-remove-lock').addEventListener('click', () => {
    pendingLock = null;
    renderLockSummary();
  });
}

/* ---------------------------------------------------------------------
 * Init
 * ------------------------------------------------------------------- */

function init() {
  wireStaticEvents();
  document.getElementById('version-badge').textContent = 'v' + (window.KEEPSAKE_VERSION || '1.0.4');

  if (!Config.configured()) {
    openSettings();
    toast('Add your Worker URL and access token to get started');
  } else {
    refreshNotes();
  }

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(() => { /* offline shell is a nice-to-have */ });
  }
}

document.addEventListener('DOMContentLoaded', init);
