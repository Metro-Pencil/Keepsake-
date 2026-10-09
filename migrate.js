/* Keepsake — migrate.js  (v1.7.0 ONLY)
 * One-time transfer of everything saved in the old Cloudflare setup into your Backblaze bucket.
 *
 * This is the only file in the app that knows Cloudflare ever existed, and nothing else depends
 * on it. Once your notes are across, delete this file, delete its <script> line in index.html
 * and its entries in sw.js and app.js (FORCE_REFRESH_SHELL_FILES), and no trace is left.
 *
 * It only READS from the old address (a GET for each note) and WRITES to your bucket. It never
 * changes or deletes anything on the old side, and it is safe to run again: a note already in
 * the bucket at the same version or newer is skipped.
 */
(function (root) {
  'use strict';

  const OLD_URL_KEY = 'ks_apiBase';
  const OLD_TOKEN_KEY = 'ks_token';
  const NAME_RE = /^[a-f0-9]{32}$/;
  const enc = new TextEncoder();

  function ls(k) { try { return root.localStorage.getItem(k) || ''; } catch (e) { return ''; } }
  function lsDel(k) { try { root.localStorage.removeItem(k); } catch (e) { /* private mode */ } }
  function el(tag, attrs, text) {
    const n = root.document.createElement(tag);
    for (const k of Object.keys(attrs || {})) n.setAttribute(k, attrs[k]);
    if (text) n.textContent = text;
    return n;
  }

  /* ----------------------------------------------------------------- reading the old side */

  function oldClient(base, token) {
    const b = base.trim().replace(/\/+$/, '');
    async function get(path) {
      let res;
      try { res = await root.fetch(b + path, { headers: { Authorization: 'Bearer ' + token.trim() } }); }
      catch (e) { throw new Error('Couldn\u2019t reach ' + b + ' \u2014 check the address and your connection.'); }
      if (res.status === 401) throw new Error('The old address rejected the access token.');
      if (!res.ok) throw new Error('The old address answered ' + res.status + ' for ' + path + '.');
      return res;
    }
    return {
      async listNotes() { return (await (await get('/api/notes')).json()).notes || []; },
      async exportNote(id) { return (await get('/api/notes/' + id + '/export')).json(); },
      async media(id, name) { return new Uint8Array(await (await get('/api/media/' + id + '/' + name)).arrayBuffer()); },
    };
  }

  /* ------------------------------------------------------------------- copying one note */

  async function copyNote(old, meta, log) {
    const id = meta.id;
    const B = root.KSB2;

    // Already there at this version or newer? Leave it alone.
    const existing = await B.getBytesOrNull('meta/' + id + '.json');
    if (existing) {
      try {
        const m = JSON.parse(new TextDecoder().decode(existing));
        if (m && (m.updatedAt || 0) >= (meta.updatedAt || 0)) return 'skipped';
      } catch (e) { /* unreadable: overwrite it */ }
    }

    const bundle = await old.exportNote(id);
    const content = bundle.content;
    if (content === undefined || content === null) throw new Error('has no content');

    // Photos/audio that the old side kept in a bucket of its own: bring each file across.
    const manifest = content && typeof content === 'object' ? content.media : null;
    if (manifest && typeof manifest === 'object') {
      for (const name of Object.keys(manifest)) {
        if (!NAME_RE.test(name)) continue;
        const bytes = await old.media(id, name);
        await B.putBytes(B.mediaKey(id, name), bytes, await B.sha256Hex(bytes));
      }
    }

    const contentJSON = JSON.stringify(content);
    const contentBytes = enc.encode(contentJSON);
    const contentSha = await B.sha256Hex(contentBytes);
    await B.putBytes('content/' + id + '.json', contentBytes, contentSha);

    const password2 = bundle.password2;
    if (meta.lockType === 'time' && typeof password2 === 'string' && password2) {
      await B.putText('vault/' + id + '.txt', password2);
    }

    // Verify before the note becomes visible: read the content back and compare.
    const back = await B.getBytes('content/' + id + '.json');
    if (await B.sha256Hex(back) !== contentSha) throw new Error('did not read back identically');

    // Meta last, so a note never appears in the list without its content.
    const newMeta = { ...meta, size: contentJSON.length };
    await B.putText('meta/' + id + '.json', JSON.stringify(newMeta));
    return 'copied';
  }

  /* ------------------------------------------------------------------------------- UI */

  function mount() {
    const slot = root.document.getElementById('migrate-slot');
    if (!slot) return;

    const section = el('section', { class: 'settings-section', 'aria-labelledby': 'migrate-heading' });
    section.appendChild(el('h3', { id: 'migrate-heading' }, 'Move notes from Cloudflare'));
    section.appendChild(el('p', { class: 'hint' },
      'One time, this version only. Copies every note (and any photos or audio) from your old Cloudflare address into the Backblaze bucket above. Nothing is changed or deleted on the old side, and you can run it again safely.'));

    const urlField = el('div', { class: 'field' });
    urlField.appendChild(el('label', { for: 'migrate-url' }, 'Old Worker address'));
    const url = el('input', { type: 'url', id: 'migrate-url', placeholder: 'https://keepsake-worker.you.workers.dev', autocomplete: 'off' });
    urlField.appendChild(url);
    const tokenField = el('div', { class: 'field' });
    tokenField.appendChild(el('label', { for: 'migrate-token' }, 'Old access token'));
    const token = el('input', { type: 'password', id: 'migrate-token', autocomplete: 'off' });
    tokenField.appendChild(token);
    const go = el('button', { class: 'btn btn-ghost', id: 'btn-migrate', type: 'button' }, 'Copy everything to Backblaze');
    const status = el('p', { class: 'hint', id: 'migrate-status', role: 'status', 'aria-live': 'polite' });
    status.style.whiteSpace = 'pre-line';
    status.hidden = true;
    const forget = el('button', { class: 'btn btn-ghost', id: 'btn-migrate-forget', type: 'button' }, 'Forget the old address and token on this device');
    forget.hidden = true;

    section.append(urlField, tokenField, go, status, forget);
    slot.appendChild(section);

    // Prefill from what this device used before.
    url.value = ls(OLD_URL_KEY);
    token.value = ls(OLD_TOKEN_KEY);

    function say(text) { status.hidden = !text; status.textContent = text; }

    go.addEventListener('click', async () => {
      if (!root.KSB2 || !root.KSB2.config.configured()) {
        say('Fill in the Backblaze details above and tap \u201cSave and test\u201d first.');
        return;
      }
      if (!url.value.trim() || !token.value.trim()) { say('Enter the old Worker address and its access token.'); return; }
      go.disabled = true;
      forget.hidden = true;
      const failed = [];
      let copied = 0;
      let skipped = 0;
      try {
        const old = oldClient(url.value, token.value);
        say('Reading the list of notes\u2026');
        const notes = await old.listNotes();
        if (!notes.length) { say('The old address has no notes.'); return; }
        for (let i = 0; i < notes.length; i++) {
          const meta = notes[i];
          const label = (meta.title || 'Untitled').slice(0, 40);
          say('Copying ' + (i + 1) + ' of ' + notes.length + ': ' + label + '\u2026');
          try {
            const r = await copyNote(old, meta, say);
            if (r === 'copied') copied++; else skipped++;
          } catch (e) {
            failed.push(label + ' \u2014 ' + (e && e.message ? e.message : 'failed'));
          }
        }
        let text = 'Done. ' + copied + ' copied' + (skipped ? ', ' + skipped + ' already in the bucket' : '') + (failed.length ? ', ' + failed.length + ' failed' : '') + '.';
        if (failed.length) text += '\nCouldn\u2019t copy:\n' + failed.join('\n') + '\nRun it again to retry just those.';
        else if (copied) text += '\nEvery note was read back from the bucket and checked. Open a few to be sure, then you can forget the old details below.';
        else text += '\nNothing new to copy \u2014 everything is already in the bucket.';
        say(text);
        if (!failed.length) forget.hidden = false;
        if (copied && typeof root.refreshNotes === 'function') root.refreshNotes();
      } catch (e) {
        say(e && e.message ? e.message : 'Something went wrong.');
      } finally {
        go.disabled = false;
      }
    });

    forget.addEventListener('click', () => {
      lsDel(OLD_URL_KEY);
      lsDel(OLD_TOKEN_KEY);
      url.value = '';
      token.value = '';
      forget.hidden = true;
      say('The old address and token are gone from this device.');
    });
  }

  if (root.document.readyState === 'loading') root.document.addEventListener('DOMContentLoaded', mount);
  else mount();

  root.KSMigrate = { _test: { copyNote, oldClient } };
})(typeof window !== 'undefined' ? window : globalThis);
