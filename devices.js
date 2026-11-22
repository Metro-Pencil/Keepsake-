/* ---------------------------------------------------------------------------
 * devices.js - who is signed in to this notebook, and who is allowed to be.
 *
 * Every browser/install makes its own key pair the first time it connects (RSA-OAEP; the private half is
 * stored non-extractable in IndexedDB, so it can't be read back out). That key is the device's identity.
 * Every time the app opens or connects, the device writes a login entry (time, browser, system, screen,
 * language, time zone, network, installed-or-tab, app version...) into the bucket under devices/.
 *
 * The MASTER account is one password kept in the bucket. Behind it is an ECDSA P-256 key pair: the public
 * half sits in devices/_master.json, the private half sits next to it encrypted with the password
 * (PBKDF2-SHA256 -> AES-256-GCM). Any device can log in as master with that password alone, and log out
 * again. While logged in a device sees every device and every login, and can Sign out (once), Block (until
 * allowed again), Allow and Forget devices, change the password, or replace the master key. Every command
 * is signed with the master key; devices check the signature, so an ordinary device cannot block anyone.
 * If no master account exists the app offers to create one; if one exists it never creates another.
 * (The password is stored where anyone holding the bucket key can read it, by choice: it is guarded by a slow
 * hash, not hidden.)
 * Replacing the master key makes a new pair, so every device that was logged in loses its master login.
 *
 * A master also chooses, per device, whether it may open normal notes and whether it may open locked notes
 * (signed the same way, in the device's inbox). A device that is not a master opens normal notes and opens
 * locked notes only once a master has switched them on for it; a device that is switched off for a type does
 * not show it, does not download it and forgets what it held. Nothing is held back while the bucket has no
 * master account (nobody could switch anything on), and a master device always opens everything.
 *
 * Honest limit: there is no server. Every device already holds the Backblaze application key, and this is
 * checked by the app itself. It stops this app on a device that obeys it. It cannot stop someone who copies
 * the Backblaze key out and uses it with other software - for that, make a new key in Backblaze.
 * ------------------------------------------------------------------------- */
(function (root) {
  'use strict';

  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const ID_RE = /^[0-9a-f]{32}$/;
  const POLL_MS = 120000;     // how often an open app asks whether it is still allowed
  const DEDUPE_MS = 120000;   // a plain reload inside this window is not logged again
  const LOG_CAP = 1000;       // entries kept per device per month
  const START_TIMEOUT_MS = 4000;
  const PW_ITER = 600000;     // PBKDF2 rounds for the master password
  const PW_MIN = 12;          // shortest master passphrase (wrapped key is readable offline)
  const SNOOZE_MS = 7 * 24 * 3600 * 1000;   // "Not now" on the create-master offer is remembered this long
  let raceMs = 1500;          // two devices creating the master at once: verify twice with this gap
  const LS = { state: 'ks_dev_state', failed: 'ks_dev_failed', lastlog: 'ks_dev_lastlog' };

  const K = {
    master: 'devices/_master.json',
    rec: (id) => 'devices/' + id + '.json',
    inbox: (id) => 'devices/' + id + '.inbox.json',
    log: (id, ym) => 'devices/' + id + '.log-' + ym + '.json',
  };

  /* ------------------------------------------------------------ small helpers */

  const bucket = () => root.KSB2;
  const now = () => Date.now();
  function lsGet(k) { try { return root.localStorage.getItem(k) || ''; } catch (e) { return ''; } }
  function lsSet(k, v) { try { root.localStorage.setItem(k, v); } catch (e) { /* private mode */ } }
  function lsJson(k, d) { try { return JSON.parse(lsGet(k)) || d; } catch (e) { return d; } }
  const getState = () => lsJson(LS.state, {});
  // Tells the rest of the app (the offline sync) that this device became, or stopped being, a master.
  const masterChanged = () => { try { root.dispatchEvent(new root.CustomEvent('ks-master-changed')); } catch (e) { /* UI only */ } };
  const setState = (s) => lsSet(LS.state, JSON.stringify(s));
  const patchState = (p) => { const s = { ...getState(), ...p }; setState(s); return s; };

  function b64(bytes) {
    const u = new Uint8Array(bytes);
    let s = '';
    for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
    return btoa(s);
  }
  function unb64(s) { const bin = atob(s); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; }
  const b64url = (bytes) => b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const unb64url = (s) => unb64(String(s).replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((String(s).length + 3) % 4));
  function randomId() { return Array.from(root.crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join(''); }
  const shortId = (id) => (id || '').slice(0, 8).toUpperCase().replace(/(.{4})/, '$1-');
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmt = (ts) => (ts ? new Date(ts).toLocaleString(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }) : '');
  const ym = (ts) => { const d = new Date(ts); return d.getUTCFullYear() + '-' + String(d.getUTCMonth() + 1).padStart(2, '0'); };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const plural = (n, one, many) => n + ' ' + (n === 1 ? one : many);

  /* ------------------------------------------------- device-local storage (IndexedDB) */

  let kv = null;
  function idbKV() {
    let dbp = null;
    const db = () => dbp || (dbp = new Promise((res, rej) => {
      const r = root.indexedDB.open('keepsake-device', 1);
      r.onupgradeneeded = () => { if (!r.result.objectStoreNames.contains('kv')) r.result.createObjectStore('kv'); };
      r.onsuccess = () => {
        const conn = r.result;
        conn.onversionchange = () => { conn.close(); dbp = null; };
        conn.onclose = () => { dbp = null; };
        res(conn);
      };
      r.onerror = () => { dbp = null; rej(r.error); };
    }));
    const run = async (mode, fn) => {
      const d = await db();
      return new Promise((res, rej) => {
        const tx = d.transaction('kv', mode);
        const out = fn(tx.objectStore('kv'));
        tx.oncomplete = () => res(out && out.result !== undefined ? out.result : undefined);
        tx.onerror = () => rej(tx.error);
        tx.onabort = () => rej(tx.error);
      });
    };
    return {
      get: async (k) => { const v = await run('readonly', (s) => s.get(k)); return v === undefined ? null : v; },
      set: (k, v) => run('readwrite', (s) => s.put(v, k)),
      del: (k) => run('readwrite', (s) => s.delete(k)),
    };
  }
  const store = () => kv || (kv = idbKV());

  /* ------------------------------------------------------------------- crypto */

  const RSA = { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' };
  const EC = { name: 'ECDSA', namedCurve: 'P-256' };
  const SIG = { name: 'ECDSA', hash: 'SHA-256' };
  const subtle = () => root.crypto.subtle;

  async function sign(privateKey, text) { return b64(await subtle().sign(SIG, privateKey, enc.encode(text))); }
  const verifyCache = new Map();
  async function verify(pubJwk, text, sigB64) {
    try {
      const k = JSON.stringify(pubJwk);
      if (!verifyCache.has(k)) verifyCache.set(k, await subtle().importKey('jwk', pubJwk, EC, false, ['verify']));
      return await subtle().verify(SIG, verifyCache.get(k), unb64(sigB64), enc.encode(text));
    } catch (e) { return false; }
  }
  const cmdText = (c) => (c && c.v >= 2
    ? ['ks-cmd', 2, c.id, c.action, c.wipe ? 1 : 0, c.at, c.by || '', c.byName || '', c.note || ''].join('\u241f')
    : ['ks-cmd', 1, c.id, c.action, c.wipe ? 1 : 0, c.at].join('|'));
  const claimText = (id, at) => (at ? 'ks-master|2|' + id + '|' + at : 'ks-master|1|' + id);
  async function proofValid(pub, id, rec) {
    if (!pub || !rec || !rec.masterProof) return false;
    if (rec.masterProofAt) return verify(pub, claimText(id, rec.masterProofAt), rec.masterProof);
    return verify(pub, claimText(id), rec.masterProof);
  }
  // What a device may open is set by the master the same way: one signed record per device, checked by the device.
  const policyText = (p) => ['ks-policy', 1, p.id, p.notes ? 1 : 0, p.locked ? 1 : 0, p.at].join('|');
  async function policyValid(pub, p) {
    const t = policyText(p);
    return (await verify(pub, t, p.sig)) || (!!p.sig2 && await verify(pub, t, p.sig2));
  }
  // A command is good if the current master key signed it. While the master key is being replaced a command
  // also carries a second signature (sig2) from the new key, so blocks never lapse in between.
  async function cmdValid(pub, c) {
    const t = cmdText(c);
    return (await verify(pub, t, c.sig)) || (!!c.sig2 && await verify(pub, t, c.sig2));
  }

  /* ------------------------------------------------- the master password */

  const hasPassword = (m) => !!(m && m.wrapped && m.wrapped.ct);
  function checkPassword(p) {
    if (typeof p !== 'string' || p.length < PW_MIN) throw new Error('The password needs at least ' + PW_MIN + ' characters.');
    return p;
  }
  async function pwKey(password, salt, iter) {
    const base = await subtle().importKey('raw', enc.encode(String(password).normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
    return subtle().deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  // The private master key (must be extractable) encrypted under a password.
  async function wrapWithPassword(privateKey, password) {
    const salt = root.crypto.getRandomValues(new Uint8Array(16));
    const iv = root.crypto.getRandomValues(new Uint8Array(12));
    const raw = await subtle().exportKey('pkcs8', privateKey);
    const ct = await subtle().encrypt({ name: 'AES-GCM', iv }, await pwKey(password, salt, PW_ITER), raw);
    return { alg: 'PBKDF2-SHA256/AES-256-GCM', iter: PW_ITER, salt: b64(salt), iv: b64(iv), ct: b64(ct) };
  }
  // The master key back out. A wrong password makes AES-GCM fail, which is how the password is checked.
  async function unwrapWithPassword(wrapped, password, extractable) {
    let raw;
    try {
      const k = await pwKey(password, unb64(wrapped.salt), wrapped.iter || PW_ITER);
      raw = await subtle().decrypt({ name: 'AES-GCM', iv: unb64(wrapped.iv) }, k, unb64(wrapped.ct));
    } catch (e) { throw new Error('That password is not right.'); }
    return subtle().importKey('pkcs8', raw, EC, !!extractable, ['sign']);
  }

  async function makeMasterPair() {
    const pair = await subtle().generateKey(EC, true, ['sign', 'verify']);
    return { privateKey: pair.privateKey, pub: await subtle().exportKey('jwk', pair.publicKey) };
  }

  async function toNonExtractable(privateKey) {
    const raw = await subtle().exportKey('pkcs8', privateKey);
    return subtle().importKey('pkcs8', raw, EC, false, ['sign']);
  }

  // Does this private key really belong to the bucket's master public key?
  async function keyMatches(privateKey, pubJwk) {
    try { return await verify(pubJwk, 'ks-check', await sign(privateKey, 'ks-check')); } catch (e) { return false; }
  }

  // The master key as text a person can keep: KSM1. + the PKCS8 private key.
  async function exportMasterText(privateKey) { return 'KSM1.' + b64url(await subtle().exportKey('pkcs8', privateKey)); }
  async function importMasterText(text) {
    const m = /^KSM1\.([A-Za-z0-9_-]+)$/.exec(String(text || '').replace(/\s+/g, ''));
    if (!m) throw new Error('That is not a Keepsake master key. It starts with KSM1.');
    return subtle().importKey('pkcs8', unb64url(m[1]), EC, true, ['sign']);
  }

  /* ------------------------------------------------------ what this device is */

  async function highEntropy() {
    const d = root.navigator && root.navigator.userAgentData;
    if (!d || !d.getHighEntropyValues) return {};
    try { return await d.getHighEntropyValues(['model', 'platformVersion', 'architecture', 'fullVersionList']); } catch (e) { return {}; }
  }

  function parseAgent(ua, hi, uad) {
    ua = ua || '';
    let browser = 'Browser', ver = '';
    let m;
    if ((m = /Edg(?:e|A|iOS)?\/([\d.]+)/.exec(ua))) { browser = 'Edge'; ver = m[1]; }
    else if ((m = /OPR\/([\d.]+)/.exec(ua))) { browser = 'Opera'; ver = m[1]; }
    else if ((m = /SamsungBrowser\/([\d.]+)/.exec(ua))) { browser = 'Samsung Internet'; ver = m[1]; }
    else if ((m = /(?:Firefox|FxiOS)\/([\d.]+)/.exec(ua))) { browser = 'Firefox'; ver = m[1]; }
    else if ((m = /(?:Chrome|CriOS)\/([\d.]+)/.exec(ua))) { browser = 'Chrome'; ver = m[1]; }
    else if ((m = /Version\/([\d.]+).*Safari/.exec(ua))) { browser = 'Safari'; ver = m[1]; }
    let os = 'Unknown system', osVer = '';
    if ((m = /Android ([\d.]+)/.exec(ua))) { os = 'Android'; osVer = m[1]; }
    else if ((m = /(?:iPhone|CPU) OS ([\d_]+)/.exec(ua)) && /iPhone|iPad/.test(ua)) { os = /iPad/.test(ua) ? 'iPadOS' : 'iOS'; osVer = m[1].replace(/_/g, '.'); }
    else if (/Windows NT/.test(ua)) { os = 'Windows'; }
    else if (/CrOS/.test(ua)) { os = 'ChromeOS'; }
    else if (/Mac OS X/.test(ua)) { os = 'macOS'; }
    else if (/Linux/.test(ua)) { os = 'Linux'; }
    if (hi && hi.platformVersion) {
      if (os === 'Windows') {
        const winMajor = parseInt(hi.platformVersion, 10);
        if (winMajor >= 13) osVer = '11';
        else if (winMajor >= 1) osVer = '10';
      }
      else if (os === 'macOS' || os === 'Android') osVer = hi.platformVersion;
    }
    const model = (hi && hi.model) || '';
    const mobile = (uad && typeof uad.mobile === 'boolean') ? uad.mobile : /Android|iPhone|iPad|Mobile/i.test(ua);
    return { browser, browserVersion: ver.split('.')[0], os, osVersion: osVer.split('.').slice(0, 2).join('.'), model, mobile };
  }

  function summarize(env) {
    const parts = [env.browser + (env.browserVersion ? ' ' + env.browserVersion : ''), env.os + (env.osVersion ? ' ' + env.osVersion : '')];
    if (env.model) parts.push(env.model);
    return parts.join(' \u00b7 ');
  }

  async function collectEnv() {
    const n = root.navigator || {};
    const hi = await highEntropy();
    const a = parseAgent(n.userAgent, hi, n.userAgentData);
    const conn = n.connection || {};
    const installed = !!((root.matchMedia && root.matchMedia('(display-mode: standalone)').matches) || n.standalone);
    let tz = '';
    try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) { /* ignore */ }
    const scr = root.screen || {};
    const env = {
      ...a,
      userAgent: n.userAgent || '',
      architecture: hi.architecture || '',
      display: installed ? 'installed app' : 'browser tab',
      screen: scr.width ? scr.width + '\u00d7' + scr.height + ' @' + (root.devicePixelRatio || 1) + 'x' : '',
      language: (n.languages && n.languages.length ? Array.from(n.languages).join(', ') : n.language) || '',
      timeZone: tz,
      utcOffsetMin: -new Date().getTimezoneOffset(),
      cores: n.hardwareConcurrency || null,
      memoryGB: n.deviceMemory || null,
      touchPoints: n.maxTouchPoints || 0,
      network: conn.effectiveType || '',
      saveData: !!conn.saveData,
      online: n.onLine !== false,
      origin: root.location ? root.location.origin : '',
      appVersion: root.KEEPSAKE_VERSION || '',
    };
    env.summary = summarize(env);
    return env;
  }

  /* ---------------------------------------------------------- bucket records */

  async function readJson(key) {
    const bytes = await bucket().getBytesOrNull(key);
    if (!bytes) return null;
    try { return JSON.parse(dec.decode(bytes)); } catch (e) { return null; }
  }
  async function readJsonStrict(key) {
    const bytes = await bucket().getBytesOrNull(key);
    if (!bytes) return null;
    try { return JSON.parse(dec.decode(bytes)); }
    catch (e) { throw new Error('Bucket record ' + key + ' is corrupted; refusing to overwrite it.'); }
  }
  const writeJson = (key, obj) => bucket().putText(key, JSON.stringify(obj));

  async function readMaster() { const m = await readJson(K.master); return m && m.pub && m.pub.kty ? m : null; }
  const masterExists = async () => !!(await bucket().getBytesOrNull(K.master));
  const readInbox = (id) => readJson(K.inbox(id));
  const readInboxStrict = (id) => readJsonStrict(K.inbox(id));
  const readRecord = (id) => readJson(K.rec(id));

  // The inbox holds what the master has told this device: a command (block / sign out / allow) and, since 1.15,
  // the access policy (may it open normal notes, may it open locked notes).
  async function saveInbox(id, inbox) {
    const out = {};
    if (inbox && inbox.cmd) out.cmd = inbox.cmd;
    if (inbox && inbox.policy) out.policy = inbox.policy;
    if (out.cmd || out.policy) await writeJson(K.inbox(id), out);      // (1.12 also kept promotion grants here; they are gone)
    else await bucket().deleteObject(K.inbox(id));
  }

  async function appendLog(id, entries) {
    if (!entries || !entries.length) return;
    const byMonth = new Map();
    for (const e of entries) {
      const m = ym(e.t);
      if (!byMonth.has(m)) byMonth.set(m, []);
      byMonth.get(m).push(e);
    }
    for (const [m, monthEntries] of byMonth) {
      const key = K.log(id, m);
      const bytes = await bucket().getBytesOrNull(key);
      let old = [];
      if (bytes) {
        let parsed;
        try { parsed = JSON.parse(dec.decode(bytes)); }
        catch (e) { throw new Error('Device activity log is corrupted; refusing to overwrite it.'); }
        if (!Array.isArray(parsed)) throw new Error('Device activity log has an unexpected format; refusing to overwrite it.');
        old = parsed;
      }
      await writeJson(key, monthEntries.concat(old).slice(0, LOG_CAP));
    }
  }

  /* ---------------------------------------------------------------- identity */

  let identityPromise = null;
  async function getIdentity(create) {
    let me = await store().get('identity');
    if (me || !create) return me;
    if (identityPromise) return identityPromise;
    const createOnce = async () => {
      const existing = await store().get('identity');
      if (existing) return existing;
      const pair = await subtle().generateKey(RSA, false, ['encrypt', 'decrypt']);
      const env = await collectEnv();
      const created = {
        id: randomId(), createdAt: now(),
        name: env.browser + ' on ' + env.os + (env.model ? ' (' + env.model + ')' : ''),
        privateKey: pair.privateKey, publicJwk: await subtle().exportKey('jwk', pair.publicKey),
      };
      await store().set('identity', created);
      return created;
    };
    const locks = root.navigator && root.navigator.locks;
    identityPromise = (locks && typeof locks.request === 'function'
      ? locks.request('ks-device-identity', createOnce)
      : createOnce()
    ).finally(() => { identityPromise = null; });
    return identityPromise;
  }

  // The master key this device holds, only if it still matches the bucket's master.
  async function myMasterKey(master) {
    if (!master) return null;
    const saved = await store().get('master');
    if (saved && saved.privateKey && await keyMatches(saved.privateKey, master.pub)) return saved.privateKey;
    return null;
  }

  // This device is now a master: keep the key, say so in its record, and log it. Nothing here may undo the login.
  async function startSession(me, master, key, detail) {
    await store().set('master', { privateKey: key, savedAt: now() });
    patchState({ masterSession: true });
    masterChanged();
    try {
      const env = await collectEnv();
      await writeRecord(me, env, master, key, {});
      await appendLog(me.id, [entry(env, 'master', detail)]);
    } catch (e) { /* the next check-in writes the record again */ }
  }

  // Make the master account. Only when the bucket has none: with one already there, this refuses.
  async function createMaster(password) {
    checkPassword(password);
    const me = await getIdentity(true);
    if (await masterExists()) throw new Error('A master account already exists for this bucket. Log in to it instead.');
    const pair = await makeMasterPair();
    const wrapped = await wrapWithPassword(pair.privateKey, password);
    if (await masterExists()) throw new Error('A master account already exists for this bucket. Log in to it instead.');
    const nonce = randomId();
    await writeJson(K.master, { v: 2, pub: pair.pub, wrapped, createdBy: me.id, nonce, createdAt: now(), changedAt: now(), gen: 1 });
    await sleep(raceMs);                               // two devices at once: verify twice with a wider gap
    const check1 = await readMaster();
    if (!check1 || check1.nonce !== nonce) throw new Error('Another device created the master account at the same moment. Log in to it with its password instead.');
    await sleep(raceMs);
    const check = await readMaster();
    if (!check || check.nonce !== nonce) throw new Error('Another device created the master account at the same moment. Log in to it with its password instead.');
    await startSession(me, check, await toNonExtractable(pair.privateKey), 'created the master account');
    return check;
  }

  // Log in as master from this device with the password alone.
  async function loginMaster(password) {
    const me = await getIdentity(true);
    const master = await readMaster();
    if (!master) throw new Error('There is no master account yet.');
    if (!hasPassword(master)) throw new Error('This master account was made by an older version and has no password yet. On a device that is already a master, set one in Settings.');
    const key = await unwrapWithPassword(master.wrapped, password, false);
    if (!(await keyMatches(key, master.pub))) throw new Error('That password does not open this bucket’s master account.');
    await startSession(me, master, key, 'logged in as master');
  }

  // Leave master. The device goes back to being an ordinary one; the key is deleted from it.
  async function logoutMaster() {
    const me = await getIdentity(false);
    await store().del('master');
    patchState({ masterSession: false, access: { ...DEFAULT_ACCESS } });
    masterChanged();
    try { root.dispatchEvent(new root.CustomEvent('ks-access-changed', { detail: access() })); } catch (e) { /* UI only */ }
    if (!me) return;
    try {
      const env = await collectEnv();
      await writeRecord(me, env, await readMaster(), null, {});
      await appendLog(me.id, [entry(env, 'master', 'logged out of master')]);
    } catch (e) { /* offline: the record is corrected at the next check-in */ }
    await poll();                                     // an ordinary device again: pick up what the master allows it to open
  }

  async function changePassword(current, next) {
    checkPassword(next);
    const { master, me } = await needMaster();
    if (!hasPassword(master)) throw new Error('Set a master password first.');
    const key = await unwrapWithPassword(master.wrapped, current, true);
    const wrapped = await wrapWithPassword(key, next);
    const latest = await readMaster();
    if (!latest || latest.gen !== master.gen || JSON.stringify(latest.pub) !== JSON.stringify(master.pub)) {
      throw new Error('The master key was replaced on another device while changing the password. Log in again with the current master password.');
    }
    await writeJson(K.master, { ...latest, wrapped, changedAt: now() });
    try { const env = await collectEnv(); await appendLog(me.id, [entry(env, 'master', 'changed the master password')]); } catch (e) { /* log only */ }
  }

  // Make a new master key. Every device that was logged in as master loses that login (its old key no longer
  // matches), so a lost or stolen master phone can be cut off, then blocked. Blocks and sign-outs already
  // waiting are signed again so none of them lapses. The password stays the same unless a new one is given.
  async function replaceMasterKey(current, next) {
    const { master, me } = await needMaster();
    if (!hasPassword(master)) throw new Error('Set a master password first.');
    await unwrapWithPassword(master.wrapped, current, false);       // proves the password
    const password = next ? checkPassword(next) : current;
    const B = bucket();
    const pair = await makeMasterPair();
    const wrapped = await wrapWithPassword(pair.privateKey, password);
    const inboxKeys = (await B.listAll('devices/')).map((o) => o.key).filter((k) => /^devices\/[0-9a-f]{32}\.inbox\.json$/.test(k));
    const withCmd = [];
    for (const k of inboxKeys) {                                      // 1. ONLY commands & policies validly signed by the OLD master key get sig2
      const fm = /^devices\/([0-9a-f]{32})\.inbox\.json$/.exec(k);
      const fileId = fm ? fm[1] : '';
      const inbox = await readJson(k);
      let touched = false;
      if (inbox && inbox.cmd && inbox.cmd.id === fileId && await cmdValid(master.pub, inbox.cmd)) {
        inbox.cmd.sig2 = await sign(pair.privateKey, cmdText(inbox.cmd));
        touched = true;
      }
      if (inbox && inbox.policy && inbox.policy.id === fileId && await policyValid(master.pub, inbox.policy)) {
        inbox.policy.sig2 = await sign(pair.privateKey, policyText(inbox.policy));
        touched = true;
      }
      if (touched) { await writeJson(k, inbox); withCmd.push(k); }
    }
    const fresh = { ...master, v: 2, pub: pair.pub, wrapped, gen: (master.gen || 1) + 1, rotatedAt: now(), changedAt: next ? now() : master.changedAt };
    await writeJson(K.master, fresh);                                // 2. the new key takes over
    await startSession(me, fresh, await toNonExtractable(pair.privateKey), 'replaced the master key');
    for (const k of withCmd) {                                        // 3. tidy up: the new signature becomes the signature
      try {
        const inbox = await readJsonStrict(k);
        if (!inbox) continue;
        let touched = false;
        if (inbox.cmd && inbox.cmd.sig2) { inbox.cmd.sig = inbox.cmd.sig2; delete inbox.cmd.sig2; touched = true; }
        if (inbox.policy && inbox.policy.sig2) { inbox.policy.sig = inbox.policy.sig2; delete inbox.policy.sig2; touched = true; }
        if (touched) await writeJson(k, inbox);
      } catch (e) { /* best-effort tidy; sig2 remains valid */ }
    }
    return fresh;
  }

  // An account made by version 1.12 has a key but no password. A device that holds that key can add one;
  // the key itself does not change, so every command already given stays valid.
  async function setLegacyPassword(password) {
    checkPassword(password);
    const { master, key, me } = await needMaster();
    if (hasPassword(master)) throw new Error('This master account already has a password.');
    let wrapped;
    try { wrapped = await wrapWithPassword(key, password); } catch (e) { throw new Error('This device cannot read the old master key. Use the device where it was created, or paste the old key first.'); }
    const upgraded = { ...master, v: 2, wrapped, changedAt: now(), gen: master.gen || 1 };
    await writeJson(K.master, upgraded);
    await startSession(me, upgraded, await toNonExtractable(key), 'set the master password');
  }

  /* ------------------------------------------------------------ the verdict */

  // Is this device allowed in? Only a command signed by the master counts.
  async function judge(me, master, inbox) {
    const c = inbox && inbox.cmd;
    if (!c || !master) return { status: 'active' };
    if (c.id !== me.id || !(await cmdValid(master.pub, c))) return { status: 'active', forged: true };
    const st = getState();
    const lastCmdAt = Number(st.lastCmdAt) || 0;
    if (c.at < lastCmdAt) {
      if (st.lock) return { status: st.lock.kind, replayed: true, keepLock: true };
      return { status: 'active', replayed: true };
    }
    if (c.at > lastCmdAt) patchState({ lastCmdAt: c.at });
    if (c.action === 'block') return { status: 'blocked', cmd: c };
    if (c.action === 'terminate' && c.at !== st.handled) return { status: 'terminated', cmd: c };
    return { status: 'active', cmd: c };
  }

  /* ------------------------------------------------ what this device may open */

  // A device that is not a master opens normal notes, and opens locked notes only once a master has switched them on
  // for it. A master device always opens everything. With no master account in the bucket there is nobody who could
  // switch anything on, so nothing is held back. A policy that is not signed by the master (or is for another
  // device) is ignored, which leaves the default: locked notes stay off.
  const DEFAULT_ACCESS = { notes: true, locked: false };

  async function accessFor(id, master, hasMaster, inbox, isMasterDevice, minPolicyAt) {
    if (isMasterDevice) return { notes: true, locked: true, source: 'master' };
    if (!hasMaster) return { notes: true, locked: true, source: 'no-master' };
    const p = inbox && inbox.policy;
    if (p && master && p.id === id && await policyValid(master.pub, p)) {
      if (Number.isFinite(minPolicyAt) && p.at < minPolicyAt) {
        // Reject replayed older policy; retain the device's current stricter/latest remembered access.
        const cur = getState().access;
        if (cur) return { notes: !!cur.notes, locked: !!cur.locked, at: minPolicyAt, source: 'policy', replayed: true };
      }
      return { notes: !!p.notes, locked: !!p.locked, at: p.at, source: 'policy' };
    }
    return { ...DEFAULT_ACCESS, source: 'default' };
  }

  // What the app obeys right now: remembered on the device, so it holds from the first moment of the next start and
  // with no connection. Not yet known (fresh install, or first start after updating): locked notes wait.
  function access() {
    const s = getState();
    if (s.masterSession) return { notes: true, locked: true, known: true, master: true };
    if (s.hasMaster === false) return { notes: true, locked: true, known: true };
    if (s.access) return { notes: !!s.access.notes, locked: !!s.access.locked, known: true };
    return { ...DEFAULT_ACCESS, known: false };
  }
  const allows = (meta) => { const a = access(); return !meta || meta.lockType === 'none' ? a.notes : a.locked; };

  // Saves the verdict. Tells the app (ks-access-changed) only when it actually differs from what was remembered.
  function commitAccess(acc, hasMaster) {
    const prev = getState();
    const changed = !prev.access || prev.access.notes !== acc.notes || prev.access.locked !== acc.locked || prev.hasMaster !== hasMaster;
    const nextPatch = { access: { notes: acc.notes, locked: acc.locked }, hasMaster };
    if (acc.source === 'policy' && Number.isFinite(acc.at) && acc.at > (Number(prev.lastPolicyAt) || 0)) {
      nextPatch.lastPolicyAt = acc.at;
    }
    patchState(nextPatch);
    if (changed) { try { root.dispatchEvent(new root.CustomEvent('ks-access-changed', { detail: access() })); } catch (e) { /* UI only */ } }
    return changed;
  }
  const accessAck = (acc) => ({ notes: acc.notes, locked: acc.locked, at: acc.at || 0, t: now() });

  async function writeRecord(me, env, master, myKey, extra) {
    const prev = (await readRecord(me.id)) || {};
    const rec = {
      v: 1, id: me.id, name: me.name, firstSeen: prev.firstSeen || me.createdAt, lastSeen: now(),
      logins: (prev.logins || 0) + (extra && extra.countLogin ? 1 : 0), env, pub: me.publicJwk,
      ack: (extra && extra.ack !== undefined) ? extra.ack : (prev.ack || null),
      access: (extra && extra.access) || prev.access || null,
      resumedAfter: (extra && extra.resumedAfter !== undefined) ? extra.resumedAfter : (prev.resumedAfter || null),
    };
    if (myKey) { rec.masterProofAt = now(); rec.masterProof = await sign(myKey, claimText(me.id, rec.masterProofAt)); }
    await writeJson(K.rec(me.id), rec);
    return rec;
  }

  const cmdDetail = (c) => (c ? [c.byName ? 'by ' + c.byName : '', c.wipe ? 'saved notes erased' : ''].filter(Boolean).join(' · ') : '');

  function entry(env, result, detail) {
    const e = { t: now(), r: result, s: env.summary, disp: env.display, tz: env.timeZone, net: env.network, ver: env.appVersion, lang: env.language, scr: env.screen };
    if (detail) e.d = detail;
    return e;
  }

  /* ------------------------------------------------- check-in, poll, enforce */

  let busy = null;
  let pollTimer = null;
  let onStatus = null;

  // One login. reason: 'open' (the app was opened) or 'connect' (details were just saved).
  async function checkIn(reason) {
    if (busy) return busy;
    busy = (async () => {
      try {
        const me = await getIdentity(true);
        const env = await collectEnv();
        const master = await readMaster();
        const hasMaster = !!master || await masterExists();       // the app never makes a master by itself: it only looks
        const myKey = await myMasterKey(master);
        const lost = !myKey && !!getState().masterSession;        // was logged in as master, and the key no longer matches
        if (lost) { patchState({ masterSession: false }); store().del('master').catch(() => {}); masterChanged(); }
        const inbox = await readInbox(me.id);
        const verdict = await judge(me, master, inbox);

        const entries = [];
        for (const f of lsJson(LS.failed, [])) entries.push({ ...entry(env, 'failed', f.kind), t: f.t });
        entries.sort((a, b) => b.t - a.t);
        const last = Number(lsGet(LS.lastlog)) || 0;
        const skip = reason === 'open' && verdict.status === 'active' && !entries.length && !lost && now() - last < DEDUPE_MS;
        if (verdict.status === 'active') { if (!skip) entries.unshift(entry(env, 'ok', reason === 'connect' ? 'connected' : 'opened')); }
        else entries.unshift(entry(env, verdict.status, cmdDetail(verdict.cmd)));
        if (lost) entries.unshift(entry(env, 'master', 'master login ended'));

        const acc = await accessFor(me.id, master, hasMaster, inbox, !!myKey, Number(getState().lastPolicyAt) || 0);
        commitAccess(acc, hasMaster);
        let rec = null;
        if (verdict.status === 'blocked' || verdict.status === 'terminated') {
          // Commit local lock/wipe state FIRST before sending telemetry, and never let telemetry failures skip enforcement.
          await commitLocalEnforcement(verdict);
          const cmdAt = (verdict.cmd && verdict.cmd.at) || (getState().lock && getState().lock.at) || 0;
          const ackObj = { kind: verdict.status, cmdAt, t: now() };
          await Promise.race([
            (async () => {
              try { rec = await writeRecord(me, env, master, myKey, { countLogin: !skip, ack: ackObj, access: accessAck(acc) }); } catch (e) {}
              if (entries.length) { try { await appendLog(me.id, entries); lsSet(LS.failed, '[]'); lsSet(LS.lastlog, String(now())); } catch (e) {} }
            })(),
            sleep(3000),
          ]);
          const out = { ...verdict, me, rec, master, hasMaster, isMaster: !!myKey, access: acc };
          await apply(out);
          return out;
        }
        rec = await writeRecord(me, env, master, myKey, { countLogin: !skip, ack: null, resumedAfter: getState().handled || null, access: accessAck(acc) });
        if (entries.length) { try { await appendLog(me.id, entries); lsSet(LS.failed, '[]'); lsSet(LS.lastlog, String(now())); } catch (e) {} }
        const out = { ...verdict, me, rec, master, hasMaster, isMaster: !!myKey, access: acc };
        await apply(out);
        return out;
      } finally { busy = null; }
    })();
    return busy;
  }

  // Quiet re-check while the app is open: no log entry unless something changed.
  async function poll() {
    if (getState().lock) { showLock(); return null; }
    if (busy || !bucket() || !bucket().config.configured()) return null;
    try {
      const me = await getIdentity(false);
      if (!me) return null;
      const [master, inbox] = await Promise.all([readMaster(), readInbox(me.id)]);
      const myKey = await myMasterKey(master);
      const lost = !myKey && !!getState().masterSession;
      const verdict = await judge(me, master, inbox);
      // The master may have changed what this device can open: pick that up, and tell the master it arrived.
      const hasMaster = !!master || await masterExists();
      const acc = await accessFor(me.id, master, hasMaster, inbox, !!myKey, Number(getState().lastPolicyAt) || 0);
      if (commitAccess(acc, hasMaster) && verdict.status === 'active' && !lost) {
        try { await writeRecord(me, await collectEnv(), master, myKey, { access: accessAck(acc) }); } catch (e) { /* shown at the next login */ }
      }
      if (verdict.status !== 'active' || lost) {
        if (lost) { patchState({ masterSession: false }); store().del('master').catch(() => {}); masterChanged(); }
        const lockedOut = verdict.status === 'blocked' || verdict.status === 'terminated';
        if (lockedOut) await commitLocalEnforcement(verdict);
        const env = await collectEnv();
        let rec = null;
        const sendTelemetry = async () => {
          const cmdAt = (verdict.cmd && verdict.cmd.at) || (getState().lock && getState().lock.at) || 0;
          try { rec = await writeRecord(me, env, master, myKey, { ack: lockedOut ? { kind: verdict.status, cmdAt, t: now() } : null, access: accessAck(acc) }); } catch (e) {}
          const logs = [];
          if (lost) logs.push(entry(env, 'master', 'master login ended'));
          if (lockedOut) logs.push(entry(env, verdict.status === 'blocked' ? 'blocked' : 'signed-out', cmdDetail(verdict.cmd)));
          if (logs.length) { try { await appendLog(me.id, logs); } catch (e) {} }
        };
        if (lockedOut) await Promise.race([sendTelemetry(), sleep(3000)]);
        else await sendTelemetry();
        const out = { ...verdict, me, rec, master, isMaster: !!myKey };
        await apply(out);
        return out;
      }
      return { ...verdict, me, master, isMaster: !!myKey };
    } catch (e) { return null; }          // offline or Backblaze unhappy: keep going as before
  }

  async function commitLocalEnforcement(v) {
    const c = v.cmd;
    if (!v.keepLock && c) {
      const patch = {
        lock: { kind: v.status, at: c.at, by: c.byName || '', note: c.note || '', wiped: !!c.wipe },
        handled: v.status === 'terminated' ? c.at : getState().handled,
        masterSession: false,
      };
      if (c.wipe) patch.wipePending = true;
      patchState(patch);
    } else {
      patchState({ masterSession: false });
    }
    try { await store().del('master'); } catch (e) { /* the key is useless without the Backblaze key anyway */ }
    masterChanged();
    showLock();
  }

  async function apply(v) {
    if (v.status === 'active') {
      if (!v.replayed && getState().lock) { patchState({ lock: null }); closeOverlay('ks-ov-lock'); }
    } else {
      await enforce(v);
    }
    if (onStatus) { try { onStatus(v); } catch (e) { /* UI only */ } }
  }

  // Block or Terminate arrived. Take the Backblaze key off this device, optionally wipe the local
  // copies, and put up the full-screen notice. (The notice is remembered, so it also holds offline.)
  async function enforce(v) {
    const c = v.cmd;
    if (!v.keepLock && c) {
      const patch = {
        lock: { kind: v.status, at: c.at, by: c.byName || '', note: c.note || '', wiped: !!c.wipe },
        handled: v.status === 'terminated' ? c.at : getState().handled,
        masterSession: false,
      };
      if (c.wipe) patch.wipePending = true;
      patchState(patch);
    } else {
      patchState({ masterSession: false });
    }
    try { await store().del('master'); } catch (e) { /* the key is useless without the Backblaze key anyway */ }
    masterChanged();
    const B = bucket();
    if (c && c.wipe) { patchState({ wipePending: true }); B.config.clear(); }
    else if (B && B.config && B.config.configured && B.config.configured()) {
      B.config.set({ endpoint: B.config.endpoint(), bucket: B.config.bucket(), keyId: B.config.keyId(), appKey: '' });
    }
    if (c && c.wipe) { root.location.reload(); return; }
    showLock();
  }

  // Local copies are wiped before the app opens its databases, so nothing holds them open.
  // Only clear wipePending once every database deletion actually succeeds, so a closed tab or
  // blocked delete will retry on the next load.
  function runPendingWipe() {
    if (!getState().wipePending) return;
    try { root.localStorage.removeItem('ks_offline'); } catch (e) { /* private mode */ }
    if (!root.indexedDB) { patchState({ wipePending: false }); return; }
    const dbs = ['keepsake-drafts', 'keepsake-media', 'keepsake-offline'];
    let remaining = dbs.length;
    let failed = false;
    const finish = (ok) => {
      if (!ok) failed = true;
      remaining--;
      if (remaining === 0 && !failed) patchState({ wipePending: false });
    };
    for (const name of dbs) {
      let settled = false;
      let blockedTimer = null;
      const doneOne = (ok) => {
        if (settled) return;
        settled = true;
        if (blockedTimer) { clearTimeout(blockedTimer); blockedTimer = null; }
        finish(ok);
      };
      try {
        const req = root.indexedDB.deleteDatabase(name);
        req.onsuccess = () => doneOne(true);
        req.onerror = () => doneOne(false);
        req.onblocked = () => {
          if (!blockedTimer && !settled) blockedTimer = setTimeout(() => doneOne(false), 1500);
        };
      } catch (e) {
        doneOne(false);
      }
    }
  }

  /* ------------------------------------------------------------ public flow */

  function ensurePolling() {
    if (pollTimer) return;
    pollTimer = setInterval(() => { if (!root.document || root.document.visibilityState === 'visible') poll(); }, POLL_MS);
    if (root.document && root.document.addEventListener) {
      root.document.addEventListener('visibilitychange', () => { if (root.document.visibilityState === 'visible') poll(); });
    }
    if (root.addEventListener) root.addEventListener('online', () => poll());
  }

  // Called when the app opens with a saved connection. Resolves { allowed } quickly: a slow or absent
  // connection never keeps the notes from opening, but a remembered block does.
  function start(cb) {
    onStatus = cb || null;
    if (getState().lock) { showLock(); return Promise.resolve({ allowed: false }); }
    const first = checkIn('open').then((v) => { welcome(v); return { allowed: v.status === 'active' }; }).catch(() => ({ allowed: true }));
    const timeout = sleep(START_TIMEOUT_MS).then(() => ({ allowed: true }));
    ensurePolling();
    return Promise.race([first, timeout]);
  }

  // Called after Save and test succeeded.
  async function afterConnect() {
    try {
      const v = await checkIn('connect');
      if (v.status === 'active') {
        if (!v.replayed) {
          patchState({ lock: null, wipePending: false });
          closeOverlay('ks-ov-lock');
        } else if (getState().lock) {
          showLock();
          return { allowed: false };
        }
        ensurePolling();
        welcome(v);
        return { allowed: true };
      }
      return { allowed: false };
    } catch (e) {
      if (getState().lock) {
        const B = bucket();
        if (B && B.config && B.config.configured && B.config.configured()) {
          B.config.set({ endpoint: B.config.endpoint(), bucket: B.config.bucket(), keyId: B.config.keyId(), appKey: '' });
        }
        showLock();
        return { allowed: false };
      }
      return { allowed: true };
    }
  }

  // First-time steps that need the person: name the device, and - only if the bucket has no master account -
  // offer to create one. (With a master account already there, nothing is offered.)
  let offered = false;
  async function welcome(v) {
    try {
      if (!v || v.status !== 'active') return;
      const offer = () => { if (!v.hasMaster && !offered && now() - (getState().offerSnooze || 0) > SNOOZE_MS) { offered = true; offerCreateMaster(); } };
      if (!getState().named) { patchState({ named: true }); nameDialog(true, offer); }
      else offer();
    } catch (e) { /* a dialog problem must never get in the way of signing in */ }
  }

  function failedAttempt(kind) {
    const q = lsJson(LS.failed, []);
    q.push({ t: now(), kind: kind || 'other' });
    lsSet(LS.failed, JSON.stringify(q.slice(-20)));
  }

  /* ------------------------------------------------------------ master actions */

  async function needMaster() {
    const master = await readMaster();
    const key = await myMasterKey(master);
    if (!key) throw new Error('This device is not a master.');
    const me = await getIdentity(false);
    return { master, key, me };
  }

  async function command(targetId, action, opts) {
    if (!ID_RE.test(targetId)) throw new Error('Bad device id');
    const { key, me, master } = await needMaster();
    if (targetId === me.id && action !== 'allow') throw new Error('Pick another device, not the one you are holding.');
    const inbox = (await readInboxStrict(targetId)) || {};
    const prevAt = inbox.cmd && Number.isFinite(inbox.cmd.at) ? inbox.cmd.at : 0;
    const baseNow = (bucket().clock && bucket().clock.now) ? bucket().clock.now() : now();
    const at = Math.max(baseNow, (prevAt || 0) + 1);
    const cmd = { v: 2, id: targetId, action, wipe: !!(opts && opts.wipe) && action !== 'allow', at, by: me.id, byName: me.name, note: ((opts && opts.note) || '').slice(0, 200) };
    cmd.sig = await sign(key, cmdText(cmd));
    inbox.cmd = cmd;
    await saveInbox(targetId, inbox);
    return cmd;
  }

  // What a device may open: normal notes, locked notes, either, both or neither. Signed with the master key; the device
  // checks the signature and obeys it the next time it opens the app or checks in (about two minutes if it is open).
  async function setAccess(targetId, want) {
    if (!ID_RE.test(targetId)) throw new Error('Bad device id');
    const { key, me, master } = await needMaster();
    if (targetId === me.id) throw new Error('This device is a master, so it always opens everything.');
    const inbox = (await readInboxStrict(targetId)) || {};
    const prevAt = inbox.policy && Number.isFinite(inbox.policy.at) ? inbox.policy.at : 0;
    const baseNow = (bucket().clock && bucket().clock.now) ? bucket().clock.now() : now();
    const at = Math.max(baseNow, (prevAt || 0) + 1);
    const policy = { v: 1, id: targetId, notes: !!(want && want.notes), locked: !!(want && want.locked), at, by: me.id, byName: me.name };
    policy.sig = await sign(key, policyText(policy));
    inbox.policy = policy;
    await saveInbox(targetId, inbox);
    return policy;
  }

  async function forget(targetId) {
    if (!ID_RE.test(targetId)) throw new Error('Bad device id');
    const { me } = await needMaster();
    if (targetId === me.id) throw new Error('Pick another device, not the one you are holding.');
    const B = bucket();
    const master = await readMaster();
    const st = await statusOf(master, targetId, await readInbox(targetId));
    if (st.status === 'blocked') throw new Error('Allow this device again first. Forgetting a blocked device would lift the block.');
    for (const o of await B.listAll('devices/' + targetId + '.')) await B.deleteObject(o.key);
  }

  async function rename(name) {
    const me = await getIdentity(false);
    if (!me) return;
    me.name = String(name || '').trim().slice(0, 60) || me.name;
    await store().set('identity', me);
    patchState({ named: true });
    try { const rec = await readRecord(me.id); if (rec) { rec.name = me.name; await writeJson(K.rec(me.id), rec); } } catch (e) { /* shown next login */ }
    return me.name;
  }

  // Only for a master account made by version 1.12, which has a key but no password: paste its old key
  // (KSM1...) to make this device a master, then give the account a password.
  async function adoptMasterKey(text) {
    const key = await importMasterText(text);
    const master = await readMaster();
    if (!master) throw new Error('No master account has been set up for this bucket yet.');
    if (hasPassword(master)) throw new Error('This master account uses a password now. Use Log in as master.');
    if (!(await keyMatches(key, master.pub))) throw new Error('That master key does not belong to this bucket.');
    await store().set('master', { privateKey: key, savedAt: now() });
    patchState({ masterSession: true });
    masterChanged();
    try { const me = await getIdentity(false); if (me) await writeRecord(me, await collectEnv(), master, key, {}); } catch (e) { /* shown next login */ }
  }

  /* ------------------------------------------------------------- reading it all */

  async function pool(items, size, fn) {
    const out = new Array(items.length);
    let i = 0;
    await Promise.all(Array.from({ length: Math.min(size, items.length) }, async () => {
      while (i < items.length) { const n = i++; out[n] = await fn(items[n]); }
    }));
    return out;
  }

  async function statusOf(master, id, inbox, rec) {
    const c = inbox && inbox.cmd;
    if (!c) return { status: 'active' };
    if (!master || c.id !== id || !(await cmdValid(master.pub, c))) return { status: 'active', forged: true };
    if (c.action === 'block') return { status: 'blocked', cmd: c };
    if (c.action === 'terminate') {
      const resumed = !!(rec && (
        rec.resumedAfter === c.at ||
        (rec.ack && rec.ack.kind === 'terminated' && rec.ack.cmdAt === c.at && (rec.lastSeen || 0) > (rec.ack.t || 0))
      ));
      if (resumed) return { status: 'active', cmd: c, reLoggedIn: true };
      return { status: 'terminated', cmd: c };
    }
    return { status: 'active', cmd: c };
  }

  async function listDevices() {
    const B = bucket();
    const master = await readMaster();
    const objs = await B.listAll('devices/');
    const ids = [...new Set(objs.map((o) => /^devices\/([0-9a-f]{32})\./.exec(o.key)).filter(Boolean).map((m) => m[1]))];
    const rows = await pool(ids, 6, async (id) => {
      const [rec, inbox] = await Promise.all([readRecord(id), readInbox(id)]);
      if (!rec) return null;
      const st = await statusOf(master, id, inbox, rec);
      const isMaster = !!(master && await proofValid(master.pub, id, rec));
      const access = await accessFor(id, master, !!master, inbox, isMaster);
      // "Confirmed" once the device has written back the policy it is now obeying.
      const accessConfirmed = access.source !== 'policy' || !!(rec.access && rec.access.at === access.at);
      return { id, rec, ...st, isMaster, claimsMaster: !!rec.masterProof && !isMaster, access, accessConfirmed };
    });
    return { master, devices: rows.filter(Boolean).sort((a, b) => (b.rec.lastSeen || 0) - (a.rec.lastSeen || 0)) };
  }

  async function loadLog(id, months) {
    const B = bucket();
    const keys = (await B.listAll('devices/' + id + '.log-')).map((o) => o.key).sort().reverse().slice(0, months || 2);
    const parts = await Promise.all(keys.map((k) => readJson(k).catch(() => [])));
    return [].concat(...parts.map((p) => (Array.isArray(p) ? p : []))).sort((a, b) => b.t - a.t);
  }

  async function loadActivity(devices, limit) {
    const parts = await pool(devices, 6, async (d) => (await loadLog(d.id, 1)).map((e) => ({ ...e, id: d.id, name: d.rec.name })));
    return [].concat(...parts).sort((a, b) => b.t - a.t).slice(0, limit || 60);
  }

  /* ---------------------------------------------------------------------- UI */

  const doc = () => root.document;
  const RESULT = {
    ok: ['\u2713', 'Signed in'], blocked: ['\u2715', 'Blocked attempt'], terminated: ['\u23fb', 'Signed out'], 'signed-out': ['\u23fb', 'Signed out'],
    failed: ['!', 'Failed attempt'], master: ['\u2605', 'Master'],
  };
  const STATUS = { active: ['\u2713', 'Active'], blocked: ['\u2715', 'Blocked'], terminated: ['\u23fb', 'Signed out'] };

  function openOverlay(id) { if (root.show) root.show(id); else doc().getElementById(id).classList.remove('hidden'); }
  function closeOverlay(id) { const el = doc() && doc().getElementById(id); if (!el) return; if (root.hide) root.hide(id); else el.classList.add('hidden'); }

  // One reusable overlay shell, created on first use.
  function shell(id, title, wide) {
    let ov = doc().getElementById(id);
    if (!ov) {
      ov = doc().createElement('div');
      ov.className = 'overlay hidden ks-dev-ov';
      ov.id = id;
      ov.innerHTML = '<div class="modal ' + (wide ? '' : 'narrow') + '" role="dialog" aria-modal="true" aria-labelledby="' + id + '-h"><div class="modal-head"><h2 id="' + id + '-h"></h2>' +
        '<button class="icon-btn" data-close="' + id + '" aria-label="Close"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M18 6 6 18M6 6l12 12"/></svg></button></div>' +
        '<div class="modal-body"></div></div>';
      doc().body.appendChild(ov);
    }
    ov.querySelector('h2').textContent = title;
    return ov.querySelector('.modal-body');
  }

  function chip(kind, icon, label) { return '<span class="dev-chip" data-kind="' + esc(kind) + '"><span aria-hidden="true">' + esc(icon) + '</span> ' + esc(label) + '</span>'; }
  // On or off is shown by the tick or cross and the word, never by colour alone.
  const accChip = (label, on) => chip(on ? 'ok' : 'blocked', on ? '✓' : '✕', label + (on ? ' on' : ' off'));
  const say = (m) => { if (root.toast) root.toast(m); };
  const ask = (t, m, fn, label, calm) => (root.openConfirm ? root.openConfirm(t, m, fn, label, calm) : say('Confirmation dialog unavailable — action cancelled.'));
  // The buttons that cut a device off, erase things or end every master login ask twice.
  const askTwice = (t, m, t2, m2, fn, label, label2, calm) => (root.openConfirmTwice ? root.openConfirmTwice(t, m, t2, m2, fn, label, label2, calm) : say('Confirmation dialog unavailable — action cancelled.'));

  async function copyText(text) {
    try { await root.navigator.clipboard.writeText(text); say('Copied'); } catch (e) { say('Could not copy - select the text and copy it by hand'); }
  }

  // A small dialog: title, a block of html, and buttons.
  function dialog(id, title, html, buttons) {
    const body = shell(id, title);
    body.innerHTML = html + '<div class="btn-row dev-actions"></div>';
    const row = body.querySelector('.dev-actions');
    buttons.forEach((b) => {
      const el = doc().createElement('button');
      el.type = 'button'; el.className = 'btn ' + (b.kind || 'btn-ghost'); el.textContent = b.label;
      el.addEventListener('click', async () => { if (b.keep !== true) closeOverlay(id); if (b.fn) await b.fn(body); });
      row.appendChild(el);
    });
    openOverlay(id);
    return body;
  }

  function nameDialog(first, then) {
    getIdentity(false).then((me) => {
      if (!me) { if (then) then(); return; }
      const after = () => { if (then) then(); };
      const body = dialog('ks-ov-name', first ? 'Name this device' : 'Rename this device',
        '<p class="hint">' + (first ? 'This is how this phone or computer will appear in the login list. ' : '') + 'It starts as the browser and system the app could see.</p>' +
        '<div class="field"><label for="ks-dev-name">Device name</label><input type="text" id="ks-dev-name" maxlength="60" autocomplete="off" value="' + esc(me.name) + '"></div>',
        [{ label: 'Save', kind: 'btn-primary', fn: async (b) => { say('Saved as ' + await rename(b.querySelector('input').value)); renderSettings(); after(); } },
          { label: first ? 'Keep this name' : 'Cancel', fn: async () => { if (first) await rename(me.name); after(); } }]);
      body.querySelector('input').select();
    }).catch(() => { if (then) then(); /* no dialog is better than a broken login */ });
  }

  // A dialog with password fields. run(values) does the work; a thrown error is shown in the dialog,
  // which stays open so the person can fix the password and try again.
  function formDialog(id, title, intro, fields, label, run, danger) {
    const body = dialog(id, title,
      '<p class="hint">' + intro + '</p>' +
      fields.map((f, i) => '<div class="field"><label for="' + id + '-f' + i + '">' + esc(f.label) + '</label><input type="password" id="' + id + '-f' + i + '" autocomplete="' + f.auto + '" autocapitalize="off" spellcheck="false"></div>').join('') +
      '<label class="dev-check"><input type="checkbox" class="dev-show"> <span>Show the password</span></label>' +
      '<p class="hint dev-err" role="alert" hidden></p>',
      [{ label, kind: danger ? 'btn-danger' : 'btn-primary', keep: true, fn: async (b) => {
        const err = b.querySelector('.dev-err'); err.hidden = true;
        const vals = Array.from(b.querySelectorAll('input[id^="' + id + '-f"]')).map((i) => i.value);
        const btn = b.querySelector('.dev-actions .btn'); btn.disabled = true;
        try { await run(vals); closeOverlay(id); }
        catch (e) { err.textContent = e.message || 'Something went wrong'; err.hidden = false; }
        finally { btn.disabled = false; }
      } }, { label: 'Cancel' }]);
    const inputs = body.querySelectorAll('input[id^="' + id + '-f"]');
    const newPwIdx = fields.findIndex((f) => f.auto === 'new-password');
    if (newPwIdx >= 0 && inputs[newPwIdx]) {
      const meter = doc().createElement('p');
      meter.className = 'hint dev-strength';
      meter.setAttribute('aria-live', 'polite');
      (inputs[newPwIdx].closest('.field') || inputs[newPwIdx].parentNode).appendChild(meter);
      const updateStrength = () => {
        const val = inputs[newPwIdx].value || '';
        if (!val) { meter.textContent = 'Use a long passphrase (' + PW_MIN + '+ characters, e.g. 4 unrelated words).'; meter.dataset.level = ''; return; }
        let classes = 0;
        if (/[a-z]/.test(val)) classes++;
        if (/[A-Z]/.test(val)) classes++;
        if (/[0-9]/.test(val)) classes++;
        if (/[^A-Za-z0-9]/.test(val)) classes++;
        if (val.length < PW_MIN) { meter.textContent = 'Too short — needs at least ' + PW_MIN + ' characters (' + val.length + '/' + PW_MIN + ').'; meter.dataset.level = 'weak'; }
        else if (val.length >= 16 || (val.length >= 12 && classes >= 3)) { meter.textContent = 'Strong passphrase.'; meter.dataset.level = 'strong'; }
        else { meter.textContent = 'Fair — consider adding another word or symbol for offline safety.'; meter.dataset.level = 'fair'; }
      };
      inputs[newPwIdx].addEventListener('input', updateStrength);
      updateStrength();
    }
    body.querySelector('.dev-show').addEventListener('change', (e) => inputs.forEach((i) => { i.type = e.target.checked ? 'text' : 'password'; i.classList.toggle('dev-pw', e.target.checked); }));
    inputs.forEach((i) => i.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); body.querySelector('.dev-actions .btn').click(); } }));
    inputs[0].focus();
    return body;
  }

  const mustMatch = (a, b) => { if (a !== b) throw new Error('The two passwords are not the same.'); };

  function createMasterDialog() {
    formDialog('ks-ov-pw', 'Create the master account',
      'A master account lets you see every device that signs in and sign out or block them, from any device, with just this password. It is stored in your bucket. You can change it later. At least ' + PW_MIN + ' characters.',
      [{ label: 'Master password', auto: 'new-password' }, { label: 'Type it again', auto: 'new-password' }], 'Create master account',
      async (v) => { mustMatch(v[0], v[1]); await createMaster(v[0]); say('Master account created. You are logged in as master.'); renderSettings(); });
  }
  function loginMasterDialog() {
    formDialog('ks-ov-pw', 'Log in as master',
      'Enter the master password. This device stays logged in as master until you log out.',
      [{ label: 'Master password', auto: 'current-password' }], 'Log in',
      async (v) => { await loginMaster(v[0]); say('Logged in as master'); renderSettings(); });
  }
  function changePasswordDialog() {
    formDialog('ks-ov-pw', 'Change the master password',
      'The master account keeps working on every device; only the password changes.',
      [{ label: 'Current password', auto: 'current-password' }, { label: 'New password', auto: 'new-password' }, { label: 'New password again', auto: 'new-password' }], 'Change password',
      async (v) => { mustMatch(v[1], v[2]); await changePassword(v[0], v[1]); say('Master password changed'); renderSettings(); });
  }
  function replaceKeyDialog() {
    formDialog('ks-ov-pw', 'Replace the master key',
      'Use this if a device that was logged in as master is lost or stolen. Every other device logged in as master is logged out; this device stays logged in with the new key. Blocks you already set stay in force. Leave the new password empty to keep the current one.',
      [{ label: 'Current password', auto: 'current-password' }, { label: 'New password (optional)', auto: 'new-password' }, { label: 'New password again', auto: 'new-password' }], 'Replace master key',
      async (v) => { if (v[1] || v[2]) mustMatch(v[1], v[2]); await replaceMasterKey(v[0], v[1]); say('Master key replaced. Other master logins are ended.'); renderSettings(); }, true);
  }
  function legacyPasswordDialog() {
    formDialog('ks-ov-pw', 'Give the master account a password',
      'This master account was made by an older version and has no password. Set one so it can be opened from any device.',
      [{ label: 'Master password', auto: 'new-password' }, { label: 'Type it again', auto: 'new-password' }], 'Set password',
      async (v) => { mustMatch(v[0], v[1]); await setLegacyPassword(v[0]); say('Master password set'); renderSettings(); });
  }

  // Shown when the app opens and finds no master account in the bucket.
  function offerCreateMaster() {
    dialog('ks-ov-offer', 'No master account yet',
      '<p class="hint">Nobody has set up a master account for this bucket. A master account lets you see every device that signs in, and sign out or block devices, from any device with one password. You can do this later in Settings.</p>',
      [{ label: 'Create master account', kind: 'btn-primary', fn: () => createMasterDialog() },
        { label: 'Not now', fn: () => patchState({ offerSnooze: now() }) }]);
  }

  function enterMasterDialog() {
    dialog('ks-ov-enter', 'Enter old master key',
      '<p class="hint">Only for a master account made by an older version, which has a key but no password. Paste that key (it starts with KSM1.), then give the account a password.</p>' +
      '<div class="field"><label for="ks-enter-key">Old master key</label><textarea id="ks-enter-key" rows="5" spellcheck="false" autocapitalize="off"></textarea><p class="hint dev-err" role="alert" hidden></p></div>',
      [{ label: 'Use this key', kind: 'btn-primary', keep: true, fn: async (b) => {
        const err = b.querySelector('.dev-err');
        try { await adoptMasterKey(b.querySelector('textarea').value); closeOverlay('ks-ov-enter'); say('This device holds the old master key. Now set a password.'); renderSettings(); }
        catch (e) { err.textContent = e.message; err.hidden = false; }
      } }, { label: 'Cancel' }]);
  }

  async function renderSettings() {
    const slot = doc().getElementById('devices-slot');
    if (!slot) return;
    const me = await getIdentity(false).catch(() => null);
    if (!me) { slot.innerHTML = '<p class="hint">This device registers itself the first time it connects to your bucket.</p>'; return; }
    slot.innerHTML = '<p class="hint">Looking for a master account…</p>';
    let master = null, isMaster = false, unreachable = false, masterDamaged = false;
    try {
      master = await readMaster();
      if (!master) masterDamaged = await masterExists();
      else isMaster = !!(await myMasterKey(master));
    } catch (e) { unreachable = true; }
    const pw = hasPassword(master);
    const btn = (k, label, cls) => '<button class="btn ' + (cls || 'btn-ghost') + '" data-d="' + k + '">' + label + '</button>';
    let buttons, hint;
    if (unreachable) { buttons = btn('retry', 'Try again'); hint = 'Could not reach your bucket to look for a master account.'; }
    else if (masterDamaged) { buttons = btn('retry', 'Try again') + btn('mine', 'This device’s info'); hint = 'The master account file (devices/_master.json) in your bucket is damaged and cannot be read. Restore it from a backup or delete devices/_master.json in Backblaze before creating a new master account.'; }
    else if (!master) { buttons = btn('create', 'Create master account', 'btn-primary'); hint = 'There is no master account yet. Create one to see every device and sign out or block devices from any device, with one password.'; }
    else if (isMaster && pw) {
      buttons = btn('manage', 'Manage devices', 'btn-primary') + btn('change', 'Change password') + btn('replace', 'Replace master key') + btn('logout', 'Log out of master');
      hint = 'You are logged in as master on this device: it sees every device and can choose what each one may open, sign it out or block it. Log out when you are done.';
    } else if (isMaster) {
      buttons = btn('manage', 'Manage devices', 'btn-primary') + btn('legacy', 'Set a master password') + btn('logout', 'Log out of master');
      hint = 'This master account has no password yet. Set one so it can be opened from any device.';
    } else if (pw) { buttons = btn('login', 'Log in as master', 'btn-primary') + btn('mine', 'This device’s info'); hint = 'A master account exists. Log in with its password to see every device and choose what each one may open.'; }
    else { buttons = btn('enter', 'Enter old master key') + btn('mine', 'This device’s info'); hint = 'A master account exists but it has no password yet (made by an older version). On the device that holds its key, open Settings and set one. If that device is gone, delete the devices/ folder in Backblaze and create a new master account.'; }
    const acc = access();
    const opens = isMaster ? chip('master', '★', 'Opens everything') : accChip('Notes', acc.notes) + ' ' + accChip('Locked notes', acc.locked);
    slot.innerHTML =
      '<div class="dev-me"><div><b>' + esc(me.name) + '</b> ' + (isMaster ? chip('master', '★', 'Logged in as master') : chip('device', '•', 'Device')) + '</div>' +
      '<div class="hint">ID ' + esc(shortId(me.id)) + ' · first connected ' + esc(fmt(me.createdAt)) + '</div>' +
      '<div class="dev-wrap dev-access-line"><span class="hint">This device opens:</span> ' + opens + '</div></div>' +
      '<div class="btn-row dev-wrap">' + buttons + btn('rename', 'Rename') + '</div><p class="hint">' + hint + '</p>' +
      (!isMaster && !acc.locked && master ? '<p class="hint">Locked notes are off for this device. A master turns them on under Manage devices, or log in as master here.</p>' : '');
    renderLogSection(me, isMaster);
    slot.onclick = async (e) => {
      const d = e.target.closest('[data-d]'); if (!d) return;
      const act = d.dataset.d;
      try {
        if (act === 'rename') nameDialog(false);
        else if (act === 'retry') renderSettings();
        else if (act === 'create') createMasterDialog();
        else if (act === 'login') loginMasterDialog();
        else if (act === 'change') changePasswordDialog();
        else if (act === 'replace') askTwice('Replace the master key?', 'Every other device logged in as master is logged out; this device stays logged in with the new key.', 'Really replace it?', 'Last check: use this for a lost or stolen device. Nothing is deleted, but every other device’s master login ends right now (this device stays logged in with the new key).', replaceKeyDialog, 'Continue', 'Yes, replace it');
        else if (act === 'legacy') legacyPasswordDialog();
        else if (act === 'enter') enterMasterDialog();
        else if (act === 'logout') ask('Log out of master?', 'This device goes back to being an ordinary device. Log in again any time with the master password.', async () => { await logoutMaster(); say('Logged out of master'); renderSettings(); }, 'Log out', true);
        else if (act === 'manage') openManager();
        else if (act === 'mine') openDetail(me.id, { self: true, rec: await readRecord(me.id) });
      } catch (err) { say(err.message); }
    };
  }

  // The Activity log section of Settings: just a pointer to the log itself, which has its own screen.
  function renderLogSection(me, isMaster) {
    const slot = doc().getElementById('log-slot');
    if (!slot) return;
    const last = Number(lsGet(LS.lastlog)) || 0;
    slot.innerHTML = '<p class="hint">' + (isMaster ? 'Every sign-in, blocked attempt and sign-out, for all devices.' : 'Every time this device opened the app or tried to sign in.') + (last ? ' This device last logged in ' + esc(fmt(last)) + '.' : '') + '</p>' +
      '<div class="btn-row dev-wrap"><button type="button" class="btn btn-ghost" data-l="log">Open activity log</button></div>';
    slot.onclick = (e) => { if (e.target.closest('[data-l]')) openLog(isMaster ? 'all' : me.id).catch((err) => say(err.message)); };
  }

  function entryHTML(e, showName) {
    const safeKind = Object.prototype.hasOwnProperty.call(RESULT, e.r) ? e.r : 'other';
    const r = RESULT[safeKind] || ['?', String(e.r || 'Event')];
    return '<li class="dev-ev" data-r="' + esc(safeKind) + '"><div class="dev-ev-top">' + chip(safeKind, r[0], r[1] + (e.d && safeKind !== 'ok' ? ' \u2014 ' + e.d : '')) +
      '<time>' + esc(fmt(e.t)) + '</time></div><div class="hint">' + (showName ? '<b>' + esc(e.name || shortId(e.id)) + '</b> \u00b7 ' : '') + esc(e.s || '') +
      (e.disp ? ' \u00b7 ' + esc(e.disp) : '') + (e.net ? ' \u00b7 ' + esc(e.net) : '') + (e.tz ? ' \u00b7 ' + esc(e.tz) : '') + (e.ver ? ' \u00b7 v' + esc(e.ver) : '') + '</div></li>';
  }

  async function openManager() {
    const body = shell('ks-ov-devices', 'Devices', true);
    body.innerHTML = '<p class="hint">Loading\u2026</p>';
    openOverlay('ks-ov-devices');
    let data;
    try { data = await listDevices(); }
    catch (e) { body.innerHTML = '<p class="hint dev-err">' + esc(e.message || 'Could not load') + '</p>'; return; }
    const me = await getIdentity(false);
    // Devices only: what each one is and what it may open. Logins have their own screen (the Activity log).
    body.innerHTML =
      '<div class="dev-toolbar"><p class="hint">' + plural(data.devices.length, 'device', 'devices') + '. Tap one to see its details and choose what it may open.</p>' +
      '<button type="button" class="btn btn-ghost" data-l="log">Activity log</button></div>' +
      '<ul class="dev-list">' + data.devices.map((d) => {
        const st = STATUS[d.status];
        const mine = me && d.id === me.id;
        const opens = d.isMaster ? chip('master', '\u2605', 'Opens everything') : accChip('Notes', d.access.notes) + ' ' + accChip('Locked notes', d.access.locked);
        return '<li><button type="button" class="dev-row" data-id="' + d.id + '"><span class="dev-row-main"><b>' + esc(d.rec.name || shortId(d.id)) + '</b> ' +
          (mine ? chip('self', '\u2022', 'This device') + ' ' : '') + (d.isMaster ? chip('master', '\u2605', 'Master login') + ' ' : '') + chip(d.status, st[0], st[1]) +
          (d.claimsMaster ? ' ' + chip('wait', '\u2026', 'Old master login') : '') + (d.forged ? ' ' + chip('blocked', '!', 'Unsigned command ignored') : '') +
          '</span><span class="dev-row-main">' + opens + (d.accessConfirmed ? '' : ' ' + chip('wait', '\u2026', 'Access change not confirmed yet')) + '</span>' +
          '<span class="hint">' + esc((d.rec.env && d.rec.env.summary) || '') + '<br>Last seen ' + esc(fmt(d.rec.lastSeen)) + '</span></button></li>';
      }).join('') + '</ul>';
    body.querySelector('.dev-list').onclick = (e) => {
      const b = e.target.closest('.dev-row'); if (!b) return;
      openDetail(b.dataset.id, { self: !!me && b.dataset.id === me.id, row: data.devices.find((x) => x.id === b.dataset.id) });
    };
    body.querySelector('[data-l="log"]').onclick = () => openLog('all').catch((err) => say(err.message));
  }

  // The activity log, on its own screen: every login, blocked attempt and sign-out. A master can look at one device
  // or at all of them; any other device sees its own.
  async function openLog(filterId) {
    const body = shell('ks-ov-log', 'Activity log', true);
    body.innerHTML = '<p class="hint">Loading\u2026</p>';
    openOverlay('ks-ov-log');
    const me = await getIdentity(false);
    let devices = [], isMaster = false;
    try {
      const master = await readMaster();
      isMaster = !!(await myMasterKey(master));
      if (isMaster) devices = (await listDevices()).devices;
    } catch (e) { body.innerHTML = '<p class="hint dev-err">' + esc(e.message || 'Could not load') + '</p>'; return; }
    const nameOf = (id) => { const d = devices.find((x) => x.id === id); return (d && d.rec.name) || (me && id === me.id ? me.name : shortId(id)); };
    const scope = isMaster ? (filterId || 'all') : (me ? me.id : '');
    body.innerHTML =
      '<div class="dev-toolbar dev-filters">' +
      (isMaster ? '<label class="dev-select"><span>Device</span><select id="ks-log-dev"><option value="all">All devices</option>' + devices.map((d) => '<option value="' + d.id + '"' + (d.id === scope ? ' selected' : '') + '>' + esc(d.rec.name || shortId(d.id)) + '</option>').join('') + '</select></label>' : '<p class="hint">This device\u2019s logins.</p>') +
      '<label class="dev-select"><span>Show</span><select id="ks-log-kind"><option value="all">Everything</option><option value="problems">Problems only</option></select></label></div>' +
      '<ul class="dev-feed" id="ks-log-feed" aria-live="polite"><li class="hint">Loading\u2026</li></ul>';
    const feedEl = body.querySelector('#ks-log-feed');
    let seq = 0;
    const paint = async () => {
      const mine = ++seq;
      const dev = isMaster ? body.querySelector('#ks-log-dev').value : scope;
      const kind = body.querySelector('#ks-log-kind').value;
      feedEl.innerHTML = '<li class="hint">Loading\u2026</li>';
      let rows;
      try { rows = dev === 'all' ? await loadActivity(devices, 120) : (await loadLog(dev, 2)).slice(0, 120).map((e) => ({ ...e, id: dev, name: nameOf(dev) })); }
      catch (e) { if (mine === seq) feedEl.innerHTML = '<li class="hint dev-err">' + esc(e.message || 'Could not load') + '</li>'; return; }
      if (mine !== seq) return;
      if (kind === 'problems') rows = rows.filter((e) => e.r !== 'ok' && e.r !== 'master');
      feedEl.innerHTML = rows.length ? rows.map((e) => entryHTML(e, dev === 'all')).join('') : '<li class="hint">Nothing recorded' + (kind === 'problems' ? ' that went wrong' : ' yet') + '.</li>';
    };
    body.querySelectorAll('select').forEach((s) => { s.onchange = paint; });
    paint();
  }

  // Sign out / Block: the confirmation, with the choice of also erasing that device's saved notes.
  function wipeDialog(title, intro, label, danger, go) {
    dialog('ks-ov-act', title,
      '<p class="hint">' + esc(intro) + '</p>' +
      '<label class="dev-check"><input type="checkbox" id="ks-wipe"> <span><b>Also erase the notes saved on that device</b></span></label>' +
      '<p class="hint">Removes the offline copies of notes, photos, audio, video and unsent edits that its browser keeps. Your notes in the bucket are not touched. It happens when that device next checks in, so it cannot reach a device that stays offline, and anything that device had not yet uploaded is lost.</p>',
      [{ label, kind: danger ? 'btn-danger' : 'btn-primary', fn: (b) => go(b.querySelector('#ks-wipe').checked) }, { label: 'Cancel' }]);
  }

  async function openDetail(id, ctx) {
    const rec = (ctx.row && ctx.row.rec) || ctx.rec || {};
    const body = shell('ks-ov-device', rec.name || 'Device', false);
    body.innerHTML = '<p class="hint">Loading\u2026</p>';
    openOverlay('ks-ov-device');
    const row = ctx.row || {};
    const env = rec.env || {};
    const facts = [['ID', shortId(id)], ['System', env.summary], ['How it runs', env.display], ['Screen', env.screen], ['Language', env.language], ['Time zone', env.timeZone],
      ['Cores / memory', [env.cores, env.memoryGB ? env.memoryGB + ' GB' : ''].filter(Boolean).join(' / ')], ['Network', env.network], ['App version', env.appVersion],
      ['First seen', fmt(rec.firstSeen)], ['Last seen', fmt(rec.lastSeen)], ['Logins', rec.logins], ['Browser string', env.userAgent]].filter((f) => f[1]);
    let ackLine = '';
    if (row.cmd && row.status !== 'active') {
      const ok = rec.ack && rec.ack.cmdAt === row.cmd.at;
      ackLine = '<p class="hint">' + (ok ? 'Confirmed on the device ' + esc(fmt(rec.ack.t)) + (row.cmd.wipe ? '; its saved notes were erased.' : '.') : 'Not confirmed yet \u2014 it takes effect when that device next opens the app, or within about two minutes if it is open.' + (row.cmd.wipe ? ' Its saved notes will be erased then.' : '')) + '</p>';
    }
    const canAct = row.id && !ctx.self;
    // What this device may open. Only a master sets it, and only for another device that is not itself a master.
    const acc = row.access || (ctx.self ? access() : { notes: true, locked: false });
    let accessBlock = '';
    if (canAct && !row.isMaster) {
      const pending = row.access && row.access.source === 'policy' && !row.accessConfirmed;
      const how = !row.access ? '' : row.access.source === 'policy'
        ? (pending ? 'Saved. It takes effect when that device next opens the app, or within about two minutes if it is open.' : 'Confirmed on the device' + (rec.access && rec.access.t ? ' ' + fmt(rec.access.t) : '') + '.')
        : 'Not set yet, so the default applies: notes on, locked notes off.';
      accessBlock =
        '<h3 class="dev-h">What this device can open</h3>' +
        '<fieldset class="dev-access"><legend class="visually-hidden">What this device can open</legend>' +
        '<label class="dev-check"><input type="checkbox" id="ks-acc-notes"' + (acc.notes ? ' checked' : '') + '><span><b>Notes</b><small>Everyday notes, in the Notes tab</small></span></label>' +
        '<label class="dev-check"><input type="checkbox" id="ks-acc-locked"' + (acc.locked ? ' checked' : '') + '><span><b>Locked notes</b><small>The Locked tab: quick-locked and time-locked notes</small></span></label>' +
        '</fieldset><p class="hint" id="ks-acc-state">' + esc(how) + '</p>' +
        '<div class="btn-row dev-wrap"><button type="button" class="btn btn-primary" data-a="access" id="ks-acc-save" disabled>Save access</button></div>' +
        '<p class="hint">A device that is switched off for a type of note does not show it, does not download it and forgets any copy it holds. This is checked by the app on that device (see the limit in Settings \u2192 Devices).</p>';
    } else {
      accessBlock = '<h3 class="dev-h">What this device can open</h3><div class="dev-wrap">' + (row.isMaster ? chip('master', '\u2605', 'Everything, because it is a master') : accChip('Notes', acc.notes) + ' ' + accChip('Locked notes', acc.locked)) + '</div>' +
        (ctx.self && !row.isMaster && !acc.locked ? '<p class="hint">A master turns Locked notes on for this device under Manage devices.</p>' : '');
    }
    body.innerHTML =
      '<div class="dev-me">' + (row.isMaster ? chip('master', '\u2605', 'Master login') + ' ' : '') + chip(row.status || 'active', (STATUS[row.status || 'active'] || STATUS.active)[0], (STATUS[row.status || 'active'] || STATUS.active)[1]) + '</div>' + ackLine +
      '<h3 class="dev-h">Device info</h3>' +
      '<dl class="dev-facts">' + facts.map((f) => '<dt>' + esc(f[0]) + '</dt><dd>' + esc(f[1]) + '</dd>').join('') + '</dl>' +
      accessBlock +
      '<h3 class="dev-h">Logins</h3><div class="btn-row dev-wrap"><button type="button" class="btn btn-ghost" data-a="log">See this device\u2019s activity log</button></div>' +
      (canAct ? '<h3 class="dev-h">Actions</h3><div class="btn-row dev-wrap">' +
        (row.isMaster ? '' : '<button class="btn btn-ghost" data-a="terminate">Sign out</button>') +
        (row.status === 'blocked' ? '<button class="btn btn-ghost" data-a="allow">Allow again</button>' : row.isMaster ? '' : '<button class="btn btn-danger" data-a="block">Block</button>') +
        (row.status === 'blocked' ? '' : '<button class="btn btn-danger" data-a="forget">Forget</button>') + '</div>' +
        '<p class="hint">Sign out ends this device\u2019s current login once; it can sign in again. Block stops it signing in until you allow it. Both can also erase the notes saved on that device. Forget removes it and its history from the list.' + (row.isMaster ? ' A device logged in as master can\u2019t be signed out or blocked, because it could undo that: use Replace master key first.' : '') + '</p>' : '');
    const done = async (msg) => { say(msg); await openManager(); closeOverlay('ks-ov-device'); };
    const saveBtn = body.querySelector('#ks-acc-save');
    if (saveBtn) {
      const nBox = body.querySelector('#ks-acc-notes'), lBox = body.querySelector('#ks-acc-locked');
      const dirty = () => { saveBtn.disabled = nBox.checked === !!acc.notes && lBox.checked === !!acc.locked; };
      nBox.onchange = dirty; lBox.onchange = dirty;
    }
    let inFlight = false;
    const setBusy = (busyNow) => {
      inFlight = busyNow;
      body.querySelectorAll('[data-a]').forEach((el) => {
        if (el.dataset.a === 'log') return;
        if (busyNow) {
          el.dataset.prevDisabled = el.disabled ? '1' : '';
          el.disabled = true;
        } else if (el.id === 'ks-acc-save') {
          const nBox = body.querySelector('#ks-acc-notes'), lBox = body.querySelector('#ks-acc-locked');
          el.disabled = !!(nBox && lBox && nBox.checked === !!acc.notes && lBox.checked === !!acc.locked);
        } else {
          el.disabled = el.dataset.prevDisabled === '1';
        }
      });
    };
    body.onclick = (e) => {
      const b = e.target.closest('[data-a]'); if (!b) return;
      const a = b.dataset.a, nm = rec.name || 'this device';
      if (inFlight && a !== 'log') return;
      const run = (fn, msg) => async () => {
        if (inFlight) return;
        setBusy(true);
        try { await fn(); await done(msg); } catch (err) { say(err.message); } finally { setBusy(false); }
      };
      if (a === 'log') openLog(id).catch((err) => say(err.message));
      else if (a === 'access') {
        const want = { notes: body.querySelector('#ks-acc-notes').checked, locked: body.querySelector('#ks-acc-locked').checked };
        const apply = async () => {
          if (inFlight) return;
          setBusy(true);
          try { await setAccess(id, want); await done('Saved: ' + nm + ' opens ' + (want.notes && want.locked ? 'notes and locked notes' : want.notes ? 'notes only' : want.locked ? 'locked notes only' : 'nothing')); }
          catch (err) { say(err.message); } finally { setBusy(false); }
        };
        if (!want.notes && !want.locked) ask('Switch off everything for ' + nm + '?', 'It will show no notes at all until you switch something back on. Its saved copies of them are removed from that device.', apply, 'Switch off', true);
        else apply();
      }
      else if (a === 'terminate') wipeDialog('Sign out ' + nm + '?', 'It is signed out the next time it opens the app or checks in, and the Backblaze key is removed from it. It can sign in again.', 'Sign out', false, (wipe) => {
        const go = run(() => command(id, 'terminate', { wipe }), wipe ? 'Sign-out sent; saved notes will be erased' : 'Sign-out sent');
        if (wipe) ask('Erase ' + nm + '\u2019s saved notes?', 'Last check: the notes, photos, audio, video and unsent edits saved on that device will be deleted when it next checks in. This can\u2019t be undone. Your notes in the bucket stay.', go, 'Yes, sign out and erase');
        else go();
      });
      else if (a === 'block') wipeDialog('Block ' + nm + '?', 'It is signed out and cannot sign in again until you allow it. This stops the app on that device; if you think the Backblaze key itself has leaked, also make a new key in Backblaze.', 'Block', true, (wipe) =>
        ask('Block ' + nm + ' for real?', 'Last check: ' + nm + ' will be refused every time it tries to sign in until you allow it again.' + (wipe ? ' Its saved notes, photos, audio, video and unsent edits will also be erased, which can\u2019t be undone.' : ''), run(() => command(id, 'block', { wipe }), wipe ? 'Blocked; saved notes will be erased' : 'Blocked'), wipe ? 'Yes, block and erase' : 'Yes, block it'));
      else if (a === 'allow') run(() => command(id, 'allow', {}), 'Allowed again')();
      else if (a === 'forget') askTwice('Forget ' + nm + '?', 'Its record and login history are deleted from the bucket. If it is still allowed in, it appears again as a new device the next time it opens.', 'Delete ' + nm + '\u2019s history?', 'Last check: its record and every login ever logged for it are deleted from the bucket. This can\u2019t be undone.', run(() => forget(id), 'Forgotten'), 'Forget', 'Yes, forget it');
    };
  }

  function showLock() {
    const st = getState().lock;
    if (!st || !doc().body) return;
    const blocked = st.kind === 'blocked';
    const body = shell('ks-ov-lock', blocked ? 'This device is blocked' : 'This device was signed out', false);
    doc().getElementById('ks-ov-lock').style.zIndex = 'var(--z-lock, 9999)';
    doc().getElementById('ks-ov-lock').style.background = 'var(--card-2, #F3EFE6)';
    const close = doc().querySelector('#ks-ov-lock .icon-btn'); if (close) close.remove();
    body.innerHTML = '<p>' + (blocked ? 'A master has blocked this device. Its Backblaze key has been removed.' : 'A master signed this device out. Its Backblaze key has been removed.') + (st.wiped ? ' The notes saved on it were erased.' : '') + '</p>' +
      '<p class="hint">' + esc(fmt(st.at)) + (st.by ? ' \u00b7 by ' + esc(st.by) : '') + (st.note ? ' \u00b7 \u201c' + esc(st.note) + '\u201d' : '') + '</p>' +
      '<div class="btn-row dev-actions"><button class="btn btn-primary" id="ks-lock-signin">' + (blocked ? 'Try signing in again' : 'Sign in again') + '</button></div>' +
      (blocked ? '<p class="hint">If a master has allowed this device again, signing in works. Otherwise it is refused and the attempt is recorded.</p>' : '');
    body.querySelector('#ks-lock-signin').onclick = () => {
      closeOverlay('ks-ov-lock');
      if (root.openSettings) root.openSettings();
      const settingsOv = doc().getElementById('overlay-settings');
      if (settingsOv) {
        const obs = new MutationObserver(() => {
          if (settingsOv.classList.contains('hidden')) {
            obs.disconnect();
            if (getState().lock) showLock();
          }
        });
        obs.observe(settingsOv, { attributes: true, attributeFilter: ['class'] });
      }
    };
    openOverlay('ks-ov-lock');
  }

  /* --------------------------------------------------------------- start-up */

  runPendingWipe();
  if (root.addEventListener) {
    root.addEventListener('storage', (e) => {
      if (e.key !== LS.state) return;
      let prev = {}, next = {};
      try { prev = JSON.parse(e.oldValue || '{}') || {}; } catch (_) {}
      try { next = JSON.parse(e.newValue || '{}') || {}; } catch (_) {}
      if (next.lock) showLock();
      else if (prev.lock && !next.lock) closeOverlay('ks-ov-lock');
      if (!!prev.masterSession !== !!next.masterSession) masterChanged();
      const pAcc = prev.access || null, nAcc = next.access || null;
      const accChanged = (!!pAcc !== !!nAcc) || (pAcc && nAcc && (!!pAcc.notes !== !!nAcc.notes || !!pAcc.locked !== !!nAcc.locked)) || prev.hasMaster !== next.hasMaster || (!!prev.masterSession !== !!next.masterSession);
      if (accChanged) {
        try { root.dispatchEvent(new root.CustomEvent('ks-access-changed', { detail: access() })); } catch (_) { /* UI only */ }
      }
    });
  }
  if (root.document) {
    const ready = () => { if (getState().lock) showLock(); };
    if (root.document.readyState === 'loading') root.document.addEventListener('DOMContentLoaded', ready); else ready();
  }

  root.KSDevices = {
    start, afterConnect, failedAttempt, renderSettings, nameDialog, poll, openLog,
    locked: () => !!getState().lock,
    isMaster: () => !!getState().masterSession,
    // What this device may open (set by a master). allows(meta) is true when a note of that kind may be shown here.
    access, allows,
    _test: { setAccess, accessFor, policyText, policyValid, commitAccess, checkIn, poll, command, forget, rename, listDevices, loadLog, adoptMasterKey, getIdentity, readMaster, parseAgent, summarize, importMasterText, exportMasterText, makeMasterPair, keyMatches, createMaster, loginMaster, logoutMaster, changePassword, replaceMasterKey, setLegacyPassword, setKV: (x) => { kv = x; }, setRaceMs: (n) => { raceMs = n; }, getState, setState, verify, sign, cmdText, claimText, b64, unb64 },
  };
})(typeof window !== 'undefined' ? window : globalThis);
