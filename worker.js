/**
 * Keepsake Worker
 *
 * Bindings expected (see wrangler.toml):
 *   NOTES_KV   — Workers KV namespace: note content, metadata, and the password-2 vault
 *   API_TOKEN  — secret: shared bearer token the frontend authenticates with
 *
 * Optional — Backblaze B2 for photos and audio (omit all four and the app keeps
 * storing media inside the notes, with the 25 MB-per-note limit):
 *   B2_ENDPOINT — var:    S3 endpoint host, e.g. s3.us-west-004.backblazeb2.com
 *   B2_BUCKET   — var:    bucket name
 *   B2_KEY_ID   — secret: application key ID
 *   B2_APP_KEY  — secret: application key
 *
 * Data layout (all in the one KV namespace):
 *   meta:{id}    -> { id, createdAt, updatedAt, lockType, unlockAt, title, preview }
 *                   (title is plain text even for locked notes; preview is null for them)
 *   content:{id} -> plain {title, body, html?, images, drawing?} OR encrypted {salt, iv, ciphertext}
 *   vault:{id}   -> password2 string (time-locked notes only)
 *
 * No R2 bucket, no payment method required on the Cloudflare account — KV's
 * free tier needs neither. Each value (a note's content) is capped at 25MB.
 * With B2 configured, a note's photos and audio live in the bucket instead
 * (media/{noteId}/{name}) and the note only keeps small references to them.
 * The browser never talks to B2 directly: every byte goes through this Worker,
 * so the bucket stays private and needs no CORS rules.
 */

const JSON_HEADERS = { 'Content-Type': 'application/json' };

function withCors(resp) {
  resp.headers.set('Access-Control-Allow-Origin', '*');
  resp.headers.set('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-Content-SHA256');
  resp.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  return resp;
}

function json(data, status = 200) {
  return withCors(new Response(JSON.stringify(data), { status, headers: JSON_HEADERS }));
}

function errorResponse(message, status) {
  return json({ error: message }, status);
}

function isAuthorized(request, env) {
  const header = request.headers.get('Authorization') || '';
  const match = header.match(/^Bearer\s+(.+)$/i);
  const token = match ? match[1] : '';
  return Boolean(token) && Boolean(env.API_TOKEN) && token === env.API_TOKEN;
}

/* ---------------------------------------------------------------------
 * Backblaze B2 (S3-compatible API), signed with AWS Signature V4.
 * ------------------------------------------------------------------- */

const NAME_RE = /^[a-f0-9]{32}$/;           // a media object's name inside its note's folder
const SHA_RE = /^[a-f0-9]{64}$/;
const EMPTY_SHA = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const MAX_MEDIA_BYTES = 90 * 1024 * 1024;   // one photo/clip; the Free plan caps a request body at 100 MB
const ORPHAN_GRACE_MS = 60 * 60 * 1000;     // an unreferenced upload is only swept after an hour
const textEnc = new TextEncoder();

function b2Enabled(env) {
  return Boolean(env.B2_KEY_ID && env.B2_APP_KEY && env.B2_ENDPOINT && env.B2_BUCKET);
}

function toHex(buf) {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
}

async function hmacSha256(keyBytes, data) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, textEnc.encode(data)));
}

async function sha256Hex(str) {
  return toHex(await crypto.subtle.digest('SHA-256', textEnc.encode(str)));
}

// RFC 3986 percent-encoding, which is what SigV4 wants (encodeURIComponent
// leaves ! ' ( ) * alone).
function uriEncode(s) {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

// Builds the headers for one signed S3 request. `headers` are extra headers to
// sign (lower-case names); host, x-amz-content-sha256 and x-amz-date are added.
async function signV4({ method, host, path, query, payloadHash, region, keyId, secret, amzDate, headers }) {
  const date = amzDate.slice(0, 8);
  const all = { ...(headers || {}), host, 'x-amz-content-sha256': payloadHash, 'x-amz-date': amzDate };
  const names = Object.keys(all).sort();
  const canonicalHeaders = names.map((n) => n + ':' + String(all[n]).trim() + '\n').join('');
  const signedHeaders = names.join(';');
  const canonicalPath = path.split('/').map(uriEncode).join('/');
  const canonicalQuery = Object.keys(query || {})
    .map((k) => [uriEncode(k), uriEncode(query[k])])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([k, v]) => k + '=' + v)
    .join('&');
  const canonicalRequest = [method, canonicalPath, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash].join('\n');
  const scope = `${date}/${region}/s3/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, await sha256Hex(canonicalRequest)].join('\n');
  let k = await hmacSha256(textEnc.encode('AWS4' + secret), date);
  k = await hmacSha256(k, region);
  k = await hmacSha256(k, 's3');
  k = await hmacSha256(k, 'aws4_request');
  const signature = toHex(await hmacSha256(k, stringToSign));
  return {
    amzDate,
    canonicalQuery,
    canonicalPath,
    authorization: `AWS4-HMAC-SHA256 Credential=${keyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}

function nowAmzDate() {
  return new Date().toISOString().replace(/[:-]|\.\d{3}/g, ''); // 20260101T120000Z
}

// Tolerates "https://s3.us-west-004.backblazeb2.com/" pasted with the scheme or a trailing slash.
function b2Host(env) {
  return String(env.B2_ENDPOINT || '').trim().replace(/^https?:\/\//i, '').replace(/\/+$/, '');
}

function b2Region(env) {
  const m = /^s3\.([a-z0-9-]+)\.backblazeb2\.com$/i.exec(b2Host(env));
  return m ? m[1] : 'us-west-004';
}

// One signed request to the bucket. `key` is the object key ('' for the bucket itself).
async function b2Fetch(env, method, key, { query = {}, payloadHash = EMPTY_SHA, body } = {}) {
  const host = b2Host(env);
  const path = '/' + env.B2_BUCKET + (key ? '/' + key : '');
  const signed = await signV4({
    method, host, path, query, payloadHash,
    region: b2Region(env), keyId: env.B2_KEY_ID, secret: env.B2_APP_KEY,
    amzDate: nowAmzDate(),
  });
  const url = 'https://' + host + signed.canonicalPath + (signed.canonicalQuery ? '?' + signed.canonicalQuery : '');
  const init = {
    method,
    headers: {
      'x-amz-date': signed.amzDate,
      'x-amz-content-sha256': payloadHash,
      'Authorization': signed.authorization,
    },
  };
  if (body !== undefined) init.body = body;
  return fetch(url, init);
}

function xmlUnescape(s) {
  return s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
}

async function b2Message(res) {
  try {
    const t = await res.text();
    const m = /<Message>([\s\S]*?)<\/Message>/.exec(t);
    return m ? xmlUnescape(m[1]) : t.slice(0, 200);
  } catch (e) { return ''; }
}

// Lists a note's media: [{ name, size, modified }]
async function b2List(env, noteId) {
  const prefix = `media/${noteId}/`;
  const items = [];
  let token = null;
  for (let page = 0; page < 5; page++) {
    const query = { 'list-type': '2', prefix, 'max-keys': '1000' };
    if (token) query['continuation-token'] = token;
    const res = await b2Fetch(env, 'GET', '', { query });
    if (!res.ok) throw new Error('Backblaze list failed (' + res.status + '): ' + await b2Message(res));
    const xml = await res.text();
    for (const m of xml.matchAll(/<Contents>([\s\S]*?)<\/Contents>/g)) {
      const key = /<Key>([\s\S]*?)<\/Key>/.exec(m[1]);
      const size = /<Size>(\d+)<\/Size>/.exec(m[1]);
      const mod = /<LastModified>([\s\S]*?)<\/LastModified>/.exec(m[1]);
      if (!key) continue;
      const name = xmlUnescape(key[1]).slice(prefix.length);
      if (!NAME_RE.test(name)) continue;
      items.push({ name, size: size ? Number(size[1]) : 0, modified: mod ? Date.parse(mod[1]) || 0 : 0 });
    }
    if (/<IsTruncated>true<\/IsTruncated>/.test(xml)) {
      const t = /<NextContinuationToken>([\s\S]*?)<\/NextContinuationToken>/.exec(xml);
      token = t ? xmlUnescape(t[1]) : null;
      if (!token) break;
    } else break;
  }
  return items;
}

async function b2Delete(env, noteId, names) {
  let n = 0;
  for (const name of names) {
    const res = await b2Fetch(env, 'DELETE', `media/${noteId}/${name}`);
    if (res.ok || res.status === 404) n++;
  }
  return n;
}

// Deletes uploads no saved version of the note refers to any more (a photo
// removed from the note, a re-encrypted copy, an abandoned upload). Anything
// younger than an hour is left alone so a save still in flight can't lose the
// files it is about to reference. Capped to stay inside the Free plan's
// 50-subrequest limit; whatever is left is caught by the next save.
async function pruneMedia(env, noteId, keepNames) {
  const keep = new Set(keepNames);
  const cutoff = Date.now() - ORPHAN_GRACE_MS;
  const stale = (await b2List(env, noteId)).filter((i) => !keep.has(i.name) && i.modified < cutoff);
  return b2Delete(env, noteId, stale.slice(0, 20).map((i) => i.name));
}

async function deleteAllMedia(env, noteId) {
  const all = await b2List(env, noteId);
  return b2Delete(env, noteId, all.slice(0, 40).map((i) => i.name));
}

function later(ctx, promise) {
  const safe = promise.catch(() => {}); // cleanup must never fail the request that triggered it
  if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(safe);
  return safe;
}

async function handleMediaPut(request, env, noteId, name) {
  if (!b2Enabled(env)) return errorResponse('Backblaze is not set up on this Worker', 501);
  const len = Number(request.headers.get('Content-Length'));
  if (!Number.isInteger(len) || len <= 0) return errorResponse('Missing Content-Length', 411);
  if (len > MAX_MEDIA_BYTES) return errorResponse('File is over the 90 MB limit', 413);
  const sha = String(request.headers.get('X-Content-SHA256') || '').toLowerCase();
  if (!SHA_RE.test(sha)) return errorResponse('Missing X-Content-SHA256', 400);
  if (!request.body) return errorResponse('Empty body', 400);

  // The body streams straight through to B2 without being held in memory.
  // Backblaze checks it against the hash the browser computed and signed.
  let body = request.body;
  if (typeof FixedLengthStream === 'function') {
    const fixed = new FixedLengthStream(len);
    request.body.pipeTo(fixed.writable).catch(() => {});
    body = fixed.readable;
  }
  const res = await b2Fetch(env, 'PUT', `media/${noteId}/${name}`, { payloadHash: sha, body });
  if (!res.ok) return errorResponse('Backblaze rejected the upload (' + res.status + '): ' + await b2Message(res), 502);
  return json({ ok: true, name, size: len });
}

async function handleMediaGet(env, noteId, name) {
  if (!b2Enabled(env)) return errorResponse('Backblaze is not set up on this Worker', 501);
  const res = await b2Fetch(env, 'GET', `media/${noteId}/${name}`);
  if (res.status === 404) return errorResponse('Media not found', 404);
  if (!res.ok) return errorResponse('Backblaze error (' + res.status + '): ' + await b2Message(res), 502);
  const headers = { 'Content-Type': 'application/octet-stream', 'Cache-Control': 'private, max-age=31536000, immutable' };
  const length = res.headers.get('Content-Length');
  if (length) headers['Content-Length'] = length;
  return withCors(new Response(res.body, { status: 200, headers }));
}

async function handleMediaList(env, noteId) {
  if (!b2Enabled(env)) return errorResponse('Backblaze is not set up on this Worker', 501);
  return json({ items: await b2List(env, noteId) });
}

async function readMeta(env, id) {
  const raw = await env.NOTES_KV.get(`meta:${id}`);
  return raw ? JSON.parse(raw) : null;
}

function metaFromBody(existing, body, now, size) {
  const lockType = body.lockType === 'quick' || body.lockType === 'time' ? body.lockType : 'none';
  return {
    id: existing ? existing.id : body.id,
    createdAt: existing ? existing.createdAt : now,
    updatedAt: now,
    lockType,
    unlockAt: lockType === 'time' ? (body.unlockAt || null) : null,
    // The title is stored in plain text for every note, locked or not, so a
    // locked note can be recognised on its card on any device. Only the
    // preview (a slice of the body) stays plain for unlocked notes alone —
    // a locked note's text, photos and drawing are encrypted client-side.
    title: String(body.title || '').slice(0, 200),
    preview: lockType === 'none' ? String(body.preview || '') : null,
    // How big the stored content is (characters of its JSON, which is bytes for
    // everything but non-Latin text). The app adds these up for its storage
    // meter. Optional: notes saved before this was added simply don't have it.
    size: Number.isFinite(size) ? size : undefined,
    // Bytes of photos/audio kept in Backblaze for this note (as stored there,
    // so encrypted size for a locked note). Absent for notes that keep their
    // media inline. The app adds these up for its second storage meter.
    mediaSize: Number.isFinite(body.mediaBytes) && body.mediaBytes > 0 ? Math.floor(body.mediaBytes) : undefined,
  };
}

async function listNotes(env) {
  const notes = [];
  let cursor;
  do {
    const page = await env.NOTES_KV.list({ prefix: 'meta:', cursor });
    for (const key of page.keys) {
      const raw = await env.NOTES_KV.get(key.name);
      if (raw) notes.push(JSON.parse(raw));
    }
    cursor = page.cursor;
  } while (cursor);
  notes.sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
  return notes;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Create and update now share one idempotent path: the id always comes from
// the client (the frontend generates it once, up front, the moment a note
// starts being edited), and saving twice with the same id is just a
// second write to the same keys — never a second note. This is what makes
// it safe for the frontend to retry a save that appeared to fail (flaky
// connection, etc.) or to autosave in the background without any risk of
// duplicate notes, regardless of how many times "save" fires.
async function upsertNote(env, id, body, ctx) {
  const now = Date.now();
  if (body.content === undefined || body.content === null) return errorResponse('Missing content', 400);
  const existing = await readMeta(env, id);
  const contentJSON = JSON.stringify(body.content);
  const meta = metaFromBody(existing, { ...body, id }, now, contentJSON.length);

  await env.NOTES_KV.put(`content:${id}`, contentJSON);
  await env.NOTES_KV.put(`meta:${id}`, JSON.stringify(meta));

  if (meta.lockType === 'time' && body.password2) {
    await env.NOTES_KV.put(`vault:${id}`, body.password2);
  } else if (meta.lockType !== 'time') {
    await env.NOTES_KV.delete(`vault:${id}`);
  }

  // The save lists every media file it refers to. Anything else stored for
  // this note is an orphan and is swept (after a grace period, see pruneMedia).
  if (Array.isArray(body.mediaKeep) && b2Enabled(env)) {
    const keep = body.mediaKeep.filter((n) => typeof n === 'string' && NAME_RE.test(n)).slice(0, 500);
    await later(ctx, pruneMedia(env, id, keep));
  }

  return json({ note: meta }, existing ? 200 : 201);
}

async function handleCreate(request, env, ctx) {
  const body = await request.json();
  const id = typeof body.id === 'string' && UUID_RE.test(body.id) ? body.id : crypto.randomUUID();
  return upsertNote(env, id, body, ctx);
}

async function handleUpdate(request, env, id, ctx) {
  const body = await request.json();
  return upsertNote(env, id, body, ctx);
}

async function handleDelete(env, id, ctx) {
  await env.NOTES_KV.delete(`content:${id}`);
  await env.NOTES_KV.delete(`meta:${id}`);
  await env.NOTES_KV.delete(`vault:${id}`);
  if (b2Enabled(env)) await later(ctx, deleteAllMedia(env, id));
  return json({ deleted: true });
}

async function handleGetOne(env, id, meta) {
  const raw = await env.NOTES_KV.get(`content:${id}`);
  if (raw === null) return errorResponse('Note content missing', 404);
  // `raw` is already JSON, so splice it into the response instead of parsing and
  // re-serialising it — noticeably less CPU and memory for a note with photos
  // or audio (the Free plan allows only 10 ms of CPU per request).
  return withCors(new Response('{"meta":' + JSON.stringify(meta) + ',"content":' + raw + '}', { status: 200, headers: JSON_HEADERS }));
}

async function handleVault(env, id, meta) {
  if (meta.lockType !== 'time') return errorResponse('Not a time-locked note', 400);
  if (!meta.unlockAt || Date.now() < meta.unlockAt) {
    return errorResponse('Still locked', 403);
  }
  const password2 = await env.NOTES_KV.get(`vault:${id}`);
  return json({ password2 });
}

async function handleExport(env, id, meta) {
  const raw = await env.NOTES_KV.get(`content:${id}`);
  if (raw === null) return errorResponse('Note content missing', 404);
  let password2 = null;
  if (meta.lockType === 'time') {
    password2 = await env.NOTES_KV.get(`vault:${id}`);
  }

  const hint = password2
    ? 'password2 is the value above. Combine it with your own password to open this note before its unlock date.'
    : null;
  return withCors(new Response(
    '{"meta":' + JSON.stringify(meta) + ',"content":' + raw + ',"password2":' + JSON.stringify(password2) +
      (hint ? ',"_hint":' + JSON.stringify(hint) : '') + '}',
    { status: 200, headers: JSON_HEADERS }
  ));
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return withCors(new Response(null, { status: 204 }));
    }

    if (!isAuthorized(request, env)) {
      return errorResponse('Unauthorized', 401);
    }

    const url = new URL(request.url);
    const parts = url.pathname.split('/').filter(Boolean); // ['api', 'notes', id?, sub?]

    if (parts[0] === 'api' && parts[1] === 'media-config' && request.method === 'GET') {
      return json({ enabled: b2Enabled(env), maxBytes: MAX_MEDIA_BYTES });
    }

    if (parts[0] === 'api' && parts[1] === 'media') {
      const noteId = parts[2];
      const name = parts[3];
      if (!noteId || !UUID_RE.test(noteId)) return errorResponse('Bad note id', 400);
      try {
        if (!name) {
          if (request.method === 'GET') return await handleMediaList(env, noteId);
          return errorResponse('Method not allowed', 405);
        }
        if (!NAME_RE.test(name)) return errorResponse('Bad media name', 400);
        if (request.method === 'PUT') return await handleMediaPut(request, env, noteId, name);
        if (request.method === 'GET') return await handleMediaGet(env, noteId, name);
        return errorResponse('Method not allowed', 405);
      } catch (err) {
        return errorResponse('Server error: ' + err.message, 500);
      }
    }

    if (parts[0] !== 'api' || parts[1] !== 'notes') {
      return errorResponse('Not found', 404);
    }

    const id = parts[2];
    const sub = parts[3];

    try {
      if (!id) {
        if (request.method === 'GET') return json({ notes: await listNotes(env) });
        if (request.method === 'POST') return handleCreate(request, env, ctx);
        return errorResponse('Method not allowed', 405);
      }

      if (!sub) {
        // PUT is an upsert — it doesn't need the note to already exist, so
        // it's the one method that skips the readMeta/404 check below. This
        // is what lets the frontend always PUT to an id it generated itself,
        // whether this is the note's first save or its fiftieth.
        if (request.method === 'PUT') return handleUpdate(request, env, id, ctx);

        const meta = await readMeta(env, id);
        if (!meta) return errorResponse('Not found', 404);
        if (request.method === 'GET') return handleGetOne(env, id, meta);
        if (request.method === 'DELETE') return handleDelete(env, id, ctx);
        return errorResponse('Method not allowed', 405);
      }

      const meta = await readMeta(env, id);
      if (!meta) return errorResponse('Not found', 404);

      if (sub === 'vault' && request.method === 'GET') return handleVault(env, id, meta);
      if (sub === 'export' && request.method === 'GET') return handleExport(env, id, meta);

      return errorResponse('Not found', 404);
    } catch (err) {
      return errorResponse('Server error: ' + err.message, 500);
    }
  },
};
