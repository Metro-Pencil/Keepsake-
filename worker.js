/**
 * Keepsake Worker
 *
 * Bindings expected (see wrangler.toml):
 *   NOTES_KV   — Workers KV namespace: note content, metadata, and the password-2 vault
 *   API_TOKEN  — secret: shared bearer token the frontend authenticates with
 *
 * Data layout (all in the one KV namespace):
 *   meta:{id}    -> { id, createdAt, updatedAt, lockType, unlockAt, title, preview }
 *   content:{id} -> plain {title, body, images} OR encrypted {salt, iv, ciphertext}
 *   vault:{id}   -> password2 string (time-locked notes only)
 *
 * No R2 bucket, no payment method required on the Cloudflare account — KV's
 * free tier needs neither. Each value (a note's content) is capped at 25MB,
 * which comfortably fits long text plus a handful of compressed photos.
 */

const JSON_HEADERS = { 'Content-Type': 'application/json' };

function withCors(resp) {
  resp.headers.set('Access-Control-Allow-Origin', '*');
  resp.headers.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
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

async function readMeta(env, id) {
  const raw = await env.NOTES_KV.get(`meta:${id}`);
  return raw ? JSON.parse(raw) : null;
}

function metaFromBody(existing, body, now) {
  const lockType = body.lockType === 'quick' || body.lockType === 'time' ? body.lockType : 'none';
  return {
    id: existing ? existing.id : body.id,
    createdAt: existing ? existing.createdAt : now,
    updatedAt: now,
    lockType,
    unlockAt: lockType === 'time' ? (body.unlockAt || null) : null,
    title: lockType === 'none' ? String(body.title || '') : null,
    preview: lockType === 'none' ? String(body.preview || '') : null,
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
async function upsertNote(env, id, body) {
  const now = Date.now();
  const existing = await readMeta(env, id);
  const meta = metaFromBody(existing, { ...body, id }, now);

  await env.NOTES_KV.put(`content:${id}`, JSON.stringify(body.content));
  await env.NOTES_KV.put(`meta:${id}`, JSON.stringify(meta));

  if (meta.lockType === 'time' && body.password2) {
    await env.NOTES_KV.put(`vault:${id}`, body.password2);
  } else if (meta.lockType !== 'time') {
    await env.NOTES_KV.delete(`vault:${id}`);
  }

  return json({ note: meta }, existing ? 200 : 201);
}

async function handleCreate(request, env) {
  const body = await request.json();
  const id = typeof body.id === 'string' && UUID_RE.test(body.id) ? body.id : crypto.randomUUID();
  return upsertNote(env, id, body);
}

async function handleUpdate(request, env, id) {
  const body = await request.json();
  return upsertNote(env, id, body);
}

async function handleDelete(env, id) {
  await env.NOTES_KV.delete(`content:${id}`);
  await env.NOTES_KV.delete(`meta:${id}`);
  await env.NOTES_KV.delete(`vault:${id}`);
  return json({ deleted: true });
}

async function handleGetOne(env, id, meta) {
  const raw = await env.NOTES_KV.get(`content:${id}`);
  if (raw === null) return errorResponse('Note content missing', 404);
  return json({ meta, content: JSON.parse(raw) });
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
  const content = JSON.parse(raw);

  let password2 = null;
  if (meta.lockType === 'time') {
    password2 = await env.NOTES_KV.get(`vault:${id}`);
  }

  return json({
    meta,
    content,
    password2,
    _hint: password2
      ? 'password2 is the value above. Combine it with your own password to open this note before its unlock date.'
      : undefined,
  });
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return withCors(new Response(null, { status: 204 }));
    }

    if (!isAuthorized(request, env)) {
      return errorResponse('Unauthorized', 401);
    }

    const url = new URL(request.url);
    const parts = url.pathname.split('/').filter(Boolean); // ['api', 'notes', id?, sub?]

    if (parts[0] !== 'api' || parts[1] !== 'notes') {
      return errorResponse('Not found', 404);
    }

    const id = parts[2];
    const sub = parts[3];

    try {
      if (!id) {
        if (request.method === 'GET') return json({ notes: await listNotes(env) });
        if (request.method === 'POST') return handleCreate(request, env);
        return errorResponse('Method not allowed', 405);
      }

      if (!sub) {
        // PUT is an upsert — it doesn't need the note to already exist, so
        // it's the one method that skips the readMeta/404 check below. This
        // is what lets the frontend always PUT to an id it generated itself,
        // whether this is the note's first save or its fiftieth.
        if (request.method === 'PUT') return handleUpdate(request, env, id);

        const meta = await readMeta(env, id);
        if (!meta) return errorResponse('Not found', 404);
        if (request.method === 'GET') return handleGetOne(env, id, meta);
        if (request.method === 'DELETE') return handleDelete(env, id);
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
