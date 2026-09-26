/**
 * Keepsake Worker
 *
 * Bindings expected (see wrangler.toml):
 *   NOTES_KV      — Workers KV namespace: note metadata + the password-2 vault
 *   NOTES_BUCKET  — R2 bucket: note content (plain or encrypted)
 *   API_TOKEN     — secret: shared bearer token the frontend authenticates with
 *
 * Data layout:
 *   KV   meta:{id}   -> { id, createdAt, updatedAt, lockType, unlockAt, title, preview }
 *   KV   vault:{id}  -> password2 string (time-locked notes only)
 *   R2   notes/{id}.json -> plain {title, body, images} OR encrypted {salt, iv, ciphertext}
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

async function handleCreate(request, env) {
  const body = await request.json();
  const id = crypto.randomUUID();
  const now = Date.now();
  const meta = metaFromBody(null, { ...body, id }, now);

  await env.NOTES_BUCKET.put(`notes/${id}.json`, JSON.stringify(body.content));
  await env.NOTES_KV.put(`meta:${id}`, JSON.stringify(meta));

  if (meta.lockType === 'time' && body.password2) {
    await env.NOTES_KV.put(`vault:${id}`, body.password2);
  }

  return json({ note: meta }, 201);
}

async function handleUpdate(request, env, id, existingMeta) {
  const body = await request.json();
  const now = Date.now();
  const meta = metaFromBody(existingMeta, body, now);

  await env.NOTES_BUCKET.put(`notes/${id}.json`, JSON.stringify(body.content));
  await env.NOTES_KV.put(`meta:${id}`, JSON.stringify(meta));

  if (meta.lockType === 'time' && body.password2) {
    await env.NOTES_KV.put(`vault:${id}`, body.password2);
  } else if (meta.lockType !== 'time') {
    await env.NOTES_KV.delete(`vault:${id}`);
  }

  return json({ note: meta });
}

async function handleDelete(env, id) {
  await env.NOTES_BUCKET.delete(`notes/${id}.json`);
  await env.NOTES_KV.delete(`meta:${id}`);
  await env.NOTES_KV.delete(`vault:${id}`);
  return json({ deleted: true });
}

async function handleGetOne(env, id, meta) {
  const obj = await env.NOTES_BUCKET.get(`notes/${id}.json`);
  if (!obj) return errorResponse('Note content missing', 404);
  const content = await obj.json();
  return json({ meta, content });
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
  const obj = await env.NOTES_BUCKET.get(`notes/${id}.json`);
  if (!obj) return errorResponse('Note content missing', 404);
  const content = await obj.json();

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

      const meta = await readMeta(env, id);
      if (!meta) return errorResponse('Not found', 404);

      if (!sub) {
        if (request.method === 'GET') return handleGetOne(env, id, meta);
        if (request.method === 'PUT') return handleUpdate(request, env, id, meta);
        if (request.method === 'DELETE') return handleDelete(env, id);
        return errorResponse('Method not allowed', 405);
      }

      if (sub === 'vault' && request.method === 'GET') return handleVault(env, id, meta);
      if (sub === 'export' && request.method === 'GET') return handleExport(env, id, meta);

      return errorResponse('Not found', 404);
    } catch (err) {
      return errorResponse('Server error: ' + err.message, 500);
    }
  },
};
