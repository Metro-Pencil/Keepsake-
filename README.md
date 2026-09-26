# Keepsake

A private notebook: long-form notes with photos, where any individual note
can be locked. Two lock types:

- **Quick lock** — one password. Opens any time you enter it.
- **Time lock** — your password *plus* a second, auto-generated password.
  Once the unlock date passes, your password alone opens the note (the
  Worker releases the second password on its own). Before that date, the
  only way in is to download the note — the download button works on locked
  notes too — and look up the second password inside the downloaded file
  yourself, then enter both.

This is a deliberate-friction lock, not a hack-proof vault: nothing stops
you, the account holder, from bypassing it with enough effort. That's the
point — it's meant to slow down impulse, not defend against an attacker.

## What's in this repo

```
index.html, app.js, manifest.json, sw.js, icons/   → the frontend (static)
worker/worker.js, worker/wrangler.toml             → the Cloudflare Worker backend
```

The frontend is plain HTML/CSS/JS — no framework, no build step. It talks to
your own Worker over a small JSON API, authenticated with a bearer token you
set once.

## 1. Deploy the Worker

You'll need a Cloudflare account and `wrangler` (`npm install -g wrangler`,
or use `npx wrangler` for every command below).

```bash
cd worker
wrangler kv namespace create NOTES_KV
```

Copy the `id` it prints into `wrangler.toml`, replacing
`REPLACE_WITH_YOUR_KV_NAMESPACE_ID`.

```bash
wrangler r2 bucket create keepsake-notes
wrangler secret put API_TOKEN
```

When prompted, paste any long random string — this is the token the app
itself uses to authenticate with your Worker (nothing to do with your note
passwords). Keep it private; anyone with it can read your notes' metadata
and encrypted blobs.

```bash
wrangler deploy
```

Note the `https://keepsake-worker.<you>.workers.dev` URL it prints.

## 2. Host the frontend

Push `index.html`, `app.js`, `manifest.json`, `sw.js`, and `icons/` to a
GitHub repo and turn on GitHub Pages (Settings → Pages) — or use any static
host (Cloudflare Pages, Netlify, etc.). There's nothing to build.

## 3. Point the app at your Worker

Open the deployed site, tap the gear icon, and fill in:

- **Worker URL** — the `*.workers.dev` address from step 1
- **Access token** — the exact string you gave `wrangler secret put API_TOKEN`

Both are stored only in that browser's local storage.

## Limits worth knowing

- Each save (a note plus its photos) goes through the Worker as one request,
  capped at 100 MB on Cloudflare's free plan — plenty of headroom, and the
  app compresses photos client-side before upload to help.
- R2 objects can be up to 5 TiB each; the free tier includes 10 GB-months of
  storage and generous free request quotas, with downloads always free.
- There's no password recovery, by design — forgetting a note's password
  (or, for a time-locked note, both passwords) means that note is
  unrecoverable.

## If you want to change things later

- The frontend is deliberately framework-free: `index.html` + `app.js`, no
  bundler, so it's easy to read top to bottom.
- `app.js` is split out from `index.html` rather than inlined, since this app
  runs long — merge them back into one file if you'd rather keep to a strict
  single-file convention.
- Note titles and previews are only ever stored in plain text for *unlocked*
  notes — locked notes (either type) store no plaintext at all server-side.
