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
index.html, app.js, manifest.json, sw.js, icon-192.png, icon-512.png
worker.js, wrangler.toml
```

Everything sits in one flat folder — no subfolders to deal with in GitHub.
`worker.js` and `wrangler.toml` are only there for you to copy from when
setting up Cloudflare; GitHub Pages will happily ignore them since nothing
links to them from the frontend.

The frontend is plain HTML/CSS/JS — no framework, no build step. It talks to
your own Worker over a small JSON API, authenticated with a bearer token you
set once.

## 1. Deploy the Worker

You'll need a Cloudflare account and `wrangler` (`npm install -g wrangler`,
or use `npx wrangler` for every command below).

```bash
wrangler kv namespace create NOTES_KV
```

Copy the `id` it prints into `wrangler.toml`, replacing
`REPLACE_WITH_YOUR_KV_NAMESPACE_ID`.

```bash
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

Push everything in this folder **except** `worker.js` and `wrangler.toml`
(those two are only for Cloudflare, not the site) to a GitHub repo, then
turn on GitHub Pages (Settings → Pages) — or use any static host. Nothing
to build; if you'd rather not bother excluding the two Worker files, it's
also harmless to push all of it — Pages just serves the site files and
ignores the rest.

## 3. Point the app at your Worker

Open the deployed site, tap the gear icon, and fill in:

- **Worker URL** — the `*.workers.dev` address from step 1
- **Access token** — the exact string you gave `wrangler secret put API_TOKEN`

Both are stored only in that browser's local storage.

## Formatting and drawing

Notes support bold, italic, underline, headings and lists, and you can draw
straight over a note with the pen / highlighter tools (pencil-wave button in
the editor toolbar). Both are stored inside the note's content — formatting as
sanitized HTML next to the plain text, drawings as vector strokes — so locked
notes keep them encrypted along with everything else. Drawings are positioned
relative to the note's width; the text reflows but ink doesn't, so on a very
different screen width ink can drift slightly off the words it was drawn over.

## Offline

Keepsake keeps a copy of every note on the device (in IndexedDB), so the
list, reading, unlocking, downloading, writing, and deleting all work with
no connection. Changes made offline are queued and sent automatically once
you're back online; until then the note shows a "Not synced" tag and the
top bar shows an offline / not-synced indicator. Locked notes are cached in
their encrypted form, exactly as the server stores them. This is
last-write-wins: if you edit the same note on two devices while one is
offline, whichever syncs last overwrites the other.

## Limits worth knowing

- Everything lives in one Workers KV namespace — no R2 bucket, and no
  payment method needed on your Cloudflare account to set this up.
- Each note's content (text + all its photos combined) is capped at 25 MB,
  which is a KV hard limit. The app compresses photos client-side before
  upload, so this comfortably fits long entries plus a good handful of
  photos — but it's not built for huge files or dozens of full-resolution
  images on one note.
- Total free storage across your whole account is around 1 GB. Plenty of
  ordinary journaling, but worth knowing if you end up with a very large
  number of photo-heavy notes over time.
- There's no password recovery, by design — forgetting a note's password
  (or, for a time-locked note, both passwords) means that note is
  unrecoverable.

## If you want to change things later

- The frontend is deliberately framework-free: `index.html` + `app.js`, no
  bundler, so it's easy to read top to bottom.
- `app.js` is split out from `index.html` rather than inlined, since this app
  runs long — merge them back into one file if you'd rather keep to a strict
  single-file convention.
- Previews (a slice of the body) are only ever stored in plain text for
  *unlocked* notes — a locked note's content is never stored in plain text.
  The one exception is a locked note's *title*, which is stored in plain text
  so locked notes can be told apart on every device; its text, photos and
  drawing are encrypted. Don't put anything sensitive in the title of a locked
  note.
- All three pieces of data — a note's content, its metadata, and (for
  time-locked notes) the vaulted second password — live in the same KV
  namespace under `content:{id}`, `meta:{id}`, and `vault:{id}`. If you ever
  outgrow KV's 25MB-per-note or ~1GB-total ceiling, swapping the
  `content:{id}` reads/writes in `worker.js` for an R2 bucket is a small,
  contained change — the rest of the app doesn't need to know either way.
