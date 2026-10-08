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
index.html, app.js, media.js, manifest.json, sw.js, icon-192.png, icon-512.png
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

## Backblaze B2 for photos and audio (optional)

By default a note's photos and audio live inside the note, which caps each note at
25 MB. Connect a Backblaze B2 bucket and they live in the bucket instead: each file can
be up to about 90 MB, a note can carry about 150 MB of them, and none of it counts toward
the 25 MB note limit or the 1 GB KV allowance. B2's free plan includes 10 GB.

Your browser never talks to Backblaze. It talks to your Worker, which signs the requests
with your bucket key, so the bucket stays **private** and needs **no CORS rules**.

Locked notes: before a photo or clip leaves the device it is encrypted with a random key
that is stored inside the note's own encrypted content. Backblaze only ever holds
ciphertext for those, and the note's two-password scheme protects the key exactly as it
protects the text. Unlocked notes' media is stored as it is.

### Set it up

1. In Backblaze, create a **Private** bucket (leave Object Lock off). Note its name and
   the S3 endpoint shown on its page (looks like `s3.us-west-004.backblazeb2.com`).
2. Backblaze → **Application Keys** → *Add a New Application Key*. Restrict it to that one
   bucket, with **Read and Write** access. Copy the **keyID** and **applicationKey**
   right away; the key is shown only once.
3. In `wrangler.toml`, fill in `B2_ENDPOINT` and `B2_BUCKET` under `[vars]`.
4. Add the two secrets, then redeploy:

   ```bash
   wrangler secret put B2_KEY_ID
   wrangler secret put B2_APP_KEY
   wrangler deploy
   ```

5. Open the app, then **Settings → Photos & audio storage**. It should say Backblaze is on
   (there is a switch to turn it off). Then add a photo to a note and save: the size
   meter stops counting it, and the file appears in your bucket under
   `media/<note id>/`.

Good to know:

- Notes saved before you turned this on keep their media inside until you next save them.
- Photos and audio are fetched when you open a note, then kept on the device (up to about
  300 MB, least-recently-used dropped first) so notes still open offline. A note saved
  offline holds its media on the device and uploads it when you are back online.
- Deleting a note deletes its files in the bucket. Removing a photo from a note and saving
  deletes it from the bucket within the hour. Do not put other files under `media/`.
- **Download** on a note includes its photos and audio (still encrypted for locked notes)
  in the file, so it remains a full backup.
- Free Worker plan limits still apply: one file per request is capped at 100 MB (the app
  stops at 90 MB), and an upload is a single request.
- Keep the application key private. Anyone who has it can read or delete your bucket.

## Formatting and drawing

Notes support bold, italic, underline, headings and lists, and you can draw
straight over a note with the pen / highlighter tools (pencil-wave button in
the editor toolbar). Both are stored inside the note's content — formatting as
sanitized HTML next to the plain text, drawings as vector strokes — so locked
notes keep them encrypted along with everything else. Drawings are positioned
relative to the note's width; the text reflows but ink doesn't, so on a very
different screen width ink can drift slightly off the words it was drawn over.

## Audio

Tap the microphone in the editor toolbar to record a clip, or attach an audio
file from your device. The clip is dropped in at your cursor, so it can sit
between two sentences or even between two words. Tap its play button to hear it
inline; the ⋯ button opens the clip on its own, where you can listen, **download
just that clip**, or delete it. Recorded clips are saved as the browser makes them
(WebM/Opus, or M4A on Safari); a file you attach is kept byte-for-byte, so
downloading it gives back exactly what you attached. In a locked note the audio is
encrypted with everything else. Recording needs HTTPS and microphone permission.

Photos and recordings have quality settings under **Settings → Media quality**
(photos: Standard / High / Original; recordings: Standard / High / Maximum). The
default for both is High. Higher quality means bigger notes, and **Original**
photos keep the picture's embedded location data.

## Offline

Keepsake keeps a copy of every note on the device (in IndexedDB), so the
list, reading, unlocking, downloading, writing, and deleting all work with
no connection. A note opens straight from that copy whenever it matches what the
server last reported (the list is refreshed on launch, after saves and when you come
back to the app), so opening doesn't wait on the network. Changes made offline are queued and sent automatically once
you're back online; until then the note shows a "Not synced" tag and the
top bar shows an offline / not-synced indicator. Locked notes are cached in
their encrypted form, exactly as the server stores them. This is
last-write-wins: if you edit the same note on two devices while one is
offline, whichever syncs last overwrites the other.

## Limits worth knowing

- Notes live in one Workers KV namespace — no R2 bucket, and no payment method needed
  on your Cloudflare account to set this up. (Photos and audio can optionally live in
  Backblaze instead, see above; the 25 MB and 1 GB figures below then apply to text only.)
- Each note's content (text + photos + audio + drawing, all combined) is capped
  at 25 MB, which is a KV hard limit. The editor shows the note's size next to the
  Save button: comfortable up to 12 MB, "getting heavy" from 12, "close to the limit"
  from 20, and a note over 25 MB can't be saved. The 12 and 20 MB lines are this
  app's own cautious ones, not Cloudflare's: the Worker holds a note in memory
  several times over while it handles it (128 MB per request), and the free plan
  allows only 10 ms of CPU per request, so very large notes are the first thing to
  fail. A locked note is about a third bigger than its contents, because encrypted
  data is stored as text; the meter accounts for that.
- Total free storage across your whole account is 1 GB. **Settings → Storage**
  shows how much of it your notes use, warns from 70% and again from 90%, and lists
  your biggest notes. If you're on a paid plan, raise the number there. (The total
  comes from the size each note records on the server. Notes saved before you
  redeployed the Worker are counted once they've synced to the device.)
- Workers KV's free plan also allows 1,000 writes a day; each save uses 2–3 of
  them. Autosave waits a little longer between saves on a heavy note for this reason.
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
