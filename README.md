# Keepsake

A private notebook: long-form notes with photos, where any individual note
can be locked. Two lock types:

- **Quick lock** — one password. Opens any time you enter it.
- **Time lock** — your password *plus* a second, auto-generated password.
  Once the unlock date passes, your password alone opens the note (the
  app fetches the second password on its own). Before that date, the
  only way in is to download the note — the download button works on locked
  notes too — and look up the second password inside the downloaded file
  yourself, then enter both.

This is a deliberate-friction lock, not a hack-proof vault: nothing stops
you, the account holder, from bypassing it with enough effort. That's the
point — it's meant to slow down impulse, not defend against an attacker.

## What's in this repo

```
index.html, app.js, b2.js, media.js, video.js, player.js, migrate.js, manifest.json, sw.js,
icon-192.png, icon-512.png, cors.json
```

One flat folder, no build step. There is **no server**: the app runs in your browser and
talks straight to a private Backblaze B2 bucket. Host the files anywhere static (GitHub
Pages is fine).

## 1. Set up the bucket

1. In Backblaze, create a **Private** bucket (leave Object Lock off). Note its name and the
   S3 endpoint on its page (looks like `s3.us-west-004.backblazeb2.com`).
2. **Application Keys → Add a New Application Key.** Restrict it to that one bucket with
   **Read and Write** access. Copy the **keyID** and **applicationKey** right away; the key
   is shown only once.
3. **Turn on "Keep only the last version of the file".** In the bucket's Lifecycle Settings.
   Backblaze keeps every version of an overwritten file and only *hides* a deleted one, and by
   default it keeps them all forever. Every save overwrites a note's files, so without this
   your 10 GB quietly fills with old copies, and deleted notes and photos never really go away.
   With it, old and hidden versions are removed about a day later.
4. **Allow this site to call the bucket (CORS).** Browsers refuse to talk to another address
   unless the bucket says it's allowed. Either:
   - in the bucket's settings, set CORS to share with exactly one origin (your site, e.g.
     `https://your-name.github.io`) and apply it to the **S3-compatible API**; or
   - edit `cors.json` (put your site's address in `AllowedOrigins`: scheme and host only, no
     path) and run, with the AWS CLI configured with a Backblaze key that may change bucket
     settings:

     ```bash
     aws s3api put-bucket-cors --bucket YOUR-BUCKET \
       --cors-configuration file://cors.json \
       --endpoint-url https://s3.YOUR-REGION.backblazeb2.com
     ```

## 2. Host the frontend

Push this folder to a GitHub repo and turn on GitHub Pages (Settings → Pages), or use any
static host.

## 3. Connect the app

Open the site, tap the gear icon and fill in **Endpoint**, **Bucket name**, **Key ID** and
**Application key**, then **Save and test**. The test tells you apart the usual problems: a
wrong key, a wrong bucket, a bucket that isn't allowing this site (CORS), or no connection.
The four values are stored only in that browser. **Anyone who has the application key can
read and delete everything in the bucket**, so keep it private and use a key limited to this
one bucket.

## What lives in the bucket

```
meta/{id}.json     title, dates, lock type, sizes (the list of notes)
content/{id}.json  the note: text, formatting, drawing, photo/audio references (encrypted if locked)
vault/{id}.txt     a time-locked note's second password
media/{id}/{file}  that note's photos, audio and video (encrypted first if the note is locked)
```

- Don't put other files under those four prefixes.
- A video is stored as many small files, not one: see **Videos** below.
- Photos and audio are separate files (up to about 90 MB each, about 150 MB per note including
  the written part).
- Deleting a note deletes all of its files. A photo removed from a note is deleted from the
  bucket after an hour (so a save still in flight never loses a file).
- Notes stay readable offline: everything you open is kept on the device, and photos and
  audio are cached there (about 300 MB, least-recently-used dropped first). Edits made
  offline are queued and uploaded when you're back online.
- **Download** on a note includes its photos and audio (still encrypted for locked notes),
  so the file is a complete backup. Videos are too big to put inside one file: the download lists
  where they are, and each video can be downloaded from its own player.
- Backblaze's free plan includes 10 GB. Settings → Storage shows how much you're using.

## Original or Compressed

Every time you add photos, audio or video, Keepsake asks first. Tap **Original** or **Compressed** to
choose (Original is pre-selected), then **OK**; Cancel or Escape adds nothing.

- **Photos:** *Original* keeps the file byte for byte (including location data);
  *Compressed* resizes and re-encodes at the strength set in Settings.
- **Audio files:** *Original* keeps the file exactly; *Compressed* re-encodes it at a lower
  bitrate. A browser can only do that in real time, so it takes as long as the audio plays
  and the screen must stay open. If the result wouldn't be smaller, the original is kept.
- **Videos:** the dialog lists each file with its length, resolution and **what it would come to if
  compressed**, and a "Final size" line follows your choice (*Original* = the file as it is;
  *Compressed* = an estimate, "about", since an encoder aims for a bitrate rather than guaranteeing
  one). When compressing finishes, the real final size is shown before the video is added. *Compressed*
  re-encodes at the strength set in Settings (Standard: up to 720p, about 9 MB a minute; High: up to
  1080p, about 23 MB a minute). Like audio it runs in real time, so it takes as long as the video plays,
  the screen must stay open (the app asks the device not to sleep meanwhile), and Cancel stops it. If
  the video is already small, or the browser can't re-encode it, the original is kept and you're told.
- **Recording:** *Original* records at the highest quality the browser offers with noise
  suppression, echo cancellation and auto-gain **turned off**; *Compressed* uses the usual
  processing at the lower bitrate chosen in Settings. You can't change a recording afterwards,
  which is why it asks before you start.

## Compressing something you already saved

Open the note, then:

- **Photos:** tap the photo to open the viewer and choose **Compress this photo**.
- **Audio:** tap the clip's ⋯ button and choose **Compress**.

It shows what the new size will be and asks before replacing anything, using the strength set in
Settings → Compressed quality (a photo already at that strength usually won't shrink, and the app
tells you instead of changing it). The original is gone from the note once you confirm; its file is
deleted from the bucket the next time that note is saved after an hour. Progress runs along the top
of the screen with the file size and a percentage. Audio takes as long as the clip plays and needs
the note to stay open; leaving the note stops it. The app has no video support, so there is nothing
to compress there.

## The time lock and clocks

A time-locked note's second password is a file in your bucket, and the app only fetches it once the
unlock date has passed. **Time-locked notes are judged by Backblaze's clock, not the phone's:** when
you open one, the app asks Backblaze what time it is right then and ignores the phone. Ordinary notes
(and quick-locked ones) use the phone's clock. Settings shows how far your phone is from Backblaze.
The clock is read from the `Date` header (hence `Date` in `cors.json`); if your CORS rule doesn't
expose it, the app falls back to writing a tiny `clock/ping.txt` file and reading its timestamp.

Backblaze also refuses any request from a phone whose clock is more than 15 minutes off, so a badly
wrong phone clock simply stops the app working until you fix it.

What it can't do: there is still no server to hold the password back. Anyone with the bucket key can
read `vault/{id}.txt` directly, and the downloaded copy of a note contains its second password (as
described above). This is a deliberate-friction lock, not a vault.

## Moving over from the old Cloudflare setup (v1.7.0 only)

Settings has a **Move notes from Cloudflare** section. Fill in the Backblaze details above
and tap *Save and test* first, then enter the old Worker address and access token (they are
prefilled if this device used them before) and tap **Copy everything to Backblaze**. It reads
each note, brings across any photos and audio, writes them to the bucket, reads each note back
to check it, and only then makes it visible. It never changes or deletes anything on the old
side and is safe to run again (notes already in the bucket at the same version or newer are
skipped).

When you've opened a few notes from the bucket and are happy, tap *Forget the old address and
token*. To remove the last traces:

1. Delete `migrate.js` and its `<script>` line in `index.html`, its line in `sw.js`'s
   `SHELL_FILES`, and its line in `FORCE_REFRESH_SHELL_FILES` in `app.js`.
2. In the Cloudflare dashboard, delete the Worker and the `NOTES_KV` namespace. That part is
   outside this app, so only you can do it.

Other devices: open the new version, enter the same four Backblaze values, and the notes
appear. Anything still queued offline on a device is uploaded to the bucket.

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
(WebM/Opus, or M4A on Safari); a file you attach as *Original* is kept byte-for-byte, so
downloading it gives back exactly what you attached. In a locked note the audio is
encrypted with everything else. Recording needs HTTPS and microphone permission. See
"Original or Compressed" above for what the prompt before each photo, file or recording does;
**Settings → Compressed quality** only sets how strong *Compressed* is.

## Offline

Keepsake keeps a copy of every note on the device (in IndexedDB), so the
list, reading, unlocking, downloading, writing, and deleting all work with
no connection. A note opens straight from that copy whenever it matches what the
bucket last reported (the list is refreshed on launch, after saves and when you come
back to the app), so opening doesn't wait on the network. Changes made offline are queued and sent automatically once
you're back online; until then the note shows a "Not synced" tag and the
top bar shows an offline / not-synced indicator. Locked notes are cached in
their encrypted form, exactly as the bucket stores them. This is
last-write-wins: if you edit the same note on two devices while one is
offline, whichever syncs last overwrites the other.

Every save is written to the device first - the note, its lock, and a list of the
photos and audio still to send - and only then uploaded, so closing the app mid-upload
loses nothing. Photos and clips go up **one at a time**; on the next launch the upload
carries on with the next file rather than starting over (a file interrupted mid-send is
sent again in full). Each file is verified against its SHA-256 before sending and against
the bucket afterwards, and the note itself is written only after all of its files are
confirmed. While data is waiting, the bar at the top shows a row each for photos, audio
and note text.

## Videos

Tap the video button in the editor. A video is never held in memory, and never uploaded as one giant
file, so a long clip can't be lost to a phone falling asleep:

- **Split and tagged.** The video (compressed first, if you chose that) is cut into **4 MB parts**. Each
  part is checksummed (SHA-256) and saved on the device as it is cut. In the bucket the parts sit under
  `media/{note id}/` as `<video id>.00000`, `<video id>.00001`, … - the name says which video a part
  belongs to and its place in it. The note holds the list (how many parts, each one's size and checksum).
- **Uploaded section by section.** Parts go up one at a time. Every few parts the app lists the bucket to
  confirm they are really there at the right size; only then are they marked done. The bar at the top
  has a "Video" row counting parts.
- **Interruptions cost almost nothing.** If the connection drops or the phone sleeps, the parts already
  sent stay in the bucket; the next try lists the bucket and sends **only what is missing**. It resumes
  by itself when the app is back on screen or online. While a video uploads or compresses the app also
  asks the screen to stay awake.
- **Lost data is sent again.** On every save the whole list is checked against the bucket. A part that
  is missing, or the wrong size, is re-sent from the copy kept on the device. (If a part is gone from both
  places, the save stops with a clear message instead of storing a broken video.)
- **In the note.** A video is a tile in the same grid as photos (same size, mixable freely): poster,
  length, size, and an icon for its upload state (tick = saved, arrow = uploading/waiting, cloud = only in
  the cloud). Press-and-hold or use a screen reader for the full wording.
- **Playing.** Tap a tile to open the player (drag-to-seek, ±10 s double-tap, speed, full screen,
  picture-in-picture). The ⋯ menu has Upload details, Compress…, Download and Remove. Parts already on the device are used as they are; any others
  are fetched, checked against their checksum, and kept for next time. Videos are not downloaded just
  because you opened the note. About 2 GB of synced video parts are kept on the device (least recently
  used dropped first, and the bucket always has them); parts still waiting to upload are never dropped.
- **Upload details.** ⋯ → Upload details shows one cell per part (saved / waiting / lost / missing
  everywhere), checked against the bucket right then. If parts were lost, **Send missing parts** re-sends
  them from the copy on this device without waiting for a save.
- **Compress later.** ⋯ → Compress… shrinks a video that is already in the note (it shows the estimate
  first, then the real result). The smaller copy replaces the original when the note is saved; the old
  parts are removed from the bucket by the usual one-hour cleanup.
- **Locked notes.** Every part is encrypted separately (AES-GCM, its own random IV) with the same
  per-note key as photos and audio, and the video's details and poster live inside the encrypted note.
  Locking a note whose video was already uploaded re-encrypts it from this device, or from the bucket
  if needed; the old unencrypted parts are removed from the bucket after the usual one-hour grace.
- **Limits.** Up to 2 GB per video. Videos don't count toward the 150 MB note limit (that limit is about
  what the editor holds in memory), but they do count toward your account storage. Playing a video in a
  *locked* note decrypts it into memory first, so very large ones can be heavy on a phone. A phone
  browser must be able to decode the video to compress it or show a poster; other files are kept as they are.
- Compressed videos are saved as MP4 where the browser can record that and WebM otherwise (Safari may
  not play WebM on older iOS versions).

## Limits worth knowing

- The editor shows the **whole note's** size next to the Save button: its text and drawing plus
  its photos and audio, against a limit of 150 MB per note. Comfortable up to 50 MB, "getting
  heavy" from 50, "close to the limit" from 100, and a note over 150 MB can't be saved. (Photos
  and audio are separate files in the bucket, but they are held in memory while the note is open,
  which is why there is a ceiling.) A locked note's written part is about a third bigger than its
  contents, because encrypted data is stored as text, and the meter accounts for that.
- Each photo or clip is limited to about 90 MB, and the written part of a note (text, formatting,
  drawing) to 25 MB.
- Storage: **Settings → Storage** shows how much of your bucket's allowance your notes use
  (10 GB by default, matching Backblaze's free plan; change the number if yours differs),
  warns from 70% and again from 90%, and lists your five biggest notes - each with its **full**
  size (text, photos, audio and video) and how many photos/clips/videos it holds.
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
- Everything is plain objects in the bucket under `meta/`, `content/`, `vault/` and `media/`
  (see "What lives in the bucket"), read and written by `b2.js`, which signs each request in the
  browser (AWS Signature V4). If you ever want a different S3-compatible store, `b2.js` is the
  one file that knows about it.
