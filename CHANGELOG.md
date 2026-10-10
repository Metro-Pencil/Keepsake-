# Changelog

All notable changes to this project are recorded here, following
[Keep a Changelog](https://keepachangelog.com) conventions and
[Semantic Versioning](https://semver.org). Every change — however
small — gets a version bump. If the version number hasn't moved,
nothing changed; that's the whole point of keeping one.

## v1.8.1 — 2026-10-10

- **The size at the top of a note is the whole note now.** It used to read "x / 25 MB" and ignore
  photos and audio, so a note with a 4 MB photo showed 0.0. It now adds up text, drawing, photos and
  audio against the real limit, 150 MB per note (50 MB "getting heavy", 100 MB "close to the limit").
  The details dialog, the recorder's size line and every "over the limit" message use the same figures.
  One photo or clip may be up to 90 MB; the written part alone up to 25 MB.
- **Original / Compressed now has an OK button.** Tapping an option only selects it (Original is
  pre-selected); nothing happens until OK. Cancel and Escape add nothing.
- **Recorded audio playback:** the clip's player no longer waits on an asynchronous step before
  starting, which browsers such as Safari treat as "not started by a tap" and refuse. When a browser
  does refuse, or can't play the format, it now says so instead of staying silent. The progress fill
  works for recordings, which report no length. A recording that is silent or almost silent is flagged
  on the review screen before it is added.
- **Cards:** the lock pill and the "Not synced" pill touched each other and sat at different heights.
  They now share one shape in a wrapping row with a gap, on every kind of card; the date row wraps
  instead of squashing, and the buttons on locked cards line up with the card's edge.
- **Error messages** (wrong password, passwords don't match, ...) were plain black because the
  style only matched an error inside a form field; they are red, with an icon, now.
- Smaller: the progress bar's label wraps so the percentage is never cut off; the lightbox's
  "Compress this photo" button is 44px and its focus ring shows on the dark backdrop; "Restore"
  (draft) is no longer a red delete-style button; a photo with no file type keeps image/* so it
  reopens; autosave timing is based on the written part only; the header badge no longer starts as
  "v1.5.0"; duplicate CSS rules merged. Service worker cache bumped to v16.

## v1.8.0 — 2026-10-09

- **Time-locked notes use Backblaze's clock.** Opening one asks Backblaze for the time right then,
  so changing the phone's clock can't release it early. Time-locked notes are also stamped with
  server time; ordinary notes keep using the phone's clock. Settings shows the difference.
- **Every file's size in the Original / Compressed prompt**, and the progress bar along the top
  now names each file, its size and a percentage for every compression, then shows the result
  ("5.4 MB → 1.2 MB").
- **Compress saved media any time:** "Compress this photo" in the photo viewer and "Compress" in
  a clip's dialog, with the new size shown and a confirmation before the original is replaced.
- **Bucket lifecycle:** the README and Settings now say to set the bucket's Lifecycle to "Keep
  only the last version of the file", otherwise overwritten and deleted files stay in storage.
- `cors.json` now also exposes the `Date` header.

## v1.7.0 — 2026-10-09

**Backblaze B2 only: Cloudflare is gone**

- **No server any more.** The app talks straight to your private Backblaze B2 bucket (its
  S3-compatible API), signing each request in the browser. Notes, locks, second passwords,
  photos and audio all live in the bucket (`meta/`, `content/`, `vault/`, `media/`). The
  Worker, the KV namespace and `wrangler.toml` are not needed and have been removed.
- **Settings now takes four values** (endpoint, bucket, key ID, application key) instead of a
  Worker address and token, with a **Save and test** that tells apart a wrong key, a wrong
  bucket, a missing CORS rule, a skewed clock and no connection. The bucket needs a CORS rule
  for your site (see the README and `cors.json`).
- **Photos and audio always go to the bucket** as separate files, so the old on/off switch is
  gone. Notes saved before keep their media inside until you next save them.
- **Original or Compressed, every time.** Adding photos, attaching an audio file or starting a
  recording now asks first. Photos: Original is byte for byte, Compressed resizes. Audio files:
  Original is kept as is, Compressed re-encodes in real time (the original is kept if that
  wouldn't make it smaller). Recording: Original turns the microphone's noise suppression,
  echo cancellation and auto-gain off and records at the highest quality; Compressed uses the
  usual processing at the chosen bitrate. Settings → Media quality became Compressed quality
  and only sets how strong Compressed is.
- **Storage meter** counts photos and audio with the notes and defaults to 10 GB (Backblaze's
  free plan). Change it in Settings if your plan differs.
- **One-time move from Cloudflare** (this version only): Settings → Move notes from Cloudflare
  copies every note, its second password and any photos or audio from the old Worker into the
  bucket, reading each note back to check it. It only reads from the old side, never deletes,
  and is safe to run again. It lives entirely in `migrate.js`; delete that file when you're done.
- **Time lock note:** with no server, the unlock date is enforced by the app on the device (it
  uses the device's clock) rather than by a server. See the README.

**Under the hood**

- New `b2.js` (SigV4 signing checked against Amazon's published test vectors, listing with
  pagination, a metadata cache so the list only re-reads changed notes, upload progress).
  `media.js` now uses it instead of a Worker. Service worker cache bumped to v14.

## v1.6.0 — 2026-10-09

**Photos and audio in Backblaze B2 (optional)**

- **Connect a Backblaze B2 bucket and a note's photos and audio are stored there** instead
  of inside the note. Files can be up to about 90 MB each and a note can carry about 150 MB
  of them; they no longer count toward the 25 MB note limit or the 1 GB KV allowance. Leave
  the four new Worker settings empty and nothing changes: everything stays inside notes as
  in v1.5.0.
- **The browser only talks to your Worker**, which signs requests to the (private) bucket.
  No CORS rules and no public bucket needed.
- **Locked notes stay locked:** media is encrypted on the device with a random per-note key
  that is kept inside the note's encrypted content, so the bucket only holds ciphertext for
  them. Unlocked notes' media is stored as it is.
- **New Settings → Photos & audio storage** shows whether the Worker has Backblaze set up
  and has a switch to turn it off. Settings → Storage shows how much is in Backblaze.
- The size meter, the recorder and the "add photo / attach audio" checks use the new limits
  when it is on, and the size breakdown lists photos & audio as stored in Backblaze.
- **Offline still works:** media is fetched when a note is opened or synced and kept on the
  device (about 300 MB, least-recently-used dropped first). A note saved offline keeps its
  media on the device and uploads it, with the note, once you are back online.
- **Download includes the media** (still encrypted for locked notes), so the file is a
  complete backup. If a note's media is bigger than 200 MB the file points to the bucket
  instead.
- **Housekeeping:** deleting a note deletes its files; photos removed from a note are
  deleted from the bucket after an hour (so an in-flight save never loses a file).
- Notes saved before this keep their media inside until you next save them.

**Under the hood**

- New `media.js` (browser side, with its own small local database) and new Worker routes
  `/api/media-config` and `/api/media/{noteId}/{file}`, with AWS Signature V4 signing checked
  against Amazon's published test vectors. `sw.js` cache bumped to v13 and `media.js` added
  to the app shell.

## v1.5.0 — 2026-10-03

**Audio in notes**

- **Record or attach audio and place it anywhere in the text** — between two
  sentences or two words. A clip shows as a small inline player: tap ▶ to listen
  (the pill fills as it plays), tap ⋯ for the clip on its own, where you can listen,
  **download just that clip**, or delete it. A file you attach is stored byte-for-byte;
  a recording is saved in whatever format the browser records (WebM/Opus, M4A on Safari).
- Locked notes encrypt their audio with everything else. Cards and plain-text copies
  show a 🎙 0:12 marker where a clip sits.
- Recording shows a live timer, a level meter and what the clip will add to the note's
  size, stops itself before the note would go over 25 MB, and can't be dismissed by an
  accidental tap or Escape (closing asks first). A blocked microphone gets a clear
  message, and attaching a file is always available.

**Quality**

- **New Settings → Media quality.** Photos: Standard (1600px) / High (2560px, the new
  default) / Original (untouched file). Recordings: 64 / 128 (default) / 256 kbps.
  Original photos keep their location data, and the setting says so.

**Size meter and storage**

- **The editor shows the note's size against the 25 MB limit** (top bar, next to Save),
  with a warning level — comfortable, getting heavy (12 MB), close to the limit (20 MB),
  over the limit — each with its own icon and wording rather than colour alone. Tap it for
  a breakdown (text / photos / audio / drawing / lock encryption), advice, and what each
  level means. The estimate matched the stored size within 0.01% in testing.
- Photos or clips that would push a note over 25 MB are refused with a message instead of
  failing later at save time; a locked note's extra ≈ 33% is counted.
- **Settings → Storage** adds up every note against your account limit (1,000 MB by
  default, editable), warns at 70% and 90% with a bar, lists your biggest notes, and a
  small "Storage NN%" pill appears in the header from 70%. Note cards show their size.

**Speed**

- **Opening a note and entering a password are much faster.** A note whose copy on this
  device is current opens straight from it instead of downloading the whole note again
  on every tap. Measured on six photo-heavy notes (4.4 MB each) over an ~8 Mbit/s link:
  opening 4.8 s → 0.02 s, unlocking 6.5 s → 0.1 s. (v1.4.2 and v1.4.3 measured the
  same — the cost had always been there and grows with note size.) What remains of an
  unlock is mostly the password key-derivation, which is deliberate.
- The list is refreshed when you come back to the app, so a note edited on another device
  is still noticed.
- The local cache keeps a note's heavy content apart from its small details, so updating a
  title, password or flag no longer re-reads and re-writes megabytes. Existing data is
  migrated automatically on first launch. Other speed-ups: one shared database connection,
  faster base64 conversion, a time-lock's second password and the note fetched together,
  thumbnails drawn from a small decoded copy (important with Original photos), and
  "has anything changed?" checks that no longer serialise every photo on each autosave.
- Autosave waits a little longer between saves on heavy notes (it re-sends the whole note).

**Bugs fixed**

- **Locked-card buttons never went away.** The Download / Delete buttons that appear on the
  first tap now tuck away after 5 seconds, when you tap anywhere else, switch tabs or press
  Escape; touching them keeps them around. Two causes: nothing ever dismissed them, and a
  tapped button kept focus, which held them open indefinitely.
- Large dialogs' explanatory text had no style outside form fields; fixed.

**Worker (optional redeploy)**

- The Worker records each note's `size`, rejects a save with no content, and returns stored
  content as-is instead of parsing and re-serialising it (less CPU/memory for big notes).
  Everything works against the old Worker too — the storage total just takes longer to fill.

**CSS / accessibility**

- Every new control is at least 44px; new colours were checked for contrast; the size,
  storage and recording notices pair a distinct icon with words; the editor top bar and
  toolbar fit from 320 to 768px (the toolbar wraps at 320); progress bars use `role="meter"`.

## v1.4.3 — 2026-10-02

**Lock dialog**

- **Fixed the lock dialog coming up blank for a time lock whose date had
  passed.** The date field was only filled in while the date was still in the
  future, so reopening the lock on a note after its time lock ended showed an
  empty "Unlock at" and "Update time lock" then refused with "Pick a date and
  time". The passed date is now shown, with a line explaining that the note
  already opens with just your password. Keeping that date as it is is allowed;
  only a *changed* date must be in the future.
- The padlock in the editor now reads "Change lock" and lights up while a lock
  is on. The summary line says which lock is set and how to change it, and
  tells you when a time lock has ended.
- Quick lock / Time lock choices expose their selected state to screen readers
  and show a check mark, so selection isn't carried by colour alone. The two
  choice titles now line up.
- **Removing a lock now asks first.** One stray tap on the unlocked-padlock icon
  used to strip the lock and autosave the note unencrypted two seconds later.

**Bugs fixed**

- **Deleting a note from the editor could bring it back.** An autosave scheduled
  a moment earlier landed after the delete and re-created the note on the server.
- **Emptying an existing note didn't stick.** Clearing the title and text and
  closing reopened the note with its old text. An existing note that you empty
  is now saved as empty; a brand-new empty note is still just dropped.
- **Photos could be attached to the wrong note.** Picking several large photos
  and opening another note before they finished processing added them to that
  other note. They are now dropped, with a message.
- **Pressing Escape in the photo viewer also closed the editor** behind it.
- **Enter now submits dialogs** (unlock, lock chooser). It did nothing before.
- **A server error was reported as "Wrong password."** Unlock now tells a bad
  token, a sealed-by-the-server note (check the device clock), and a network
  problem apart from a wrong password, and shows "Opening…" while it works.
- **An offline edit could be hidden behind an older server copy.** While a note
  has an unsynced change, opening or downloading it now uses the local version.
- **Transparent PNGs turned solid black** when compressed to JPEG; they now get
  a white backdrop.
- **Locked notes no longer write a plain-text draft to the device.** The
  encrypted copy still reaches the outbox/server a couple of seconds after you
  stop typing. Trade-off: abruptly closing the app within about two seconds of
  typing in a locked note can lose that last stretch.
- "Resume" on a recovered draft of a locked note now goes through the normal
  unlock; opening it directly left a note that could never be saved.
- The sync bar's spinner stops once it says "Saved".
- Card ids and photo sources are escaped/validated before going into markup.

**CSS / accessibility**

- Text colours that failed contrast now pass 4.5:1: the grey for dates, hints
  and the composer (2.9:1 → 4.9:1) and the amber for time-lock pills, banners
  and warnings (3.4:1 → 5.2:1). Form field edges are now visible (3:1).
- Every control is at least 44px: header tabs and gear, card download/delete,
  Save, dialog buttons and inputs, the photo "×" (now 32px, hanging off the
  corner), and the lightbox close button.
- The editor's Delete button is back at the far edge of the toolbar — `.spacer`
  was used but never defined.
- Lightbox arrows no longer jump down while pressed (the pressed-button
  transform overwrote their vertical centring).
- The header wraps into two tidy rows on phones (brand + gear, then full-width
  tabs) instead of stranding the gear on its own line. The composer spans the
  full width.
- Text sizes are in `rem` so the device's text-size setting applies; side
  padding respects landscape notches; the toast clears the home indicator;
  forced-colors mode keeps ink swatches distinct; dialogs have proper roles and
  labels.
- Bumped the service worker's cache name. No Worker redeploy needed.

## v1.4.2 — 2026-10-01

- **Locked-note titles now live on the server, so every device shows them.**
  The title is stored in plain text alongside the note (capped at 200
  characters); the text, photos and drawing inside stay encrypted, and a
  locked note's preview is still never stored. The lock dialog says so.
  **Requires redeploying the Worker** (`wrangler deploy`). Until then the
  app keeps working and falls back to the v1.4.1 behaviour (titles
  remembered on the device). Notes locked before this release get their
  title pushed automatically: once the Worker is redeployed, open each one
  (unlock, then close) a single time and it re-saves with its title.
- **The lock dialog remembers what you entered.** Reopening it on a note
  with a lock set — whether moments ago or from unlocking it — now shows the
  chosen lock type, password, confirmation and unlock date instead of a
  blank form, and the button reads "Update quick/time lock".
- **Show/hide password eye** on every password field (lock dialogs, unlock
  dialogs, and the Settings access token). It's a 44px target, keeps the
  keyboard open while you tap it, and passwords re-hide whenever a dialog
  closes.
- Bumped the service worker's cache name.

## v1.4.1 — 2026-10-01

- **Locked notes now show their title on the card**, so a stack of locked
  notes (quick or time) can be told apart at a glance. The title is kept
  **only on the device** — the server still stores nothing readable about a
  locked note, exactly as before. It's remembered whenever you save or
  unlock a locked note, so: notes locked from now on show it straight away;
  notes that were already locked show it after you unlock them once on each
  device (until then they read "Locked note", in a lighter shade). A device
  you've never unlocked a note on won't know its title.
- No Worker redeploy needed.

## v1.4.0 — 2026-09-30

- **Fixed "Not synced" staying on forever.** The Worker answers a delete
  for a note it doesn't have with a 404, and the app treated that as a real
  failure: a delete queued for a note that never reached the server (or was
  already gone) stayed in the outbox permanently, retrying silently every
  30s, so the "Not synced" pill never cleared no matter how many later saves
  succeeded. A 404 on delete now counts as done — including for anything
  already stuck in the queue, which clears the next time the app opens.
- **Formatting.** The note body is now a rich-text editor with a bar above
  the toolbar: **bold**, *italic*, underline, two heading sizes, and
  bulleted / numbered lists (Ctrl/Cmd+B, I, U also work). Pasting always
  inserts plain text. Formatting is stored as sanitized HTML in
  `content.html`, with the plain text kept in `content.body`, so previews
  and older notes are unaffected — old notes simply open as ordinary lines.
- **Draw on notes.** New pencil/scribble button in the editor toolbar
  switches to drawing mode directly over the note: pen, highlighter (tints
  text instead of hiding it), eraser (removes whole strokes), five colours,
  three thicknesses, undo / redo / clear, and a scroll tool for moving the
  page without drawing. Drawings are saved as vector strokes in
  `content.drawing` (encrypted along with everything else on locked notes),
  scale with the note's width, and autosave like text.
- **Download and Delete moved inside normal notes.** They're gone from the
  card face on ordinary notes and live in the editor's toolbar (Download is
  new there; Delete already was). **Locked notes keep them on the card** —
  Download has to work while a note is sealed.
- **Dialogs are centred instead of sliding up from the bottom** (lock
  chooser, unlock, confirm, settings). They also follow the on-screen
  keyboard, re-centring in the space left above it, and a focused field
  scrolls into the middle, so password fields are no longer hidden by it.
  Dialog inputs are now 16px, which stops iOS zooming the page on focus.
- Editor buttons are now 44px touch targets; the new UI uses spacing,
  radius and z-index tokens.
- Bumped the service worker's cache name so this reaches installed copies.
- No Worker redeploy needed for this release.

## v1.3.0 — 2026-09-28

- **Every note now works offline — locked and unlocked.** The app keeps a
  full local copy of all your notes (still encrypted, for locked ones) in
  IndexedDB and renders the list from that, so opening the app with no
  connection shows your notes as normal cards instead of a "Could not load
  notes" warning. After each successful sync it quietly downloads the
  content of anything it doesn't have yet, so notes you've never opened on
  this device are available too. Opening, unlocking, and downloading a note
  all fall back to the local copy when the server can't be reached.
  (One limit: a time-locked note whose date passes *while you're offline*
  needs one connection to fetch its released second password.)
- **Writing works offline.** Creating, editing, locking, and deleting notes
  with no connection no longer errors — the change is saved on the device,
  queued, and shown right away. A queued note appears as a normal card
  with a small "Not synced" tag, and everything is pushed to the server
  automatically once a connection is back (on reconnect, and every 30s
  while anything is waiting). Only real server errors (bad token, 500s)
  still surface as errors; being offline no longer does.
- **"Not synced" indicator in the top bar**, next to the version badge:
  shows "Offline", "Offline · N not synced", or "N not synced", and
  disappears when everything has reached the server.
- **The save/progress bar no longer slides down from the top on every
  autosave.** It now lives in one fixed spot — a strip directly under the
  title row of the front page — and, because the full-screen editor sits
  above it, it isn't shown while you're writing. (Its progress text and bar
  are unchanged; it just no longer overlays everything.)
- **Note cards: download and delete now sit inline with the date** instead
  of in a separate bordered footer strip, and are a bit larger to tap.
  On **locked** notes they're hidden until you tap the card once; a second
  tap opens the unlock prompt as before.
- Fixed opening a locked note and closing it without changes re-encrypting
  and re-uploading it anyway (the "already saved" baseline was built in a
  different shape than the snapshot it's compared to, so it never matched).
- Deleting is now local-first: the note leaves the list immediately and the
  server delete is queued, instead of being rolled back if the request
  fails.
- The header now pads for the device's top safe area itself (that used to
  be handled only by the old fixed sync bar).
- Bumped the service worker's cache name so this reaches installed copies.

## v1.2.1 — 2026-09-28

- **Fixed "Force refresh" not actually refreshing.** It correctly cleared
  the service worker's own cache, but that's a separate layer from the
  browser's plain HTTP cache — which could still hand back an old `app.js`
  with no network request at all. That's why the version number in
  Settings would bump but the actual behavior stayed the same, and why
  reopening the app later could even revert the version number back down
  (a freshly (re)installed service worker was precaching straight from
  that same stale HTTP cache). Both the button and the service worker's
  own install step now force a real network fetch for every shell file,
  so a refresh — manual or automatic — always loads current code.

## v1.2.0 — 2026-09-28

- **Opening a note no longer force-opens the keyboard.** The title field
  used to grab focus automatically every time — new note or existing —
  which popped the keyboard even when you just wanted to read. It now
  waits until you actually tap into the title or body.
- **Fixed the dark bar that appeared above the keyboard.** The full-screen
  editor is pinned to the whole screen (`inset: 0`), and mobile browsers
  don't shrink that box when the keyboard opens — only the visible area
  shrinks — so a gap opened up behind the keyboard. The editor now tracks
  `visualViewport` and resizes itself to match whenever the keyboard
  opens or closes, so the toolbar sits right above the keyboard with
  nothing behind it.
- **Each photo now shows its saved (compressed) size** as a small badge
  on its thumbnail and in the new photo viewer below.
- **Tapping a photo now opens it full-screen**, with left/right arrows
  (or a swipe) to page through every photo on the note, and a close
  button / tap-outside / Escape to dismiss.
- **The "Saving photos…" progress message no longer appears while you're
  just typing text.** Because a note's text and photos are stored
  together as one blob (see the README's KV notes), every autosave still
  has to resend the whole thing — but the status strip now only calls it
  out as a photo save when the photos themselves actually changed since
  the last successful save; a text-only edit now just says "Saving…"
  like it should.

## v1.1.0 — 2026-09-27

- **Autosave.** While a note is open, changes are cached locally (IndexedDB)
  about once a second and synced to the server in the background a couple
  of seconds after you pause typing, with a periodic safety net during a
  long unbroken typing session. If a session ever ends abruptly — crash,
  dead battery, a swiped-away tab — before a change reached the server,
  reopening that note (or relaunching the app) offers to restore it.
- **Save and closing the editor (✕/Escape) are now instant.** They close
  the editor right away and finish the actual encrypt/upload in the
  background instead of blocking on it. Progress for that background save
  — and for adding photos — now shows in a status strip fixed to the very
  top of the page, above everything else, so it's always visible instead
  of hidden behind the editor. This is also the fix for the photo-upload
  progress bar not showing up: it used to live inside the editor's
  scrolling area, where a stretched, empty textarea (or the on-screen
  keyboard) could push it out of view.
- Because closing now always triggers a save if anything changed, the
  "Discard this note?" prompt from v1.0.4 is gone — there's essentially
  nothing left to discard.
- **Fixed the root cause of duplicate notes**, not just the double-tap
  case from v1.0.4. A note's id is now generated on the device the moment
  you start editing it, and saving is a single idempotent operation on
  that id (see `worker.js`) — so a double-tap, autosave overlapping a
  manual save, or retrying a save that looked like it failed can no longer
  create a second note; each one just overwrites the same one.
  **Requires redeploying the Worker** (`wrangler deploy`) — the frontend
  alone doesn't ship this fix.
- Removed the instructions for finding a time-locked note's second
  password early (from the lock-setup screen and the "I have both
  passwords" unlock dialog). The early-unlock feature itself is unchanged.
- Saving or deleting a note updates the list immediately from the
  response you already have, instead of re-fetching and rebuilding the
  entire grid every time.
- Added visible press feedback (and matching transitions) to every
  button, card, and tab — including on touch, where the old :hover-only
  states never fired at all. This is the main fix for taps feeling slow
  or unresponsive.
- Bumped the service worker's cache name so this update reaches everyone
  already using the installed app.

## v1.0.4 — 2026-09-27

- Added a progress bar in the editor for adding photos (shows "photo X of
  N" while each one is compressed) and for saving a note that contains
  photos (shows real upload percentage).
- Photos now appear as thumbnails one by one as each finishes processing,
  instead of all at once at the end.
- Fixed a bug where the Cancel/Close buttons inside the unlock dialog
  didn't do anything — they're built fresh each time the dialog opens, but
  were only ever wired once at startup, before they existed.
- Fixed a bug where pressing Escape while a smaller dialog (e.g. the lock
  chooser) was open over the note editor closed both at once, silently
  discarding whatever was in the editor.
- Closing the editor (✕ button or Escape) with unsaved changes now asks
  "Discard this note?" instead of silently dropping them.
- Fixed a bug where a fast double-tap on Save while creating a new note
  could send two save requests and create a duplicate note. Save is now
  disabled (and shows "Saving…") until the request finishes.
- Skipped photos (ones that fail to read) are now reported with a toast
  instead of silently disappearing.
- Added a heads-up if a note's photos push it over Workers KV's 25MB
  cap, both while adding photos and before attempting to save, instead of
  only finding out from a server error after the fact.
- The notes list now shows a "Loading…" state on first load instead of a
  blank screen while the initial fetch is in flight.
- The Worker URL field in Settings is now checked for an http(s)://
  prefix — without one, requests were silently misrouted with a confusing
  failure.
- Disabled buttons (Force refresh, Add photo while processing) now look
  visibly dimmed instead of appearing clickable while inactive.

## v1.0.3 — 2026-09-27

- Added a "Force refresh" button in Settings that unregisters the service
  worker, clears the cached app shell, and reloads — a manual way to get
  the newest deployed version if the app ever looks stuck on an old one.
- Bumped the service worker's cache name so this deploy itself is picked
  up by everyone already using the installed app, not just new visits.

## v1.0.2 — 2026-09-27

- Replaced the cramped bottom-sheet note editor with a full-screen writing
  view — title, a body that expands to fill the available height, and a
  bottom toolbar for photo/lock/delete, closer to how Google Keep opens a
  note rather than a small popup.

## v1.0.1 — 2026-09-27

- Flattened the repo layout — no `icons/` or `worker/` subfolders anymore.
  Every file sits at the root, so there's nothing to create when uploading
  straight into GitHub.

## v1.0.0 — 2026-09-26

Initial release.

- Basic note taking: title, long-form body text, multiple photos per note.
- **Quick lock** — protect an individual note with a single password.
- **Time lock** — protect a note with two passwords: one you choose, one Keepsake
  generates. After the unlock date, your password alone opens the note — the
  Worker releases the second password automatically. Before that date, the only
  way in is to download the note (works even while locked) and look up the
  second password inside the downloaded file yourself.
- Notes stay stored in Cloudflare (Workers KV — no R2, no payment method
  required) indefinitely, even once a time lock's date has passed — no
  prompts to archive or download.
- Download button on every note, locked or not, exporting it as a standalone
  JSON file.
- Installable PWA shell — the interface works offline; note data always
  requires a connection to your Worker.
