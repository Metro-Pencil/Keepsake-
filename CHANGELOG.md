# Changelog

All notable changes to this project are recorded here, following
[Keep a Changelog](https://keepachangelog.com) conventions and
[Semantic Versioning](https://semver.org). Every change — however
small — gets a version bump. If the version number hasn't moved,
nothing changed; that's the whole point of keeping one.

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
