# Changelog

All notable changes to this project are recorded here, following
[Keep a Changelog](https://keepachangelog.com) conventions and
[Semantic Versioning](https://semver.org). Every change — however
small — gets a version bump. If the version number hasn't moved,
nothing changed; that's the whole point of keeping one.

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
