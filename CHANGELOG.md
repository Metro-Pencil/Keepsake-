# Changelog

All notable changes to this project are recorded here, following
[Keep a Changelog](https://keepachangelog.com) conventions and
[Semantic Versioning](https://semver.org). Every change — however
small — gets a version bump. If the version number hasn't moved,
nothing changed; that's the whole point of keeping one.

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
