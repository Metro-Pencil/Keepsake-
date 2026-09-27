# Changelog

All notable changes to this project are recorded here, following
[Keep a Changelog](https://keepachangelog.com) conventions and
[Semantic Versioning](https://semver.org). Every change — however
small — gets a version bump. If the version number hasn't moved,
nothing changed; that's the whole point of keeping one.

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
