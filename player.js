/* Keepsake — player.js
 * The full-screen video player. Markup lives in index.html (#overlay-video); this file only drives it.
 *
 *   KSPlayer.open({ title, sub, poster, dur, getSource(onProgress, isCancelled), onDownload, onRemove })
 *   KSPlayer.close()
 *
 * getSource resolves { url, revoke } - for a video kept in parts that is the moment the parts are joined
 * (see video.js), so the player shows "Getting video ready" with a progress bar until then.
 *
 * Controls: tap the picture to show/hide them; double-tap the left or right side to jump 10 s; drag the bar to
 * scrub; Space/K play, ←/→ 5 s, J/L 10 s, M mute, F fullscreen, Esc close. Everything is also a real button.
 */
(function (root) {
  'use strict';

  const SPEEDS = [1, 1.25, 1.5, 2, 0.5];
  const IDLE_MS = 3000;
  const SKIP = 10;
  const svg = (d, extra) => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"' + (extra || '') + '>' + d + '</svg>';
  const ICON = {
    play: '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M8 5.2v13.6a1 1 0 0 0 1.5.86l11-6.8a1 1 0 0 0 0-1.72l-11-6.8A1 1 0 0 0 8 5.2z"/></svg>',
    pause: '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><rect x="6" y="4.5" width="4.2" height="15" rx="1.2"/><rect x="13.8" y="4.5" width="4.2" height="15" rx="1.2"/></svg>',
    replay: svg('<path d="M4 12a8 8 0 1 0 2.6-5.9"/><path d="M4 4.5V9h4.5"/>'),
    back: svg('<path d="M12 5V2L7.5 6 12 10V7a6 6 0 1 1-6 6"/><text x="12" y="17" text-anchor="middle" font-size="7" font-weight="700" stroke="none" fill="currentColor">10</text>'),
    fwd: svg('<path d="M12 5V2l4.5 4L12 10V7a6 6 0 1 0 6 6"/><text x="12" y="17" text-anchor="middle" font-size="7" font-weight="700" stroke="none" fill="currentColor">10</text>'),
    vol: svg('<path d="M4 9.5v5h3.5L12 18.5v-13L7.5 9.5z"/><path d="M15.5 9a4 4 0 0 1 0 6M18 6.5a7.5 7.5 0 0 1 0 11"/>'),
    mute: svg('<path d="M4 9.5v5h3.5L12 18.5v-13L7.5 9.5z"/><path d="M16 9.5l5 5M21 9.5l-5 5"/>'),
    full: svg('<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>'),
    unfull: svg('<path d="M9 4v5H4M15 4v5h5M9 20v-5H4M15 20v-5h5"/>'),
    pip: svg('<rect x="3" y="5" width="18" height="14" rx="2"/><rect x="12" y="11" width="7" height="5" rx="1" fill="currentColor" stroke="none"/>'),
  };

  const $ = (id) => root.document.getElementById(id);
  const fmt = (s) => {
    s = Math.max(0, Math.floor(Number(s) || 0));
    const h = Math.floor(s / 3600); const m = Math.floor((s % 3600) / 60); const sec = s % 60;
    return h ? `${h}:${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}` : `${m}:${String(sec).padStart(2, '0')}`;
  };

  let el = null;      // the root element
  let v = null;       // the <video>
  let S = null;       // state of the open video
  let wired = false;
  let opener = null;

  function wire() {
    if (wired) return;
    wired = true;
    el = $('overlay-video'); v = $('vp-video');
    const on = (id, ev, fn) => $(id).addEventListener(ev, fn);

    $('vp-back').innerHTML = ICON.back; $('vp-fwd').innerHTML = ICON.fwd; $('vp-pip').innerHTML = ICON.pip;
    on('vp-close', 'click', close);
    on('vp-center', 'click', (e) => { e.stopPropagation(); toggle(); });
    on('vp-play', 'click', toggle);
    on('vp-back', 'click', () => skip(-SKIP));
    on('vp-fwd', 'click', () => skip(SKIP));
    on('vp-mute', 'click', () => { v.muted = !v.muted; syncVolume(); });
    on('vp-speed', 'click', cycleSpeed);
    on('vp-full', 'click', toggleFullscreen);
    on('vp-pip', 'click', togglePip);
    on('vp-menu-btn', 'click', (e) => { e.stopPropagation(); setMenu(!S.menuOpen); });
    on('vp-cancel', 'click', () => { if (S) S.cancelled = true; close(); });
    on('vp-err-download', 'click', () => S && S.onDownload && S.onDownload());
    on('vp-act-download', 'click', () => { setMenu(false); if (S && S.onDownload) S.onDownload(); });
    on('vp-act-remove', 'click', () => { setMenu(false); if (S && S.onRemove) S.onRemove(); });
    on('vp-act-details', 'click', () => { setMenu(false); if (S && S.onDetails) S.onDetails(); });
    on('vp-act-compress', 'click', () => { setMenu(false); if (S && S.onCompress) S.onCompress(); });

    // Picture: tap shows/hides the controls, double-tap jumps.
    const stage = $('vp-stage');
    let lastTap = { t: 0, side: 0 }; let singleTimer = 0;
    stage.addEventListener('pointerup', (e) => {
      if (e.target.closest('button, #vp-menu, #vp-loading, #vp-error') || !S || S.loading) return;
      const r = stage.getBoundingClientRect();
      const x = (e.clientX - r.left) / r.width;
      const side = x < 0.34 ? -1 : x > 0.66 ? 1 : 0;
      const now = Date.now();
      if (side && lastTap.side === side && now - lastTap.t < 320) {
        clearTimeout(singleTimer); lastTap = { t: 0, side: 0 };
        skip(side * SKIP); ripple(side);
        return;
      }
      lastTap = { t: now, side };
      clearTimeout(singleTimer);
      singleTimer = setTimeout(() => {
        if (S.menuOpen) { setMenu(false); return; }
        if (el.classList.contains('is-idle')) wake(); else if (!v.paused) el.classList.add('is-idle'); else toggle();
      }, 300);
    });
    el.addEventListener('pointermove', (e) => { if (e.pointerType === 'mouse') wake(); });
    el.addEventListener('focusin', wake);

    // Scrubber
    const bar = $('vp-scrub');
    const fracAt = (e) => { const r = bar.getBoundingClientRect(); return Math.max(0, Math.min(1, (e.clientX - r.left) / r.width)); };
    bar.addEventListener('pointerdown', (e) => {
      if (!S || S.loading) return;
      S.dragging = true; bar.setPointerCapture(e.pointerId); bar.classList.add('is-drag');
      preview(fracAt(e));
    });
    bar.addEventListener('pointermove', (e) => { if (S && S.dragging) preview(fracAt(e)); });
    const endDrag = (e) => {
      if (!S || !S.dragging) return;
      S.dragging = false; bar.classList.remove('is-drag');
      seekTo(fracAt(e) * duration());
    };
    bar.addEventListener('pointerup', endDrag);
    bar.addEventListener('pointercancel', () => { if (S) { S.dragging = false; bar.classList.remove('is-drag'); paint(); } });
    bar.addEventListener('keydown', (e) => {
      const map = { ArrowLeft: -5, ArrowRight: 5, ArrowDown: -5, ArrowUp: 5, PageDown: -30, PageUp: 30 };
      if (map[e.key] !== undefined) { e.preventDefault(); skip(map[e.key]); }
      else if (e.key === 'Home') { e.preventDefault(); seekTo(0); }
      else if (e.key === 'End') { e.preventDefault(); seekTo(duration()); }
    });

    // The video itself
    v.addEventListener('play', () => { setPlaying(true); wake(); });
    v.addEventListener('pause', () => { setPlaying(false); wake(); });
    v.addEventListener('ended', () => { setPlaying(false); S.ended = true; syncPlayIcons(); wake(); });
    v.addEventListener('timeupdate', paint);
    v.addEventListener('progress', paintBuffered);
    v.addEventListener('durationchange', paint);
    v.addEventListener('loadedmetadata', () => { paint(); });
    v.addEventListener('waiting', () => el.classList.add('is-buffering'));
    v.addEventListener('playing', () => el.classList.remove('is-buffering'));
    v.addEventListener('canplay', () => el.classList.remove('is-buffering'));
    v.addEventListener('volumechange', syncVolume);
    v.addEventListener('error', () => { if (S && !S.loading) showError(); });

    root.document.addEventListener('keydown', onKey, true);
    root.document.addEventListener('fullscreenchange', syncFullscreen);
    root.document.addEventListener('webkitfullscreenchange', syncFullscreen);
    v.addEventListener('webkitendfullscreen', syncFullscreen);

    if (!(root.document.pictureInPictureEnabled)) $('vp-pip').hidden = true;
  }

  const duration = () => (v && isFinite(v.duration) && v.duration > 0 ? v.duration : (S ? S.dur : 0)) || 0;

  /* -------------------------------------------------------------------- state paints */

  function paint() {
    if (!S) return;
    const d = duration();
    const t = S.dragging ? S.dragTime : v.currentTime;
    const p = d > 0 ? Math.min(1, t / d) : 0;
    $('vp-scrub').style.setProperty('--p', p.toFixed(4));
    $('vp-time').textContent = fmt(t);
    $('vp-dur').textContent = d > 0 ? fmt(d) : '–:––';
    const bar = $('vp-scrub');
    bar.setAttribute('aria-valuemax', String(Math.round(d)));
    bar.setAttribute('aria-valuenow', String(Math.round(t)));
    bar.setAttribute('aria-valuetext', `${fmt(t)} of ${d > 0 ? fmt(d) : 'unknown length'}`);
    paintBuffered();
  }

  function paintBuffered() {
    const d = duration();
    let end = 0;
    try { if (v.buffered && v.buffered.length) end = v.buffered.end(v.buffered.length - 1); } catch (e) { end = 0; }
    $('vp-scrub').style.setProperty('--b', (d > 0 ? Math.min(1, end / d) : 0).toFixed(4));
  }

  function preview(frac) {
    S.dragTime = frac * duration();
    const bub = $('vp-bubble');
    bub.textContent = fmt(S.dragTime);
    bub.style.setProperty('--x', (frac * 100).toFixed(2) + '%');
    paint();
  }

  function setPlaying(on) {
    el.classList.toggle('is-playing', on);
    if (on && S) S.ended = false;
    syncPlayIcons();
  }

  function syncPlayIcons() {
    const playing = !v.paused && !v.ended;
    const ended = S && S.ended;
    const icon = ended ? ICON.replay : playing ? ICON.pause : ICON.play;
    const label = ended ? 'Replay' : playing ? 'Pause' : 'Play';
    $('vp-center').innerHTML = icon; $('vp-center').setAttribute('aria-label', label);
    $('vp-play').innerHTML = icon; $('vp-play').setAttribute('aria-label', label);
  }

  function syncVolume() {
    $('vp-mute').innerHTML = v.muted || v.volume === 0 ? ICON.mute : ICON.vol;
    $('vp-mute').setAttribute('aria-label', v.muted ? 'Unmute' : 'Mute');
    $('vp-mute').setAttribute('aria-pressed', String(!!v.muted));
  }

  function syncFullscreen() {
    const on = !!(root.document.fullscreenElement || root.document.webkitFullscreenElement);
    $('vp-full').innerHTML = on ? ICON.unfull : ICON.full;
    $('vp-full').setAttribute('aria-label', on ? 'Exit full screen' : 'Full screen');
  }

  /* ----------------------------------------------------------------------- actions */

  function toggle() {
    if (!S || S.loading || S.failed) return;
    if (S.ended) { v.currentTime = 0; S.ended = false; }
    if (v.paused) { const p = v.play(); if (p && p.catch) p.catch(() => {}); } else v.pause();
  }

  function seekTo(t) {
    const d = duration();
    try { v.currentTime = Math.max(0, Math.min(d || t, t)); } catch (e) { /* not seekable yet */ }
    S.ended = false;
    paint();
  }

  function skip(by) { if (S && !S.loading) seekTo(v.currentTime + by); wake(); }

  function ripple(side) {
    const r = $(side < 0 ? 'vp-ripple-l' : 'vp-ripple-r');
    r.classList.remove('go'); void r.offsetWidth; r.classList.add('go');
  }

  function cycleSpeed() {
    S.speedIdx = (S.speedIdx + 1) % SPEEDS.length;
    v.playbackRate = SPEEDS[S.speedIdx];
    const label = SPEEDS[S.speedIdx] + '×';
    $('vp-speed').textContent = label;
    $('vp-speed').setAttribute('aria-label', 'Playback speed ' + label + '. Tap to change.');
  }

  function toggleFullscreen() {
    const d = root.document;
    if (d.fullscreenElement || d.webkitFullscreenElement) { (d.exitFullscreen || d.webkitExitFullscreen).call(d); return; }
    const req = el.requestFullscreen || el.webkitRequestFullscreen;
    if (req) { const p = req.call(el); if (p && p.catch) p.catch(() => {}); }
    else if (v.webkitEnterFullscreen) v.webkitEnterFullscreen(); // iPhone: only the video itself can go full screen
  }

  function togglePip() {
    const d = root.document;
    if (d.pictureInPictureElement) d.exitPictureInPicture().catch(() => {});
    else if (v.requestPictureInPicture) v.requestPictureInPicture().catch(() => {});
  }

  function setMenu(open) {
    S.menuOpen = open;
    $('vp-menu').hidden = !open;
    $('vp-menu-btn').setAttribute('aria-expanded', String(open));
    if (open) { wake(); $('vp-act-download').focus(); }
  }

  // Controls show on any interaction and fade after a few idle seconds of playback.
  function wake() {
    if (!el) return;
    el.classList.remove('is-idle');
    clearTimeout(wake.timer);
    wake.timer = setTimeout(() => {
      if (S && !v.paused && !S.menuOpen && !S.dragging) el.classList.add('is-idle');
    }, IDLE_MS);
  }

  function onKey(e) {
    if (!el || el.classList.contains('hidden') || !S) return;
    const confirmOpen = !$('overlay-confirm').classList.contains('hidden');
    if (confirmOpen) return; // "Remove this video?" is answered first
    if (e.key === 'Escape') {
      e.preventDefault(); e.stopPropagation();
      if (S.menuOpen) setMenu(false); else close();
      return;
    }
    if (e.target && e.target.closest && e.target.closest('button') && (e.key === ' ' || e.key === 'Enter')) return; // let the button act
    const k = e.key.toLowerCase();
    const acts = {
      ' ': toggle, k: toggle, arrowleft: () => skip(-5), arrowright: () => skip(5), j: () => skip(-SKIP), l: () => skip(SKIP),
      m: () => { v.muted = !v.muted; }, f: toggleFullscreen, home: () => seekTo(0),
    };
    if (e.target && e.target.id === 'vp-scrub' && (k.startsWith('arrow') || k === 'home' || k === 'end')) return; // the scrubber handles its own
    if (acts[k]) { e.preventDefault(); acts[k](); wake(); }
  }

  function showError() {
    S.failed = true;
    el.classList.add('has-error');
    el.classList.remove('is-buffering');
  }

  /* ------------------------------------------------------------------ open / close */

  async function open(opts) {
    wire();
    if (S) close();
    opener = root.document.activeElement;
    S = {
      dur: opts.dur || 0, loading: true, cancelled: false, menuOpen: false, dragging: false, dragTime: 0, ended: false, failed: false,
      speedIdx: 0, onDownload: opts.onDownload, onRemove: opts.onRemove, onDetails: opts.onDetails, onCompress: opts.onCompress, src: null,
    };
    el.classList.remove('hidden', 'has-error', 'is-playing', 'is-buffering', 'is-idle', 'is-ready');
    el.classList.add('is-loading');
    root.document.body.classList.add('vp-open');
    $('vp-title').textContent = opts.title || 'Video';
    $('vp-sub').textContent = opts.sub || '';
    const poster = $('vp-poster');
    if (opts.poster) { poster.src = opts.poster; poster.hidden = false; } else { poster.removeAttribute('src'); poster.hidden = true; }
    $('vp-menu').hidden = true;
    $('vp-act-compress').hidden = !opts.onCompress;
    $('vp-act-details').hidden = !opts.onDetails;
    $('vp-err-msg').textContent = 'This browser can\u2019t play this video. Download it to watch it somewhere else.';
    $('vp-load-text').textContent = 'Getting video ready\u2026';
    $('vp-load-count').textContent = '';
    $('vp-load-fill').style.transform = 'scaleX(0)';
    $('vp-speed').textContent = '1×';
    v.muted = false; v.playbackRate = 1;
    syncVolume(); syncFullscreen(); syncPlayIcons(); paint();
    $('vp-close').focus();

    const mine = S;
    try {
      const src = await opts.getSource((done, total, bytes, bytesTotal) => {
        if (S !== mine) return;
        const f = bytesTotal ? bytes / bytesTotal : (total ? done / total : 0);
        $('vp-load-fill').style.transform = `scaleX(${Math.min(1, f).toFixed(4)})`;
        $('vp-load-count').textContent = `${done} / ${total} parts`;
        $('vp-load-text').textContent = 'Getting video ready\u2026';
        $('vp-load').setAttribute('aria-valuenow', String(Math.round(f * 100)));
      }, () => S !== mine || mine.cancelled);
      if (S !== mine) { src.revoke(); return; }
      mine.src = src;
      mine.loading = false;
      el.classList.remove('is-loading');
      el.classList.add('is-ready');
      v.src = src.url;
      v.load();
      const p = v.play();
      if (p && p.catch) p.catch(() => { syncPlayIcons(); wake(); }); // a browser that wants a tap first: the big play button is right there
      wake();
    } catch (e) {
      if (S !== mine || (e && e.cancelled)) return;
      mine.loading = false;
      el.classList.remove('is-loading');
      $('vp-err-msg').textContent = (e && e.message) || 'This video couldn\u2019t be opened.';
      showError();
    }
  }

  function close() {
    if (!el || !S) { if (el) el.classList.add('hidden'); return; }
    S.cancelled = true;
    const src = S.src;
    S = null;
    clearTimeout(wake.timer);
    try { v.pause(); } catch (e) { /* closing anyway */ }
    v.removeAttribute('src');
    try { v.load(); } catch (e) { /* closing anyway */ }
    if (src) src.revoke();
    const d = root.document;
    if (d.fullscreenElement || d.webkitFullscreenElement) { try { (d.exitFullscreen || d.webkitExitFullscreen).call(d); } catch (e) { /* ignore */ } }
    if (d.pictureInPictureElement) d.exitPictureInPicture().catch(() => {});
    el.classList.add('hidden');
    d.body.classList.remove('vp-open');
    if (opener && opener.isConnected && opener.focus) { try { opener.focus(); } catch (e) { /* ignore */ } }
    opener = null;
  }

  root.KSPlayer = { open, close, isOpen() { return !!S; }, currentBlob() { return S && S.src ? S.src.blob : null; } };
})(typeof window !== 'undefined' ? window : globalThis);
