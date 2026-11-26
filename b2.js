/* Keepsake — b2.js
 * Talks straight to your Backblaze B2 bucket (its S3-compatible API), signed in the browser
 * with AWS Signature V4. There is no server in between: this file IS the storage layer.
 *
 * Bucket layout
 *   meta/{id}.json         { id, createdAt, updatedAt, lockType, unlockAt, title, preview, size, mediaSize }
 *                          (title is plain text even for locked notes; preview is null for them)
 *   content/{id}.json      plain {title, body, html?, images, drawing?, ...}  OR  encrypted {salt, iv, ciphertext}
 *   vault/{id}.txt         the second password of a time-locked note
 *   media/{id}/{name}      a note's photos and audio (see media.js)
 *
 * The four settings (endpoint, bucket, key ID, application key) live in this browser's local
 * storage only. Anyone who has the application key can read and delete the bucket.
 *
 * The bucket needs a CORS rule that lets this site's address call it (see the README).
 *
 * It exposes the same small API the rest of the app always used (listNotes, getNote, saveNote,
 * deleteNote, getVault, exportNote), so everything else - the offline cache, the outbox, the
 * locks - works exactly as before.
 */
(function (root) {
  'use strict';

  const LS = {
    endpoint: 'ks_b2_endpoint',
    bucket: 'ks_b2_bucket',
    keyId: 'ks_b2_keyId',
    appKey: 'ks_b2_appKey',
  };
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const EMPTY_SHA = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  // A media file is 32 hex characters. A video is stored as many small parts, each named
  // <video's 32 hex>.<part number, 5 digits> - the name itself tags which video a part belongs to and where
  // it goes, so the bucket stays self-describing even without the note that lists them.
  const NAME_RE = /^[a-f0-9]{32}(?:\.\d{5})?$/;
  const ORPHAN_GRACE_MS = 60 * 60 * 1000; // an unreferenced upload is only swept after an hour
  const META_CACHE_KEY = 'ks_b2_metacache';
  const CLOCK_KEY = 'ks_b2_clockoffset';

  /* ------------------------------------------------------------------ settings */

  function lsGet(k) { try { return root.localStorage.getItem(k) || ''; } catch (e) { return ''; } }
  function lsSet(k, v) { try { root.localStorage.setItem(k, v); } catch (e) { /* private mode */ } }
  function lsDel(k) { try { root.localStorage.removeItem(k); } catch (e) { /* private mode */ } }

  // Tolerates "https://s3.us-west-004.backblazeb2.com/" pasted with the scheme or a trailing slash.
  function cleanHost(s) { return String(s || '').trim().replace(/^https?:\/\//i, '').replace(/\/+$/, '').toLowerCase(); }

  const config = {
    endpoint() { return cleanHost(lsGet(LS.endpoint)); },
    bucket() { return lsGet(LS.bucket).trim(); },
    keyId() { return lsGet(LS.keyId).trim(); },
    appKey() { return lsGet(LS.appKey).trim(); },
    set({ endpoint, bucket, keyId, appKey }) {
      lsSet(LS.endpoint, cleanHost(endpoint));
      lsSet(LS.bucket, String(bucket || '').trim());
      lsSet(LS.keyId, String(keyId || '').trim());
      lsSet(LS.appKey, String(appKey || '').trim());
    },
    configured() { return !!(this.endpoint() && this.bucket() && this.keyId() && this.appKey()); },
    region() {
      const m = /^s3\.([a-z0-9-]+)\.backblazeb2\.com$/i.exec(this.endpoint());
      return m ? m[1].toLowerCase() : 'us-west-004';
    },
    clear() { Object.values(LS).forEach(lsDel); lsDel(META_CACHE_KEY); },
  };

  /* ------------------------------------------------------------------- helpers */

  function toHex(buf) {
    return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
  }

  async function hmacSha256(keyBytes, data) {
    const key = await root.crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await root.crypto.subtle.sign('HMAC', key, enc.encode(data)));
  }

  async function sha256Hex(data) {
    const bytes = typeof data === 'string' ? enc.encode(data) : data;
    return toHex(await root.crypto.subtle.digest('SHA-256', bytes));
  }

  // RFC 3986 percent-encoding, which is what SigV4 wants (encodeURIComponent leaves ! ' ( ) * alone).
  function uriEncode(s) {
    return encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
  }

  function xmlUnescape(s) {
    return String(s || '')
      .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
      .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
  }

  function nowAmzDate() {
    return new Date(clock.now()).toISOString().replace(/[:-]|\.\d{3}/g, ''); // 20260101T120000Z
  }

  // Builds the headers for one signed S3 request. `headers` are extra headers to sign
  // (lower-case names); host, x-amz-content-sha256 and x-amz-date are added.
  async function signV4({ method, host, path, query, payloadHash, region, keyId, secret, amzDate, headers }) {
    const date = amzDate.slice(0, 8);
    const all = { ...(headers || {}), host, 'x-amz-content-sha256': payloadHash, 'x-amz-date': amzDate };
    const names = Object.keys(all).sort();
    const canonicalHeaders = names.map((n) => n + ':' + String(all[n]).trim() + '\n').join('');
    const signedHeaders = names.join(';');
    const canonicalPath = path.split('/').map(uriEncode).join('/');
    const canonicalQuery = Object.keys(query || {})
      .map((k) => [uriEncode(k), uriEncode(query[k])])
      .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
      .map(([k, v]) => k + '=' + v)
      .join('&');
    const canonicalRequest = [method, canonicalPath, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash].join('\n');
    const scope = `${date}/${region}/s3/aws4_request`;
    const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, await sha256Hex(canonicalRequest)].join('\n');
    let k = await hmacSha256(enc.encode('AWS4' + secret), date);
    k = await hmacSha256(k, region);
    k = await hmacSha256(k, 's3');
    k = await hmacSha256(k, 'aws4_request');
    const signature = toHex(await hmacSha256(k, stringToSign));
    return {
      amzDate,
      canonicalQuery,
      canonicalPath,
      authorization: `AWS4-HMAC-SHA256 Credential=${keyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
    };
  }

  // Builds a presigned query-string URL for GET requests. Because the signature lives in
  // query parameters instead of an Authorization header, browsers treat plain GETs as
  // CORS simple requests and skip the OPTIONS preflight round trip.
  async function signV4Query({ method, host, path, query, region, keyId, secret, amzDate, expires }) {
    const date = amzDate.slice(0, 8);
    const scope = `${date}/${region}/s3/aws4_request`;
    const q = {
      ...(query || {}),
      'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
      'X-Amz-Credential': `${keyId}/${scope}`,
      'X-Amz-Date': amzDate,
      'X-Amz-Expires': String(expires || 300),
      'X-Amz-SignedHeaders': 'host',
    };
    const canonicalPath = path.split('/').map(uriEncode).join('/');
    const canonicalQuery = Object.keys(q)
      .map((k) => [uriEncode(k), uriEncode(q[k])])
      .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
      .map(([k, v]) => k + '=' + v)
      .join('&');
    const canonicalHeaders = 'host:' + String(host).trim() + '\n';
    const canonicalRequest = [method, canonicalPath, canonicalQuery, canonicalHeaders, 'host', 'UNSIGNED-PAYLOAD'].join('\n');
    const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, await sha256Hex(canonicalRequest)].join('\n');
    let k = await hmacSha256(enc.encode('AWS4' + secret), date);
    k = await hmacSha256(k, region);
    k = await hmacSha256(k, 's3');
    k = await hmacSha256(k, 'aws4_request');
    const signature = toHex(await hmacSha256(k, stringToSign));
    return {
      url: 'https://' + host + canonicalPath + '?' + canonicalQuery + '&X-Amz-Signature=' + signature,
      amzDate,
    };
  }

  /* ------------------------------------------------------------------------ clock */

  // Backblaze's clock versus this device's. Every reply that carries a readable Date header
  // refreshes it, so it is almost always current. Time-locked notes use this clock (the phone's
  // is only a fallback for display); ordinary notes use the phone's.
  let clockOffset = Number(lsGet(CLOCK_KEY)) || 0;
  let clockKnown = !!lsGet(CLOCK_KEY);
  let clockSyncedAt = 0;

  function setOffset(serverMs) {
    clockOffset = serverMs - Date.now();
    clockKnown = true;
    clockSyncedAt = Date.now();
    lsSet(CLOCK_KEY, String(clockOffset));
  }

  function noteServerDate(header) {
    const t = Date.parse(header || '');
    if (!isFinite(t)) return false;
    setOffset(t);
    return true;
  }

  const clock = {
    known() { return clockKnown; },
    offset() { return clockOffset; },
    // Best current guess of the server's time (falls back to the phone's if never synced).
    now() { return Date.now() + (clockKnown ? clockOffset : 0); },
    // Asks Backblaze for the time right now and returns it. Throws if it can't be reached.
    async sync() {
      const res = await s3ok('GET', '', { query: { 'list-type': '2', 'max-keys': '1' } });
      if (noteServerDate(res.headers.get('date'))) return Date.now() + clockOffset;
      // The bucket's CORS rule doesn't expose the Date header, so read the time off a file instead:
      // write a tiny one and take its LastModified from the listing body, which is always readable.
      await putText('clock/ping.txt', String(Date.now()));
      const hit = (await listAll('clock/')).find((o) => o.key === 'clock/ping.txt');
      if (!hit || !hit.modified) throw new Error('Couldn\u2019t read the server time from Backblaze');
      setOffset(hit.modified);
      return Date.now() + clockOffset;
    },
    // Re-syncs only if it has been a while (or never) in this session.
    async ensureFresh(maxAgeMs) {
      if (clockSyncedAt && Date.now() - clockSyncedAt < maxAgeMs) return;
      await this.sync();
    },
  };

  /* -------------------------------------------------------------------- errors */

  function networkError() {
    const err = new Error('Network error \u2014 check your connection');
    err.isNetworkError = true;
    return err;
  }

  function abortError() {
    const err = new Error('Aborted');
    err.name = 'AbortError';
    err.isAbortError = true;
    return err;
  }

  function notConfiguredError() {
    const err = new Error('Backblaze isn\u2019t set up yet \u2014 open Settings and fill in your bucket details.');
    err.status = 401;
    err.notConfigured = true;
    return err;
  }

  // Turns a Backblaze error response into an Error the app already knows how to show.
  // Key problems are reported as status 401 (the app's "check Settings" case).
  function apiError(status, code, message) {
    let text = message || ('Request failed (' + status + ')');
    let st = status;
    if (status === 403 && /^(InvalidAccessKeyId|SignatureDoesNotMatch|AccessDenied|InvalidAccessKey|InvalidSecurity)/.test(code || '')) {
      st = 401;
      text = code === 'AccessDenied'
        ? 'Backblaze refused access \u2014 the key needs Read and Write access to this bucket.'
        : 'Backblaze rejected the key \u2014 check the key ID and application key in Settings.';
    } else if (code === 'RequestTimeTooSkewed') {
      st = 400;
      text = 'This device\u2019s clock is more than 15 minutes off, so Backblaze refuses the request. Fix the date and time.';
    } else if (code === 'NoSuchBucket') {
      st = 400;
      text = 'Backblaze can\u2019t find that bucket \u2014 check the bucket name and endpoint in Settings.';
    }
    const err = new Error(text);
    err.status = st;
    err.code = code || '';
    err.body = { error: text };
    return err;
  }

  async function errorFromResponse(res) {
    let code = '';
    let message = '';
    try {
      const t = typeof res._errorText === 'string' ? res._errorText : await res.text();
      const c = /<Code>([\s\S]*?)<\/Code>/.exec(t);
      const m = /<Message>([\s\S]*?)<\/Message>/.exec(t);
      code = c ? xmlUnescape(c[1]) : '';
      message = m ? xmlUnescape(m[1]) : '';
    } catch (e) { /* no body */ }
    return apiError(res.status, code, message);
  }

  /* ------------------------------------------------------------ signed requests */

  const DEFAULT_FETCH_TIMEOUT_MS = 30000;

  function resolveCreds(creds) {
    if (creds) {
      const host = cleanHost(creds.endpoint);
      const bucketName = String(creds.bucket || '').trim();
      const keyId = String(creds.keyId || '').trim();
      const secret = String(creds.appKey || '').trim();
      if (!host || !bucketName || !keyId || !secret) throw notConfiguredError();
      const m = /^s3\.([a-z0-9-]+)\.backblazeb2\.com$/i.exec(host);
      return { host, bucket: bucketName, keyId, secret, region: m ? m[1] : 'us-west-004' };
    }
    if (!config.configured()) throw notConfiguredError();
    return { host: config.endpoint(), bucket: config.bucket(), keyId: config.keyId(), secret: config.appKey(), region: config.region() };
  }

  const RETRY_STATUS = new Set([408, 429, 500, 502, 503, 504]);
  const RETRY_DELAYS_MS = [800, 2400];
  function sleep(ms, signal) {
    if (!signal) return new Promise((r) => root.setTimeout(r, ms));
    if (signal.aborted) return Promise.resolve();
    return new Promise((resolve) => {
      const onAbort = () => { root.clearTimeout(t); resolve(); };
      const t = root.setTimeout(() => { signal.removeEventListener('abort', onAbort); resolve(); }, ms);
      signal.addEventListener('abort', onAbort, { once: true });
    });
  }

  function makeSignal(timeoutMs, callerSignal) {
    if (typeof root.AbortController !== 'function') {
      return { signal: callerSignal || undefined, cleanup() {} };
    }
    if (!callerSignal && !(timeoutMs > 0)) return { signal: undefined, cleanup() {} };
    const ac = new root.AbortController();
    let timer = null;
    const onCallerAbort = () => { try { ac.abort(); } catch (e) {} };
    if (callerSignal) {
      if (callerSignal.aborted) onCallerAbort();
      else callerSignal.addEventListener('abort', onCallerAbort, { once: true });
    }
    if (timeoutMs > 0) {
      timer = root.setTimeout(() => { try { ac.abort(); } catch (e) {} }, timeoutMs);
    }
    return {
      signal: ac.signal,
      cleanup() {
        if (timer) { root.clearTimeout(timer); timer = null; }
        if (callerSignal) callerSignal.removeEventListener('abort', onCallerAbort);
      },
    };
  }

  async function prepare(method, key, query, payloadHash, creds, extraHeaders) {
    const c = resolveCreds(creds);
    const path = '/' + c.bucket + (key ? '/' + key : '');
    const signHeaders = {};
    const outHeaders = {};
    if (extraHeaders) {
      for (const k of Object.keys(extraHeaders)) {
        const v = extraHeaders[k];
        if (v !== undefined && v !== null && v !== '') {
          signHeaders[k.toLowerCase()] = String(v);
          outHeaders[k] = String(v);
        }
      }
    }
    const signed = await signV4({
      method, host: c.host, path, query: query || {}, payloadHash,
      region: c.region, keyId: c.keyId, secret: c.secret,
      amzDate: nowAmzDate(),
      headers: signHeaders,
    });
    return {
      url: 'https://' + c.host + signed.canonicalPath + (signed.canonicalQuery ? '?' + signed.canonicalQuery : ''),
      headers: {
        ...outHeaders,
        'x-amz-date': signed.amzDate,
        'x-amz-content-sha256': payloadHash,
        'Authorization': signed.authorization,
      },
    };
  }

  async function preparePresignedGet(key, query, creds) {
    const c = resolveCreds(creds);
    const path = '/' + c.bucket + (key ? '/' + key : '');
    return signV4Query({
      method: 'GET', host: c.host, path, query: query || {},
      region: c.region, keyId: c.keyId, secret: c.secret,
      amzDate: nowAmzDate(), expires: 300,
    });
  }

  // One signed request. `body` (Uint8Array) is optional. Resolves with the Response; throws
  // a network error if the request never got an HTTP answer at all (or timed out), or AbortError
  // if the caller's signal aborted. When `readAs` ('bytes' | 'text') is set, the body is consumed
  // before the timeout timer is cleared so stalled body downloads still time out.
  async function s3(method, key, opts) {
    const o = opts || {};
    const timeoutMs = o.timeoutMs !== undefined ? o.timeoutMs : DEFAULT_FETCH_TIMEOUT_MS;
    const callerSignal = o.signal || null;
    const usePresignedGet = method === 'GET' && o.body === undefined && !o.forceHeaderSign;
    const payloadHash = usePresignedGet ? null : (o.payloadHash || (o.body ? await sha256Hex(o.body) : EMPTY_SHA));
    const maxAttempts = RETRY_DELAYS_MS.length + 1;
    let clockRetried = !!o._clockRetried;

    for (let attempt = 0; attempt < maxAttempts; ) {
      if (callerSignal && callerSignal.aborted) throw abortError();
      let url, headers;
      if (usePresignedGet) {
        const req = await preparePresignedGet(key, o.query, o.creds);
        url = req.url;
        headers = o.headers ? { ...o.headers } : undefined;
      } else {
        const req = await prepare(method, key, o.query, payloadHash, o.creds, o.signHeaders);
        url = req.url;
        headers = o.headers ? { ...req.headers, ...o.headers } : req.headers;
      }
      const init = { method, cache: 'no-store' };
      if (headers && Object.keys(headers).length) init.headers = headers;
      if (o.body !== undefined) init.body = o.body;
      const { signal, cleanup } = makeSignal(timeoutMs, callerSignal);
      if (signal) init.signal = signal;

      let res;
      try {
        res = await root.fetch(url, init);
        const gotDate = noteServerDate(res.headers.get('date'));
        // If the device clock was skewed and Backblaze gave us its Date header, retry once with the corrected clock.
        if (res.status === 403 && gotDate && !clockRetried) {
          let errText = '';
          try { errText = await res.text(); } catch (e) {}
          if (/RequestTimeTooSkewed/.test(errText)) {
            clockRetried = true;
            continue;
          }
          res._errorText = errText;
          return res;
        }
        if (RETRY_STATUS.has(res.status) && attempt < maxAttempts - 1) {
          if (res.body && typeof res.body.cancel === 'function') {
            try { res.body.cancel().catch(() => {}); } catch (e) {}
          }
        } else {
          if (res.ok) {
            if (o.readAs === 'bytes') res._data = new Uint8Array(await res.arrayBuffer());
            else if (o.readAs === 'text') res._data = await res.text();
          } else if (res.status !== 404) {
            try { res._errorText = await res.text(); } catch (e) { res._errorText = ''; }
          }
          return res;
        }
      } catch (e) {
        if (callerSignal && callerSignal.aborted) throw abortError();
        throw networkError();
      } finally {
        cleanup();
      }

      if (callerSignal && callerSignal.aborted) throw abortError();
      await sleep(RETRY_DELAYS_MS[attempt], callerSignal);
      if (callerSignal && callerSignal.aborted) throw abortError();
      attempt++;
    }
  }

  async function s3ok(method, key, opts) {
    const res = await s3(method, key, opts);
    if (!res.ok) throw await errorFromResponse(res);
    return res;
  }

  // PUT with upload progress (XHR rather than fetch). `bytes` is a Uint8Array.
  // Backblaze answers 503 "busy" now and then and asks clients to simply try again, so a
  // transient refusal (or one dropped connection while the device still says it is online) is
  // retried a couple of times before it is reported. Every attempt is signed afresh, and the
  // payload hash travels with the request, so Backblaze itself rejects a body that arrives damaged.
  async function putBytes(key, bytes, sha, onProgress, opts) {
    const hash = sha || await sha256Hex(bytes);
    let lastErr = null;
    let clockRetried = false;
    for (let attempt = 0; attempt <= RETRY_DELAYS_MS.length; attempt++) {
      try {
        return await putBytesOnce(key, bytes, hash, onProgress, opts);
      } catch (e) {
        lastErr = e;
        if (e.code === 'RequestTimeTooSkewed' && e._gotServerDate && clock.known() && !clockRetried && attempt === 0) {
          clockRetried = true;
          if (onProgress) onProgress(0, bytes.length);
          attempt--;
          continue;
        }
        const online = !root.navigator || root.navigator.onLine !== false;
        const transient = (e.status && RETRY_STATUS.has(e.status)) || (e.isNetworkError && online && attempt === 0);
        if (!transient || attempt === RETRY_DELAYS_MS.length) throw e;
        if (onProgress) onProgress(0, bytes.length); // the file starts over: so does its progress
        await sleep(RETRY_DELAYS_MS[attempt]);
      }
    }
    throw lastErr;
  }

  async function putBytesOnce(key, bytes, sha, onProgress, opts) {
    const extraHeaders = {};
    if (opts && opts.ifMatch) extraHeaders['If-Match'] = opts.ifMatch;
    if (opts && opts.ifNoneMatch) extraHeaders['If-None-Match'] = opts.ifNoneMatch;
    const req = await prepare('PUT', key, {}, sha, null, extraHeaders);
    return new Promise((resolve, reject) => {
      const xhr = new root.XMLHttpRequest();
      xhr.open('PUT', req.url);
      xhr.timeout = Math.max(60000, Math.min(600000, Math.ceil((bytes ? bytes.length : 0) / 20000) * 1000));
      for (const h of Object.keys(req.headers)) xhr.setRequestHeader(h, req.headers[h]);
      if (onProgress) xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(e.loaded, e.total); };
      xhr.onload = () => {
        const gotDate = noteServerDate(xhr.getResponseHeader('Date'));
        if (xhr.status >= 200 && xhr.status < 300) { resolve(); return; }
        let code = '';
        let message = '';
        try {
          const c = /<Code>([\s\S]*?)<\/Code>/.exec(xhr.responseText);
          const m = /<Message>([\s\S]*?)<\/Message>/.exec(xhr.responseText);
          code = c ? xmlUnescape(c[1]) : '';
          message = m ? xmlUnescape(m[1]) : '';
        } catch (e) { /* no body */ }
        const err = apiError(xhr.status, code, message);
        err._gotServerDate = gotDate;
        reject(err);
      };
      xhr.onerror = () => reject(networkError());
      xhr.ontimeout = () => reject(networkError());
      xhr.onabort = () => reject(networkError());
      xhr.send(bytes);
    });
  }

  async function getBytes(key, opts) {
    const res = await s3ok('GET', key, { ...(opts || {}), readAs: 'bytes' });
    return res._data;
  }

  // One slice of an object: bytes start..end (inclusive). { bytes, partial } - partial is false if the server
  // ignored the range and sent the whole object. null if the object does not exist. (A single byte range is a
  // CORS-safelisted header, so it needs no change to the bucket's CORS rule.)
  async function getRange(key, start, end, opts) {
    const o = opts || {};
    const headers = { ...(o.headers || {}), Range: 'bytes=' + start + '-' + end };
    const res = await s3('GET', key, { ...o, headers, readAs: 'bytes' });
    if (res.status === 404) return null;
    if (!res.ok) throw await errorFromResponse(res);
    return { bytes: res._data, partial: res.status === 206 };
  }

  async function getText(key, opts) { return dec.decode(await getBytes(key, opts)); }

  // Resolves with the object's bytes, or null if it doesn't exist.
  async function getBytesOrNull(key, opts) {
    const res = await s3('GET', key, { ...(opts || {}), readAs: 'bytes' });
    if (res.status === 404) return null;
    if (!res.ok) throw await errorFromResponse(res);
    return res._data;
  }

  async function putText(key, text, onProgress) {
    const bytes = enc.encode(text);
    return putBytes(key, bytes, await sha256Hex(bytes), onProgress);
  }

  async function deleteObject(key) {
    const res = await s3('DELETE', key);
    if (!res.ok && res.status !== 404) throw await errorFromResponse(res);
  }

  // Lists every object under a prefix: [{ key, size, modified, etag }]
  async function listAll(prefix) {
    const items = [];
    let token = null;
    for (let page = 0; page < 200; page++) {
      const query = { 'list-type': '2', prefix, 'max-keys': '1000' };
      if (token) query['continuation-token'] = token;
      const res = await s3ok('GET', '', { query, readAs: 'text' });
      const xml = res._data;
      for (const m of xml.matchAll(/<Contents>([\s\S]*?)<\/Contents>/g)) {
        const key = /<Key>([\s\S]*?)<\/Key>/.exec(m[1]);
        if (!key) continue;
        const size = /<Size>(\d+)<\/Size>/.exec(m[1]);
        const mod = /<LastModified>([\s\S]*?)<\/LastModified>/.exec(m[1]);
        const etag = /<ETag>([\s\S]*?)<\/ETag>/.exec(m[1]);
        items.push({
          key: xmlUnescape(key[1]),
          size: size ? Number(size[1]) : 0,
          modified: mod ? Date.parse(mod[1]) || 0 : 0,
          etag: etag ? xmlUnescape(etag[1]).replace(/"/g, '') : '',
        });
      }
      if (/<IsTruncated>true<\/IsTruncated>/.test(xml)) {
        const t = /<NextContinuationToken>([\s\S]*?)<\/NextContinuationToken>/.exec(xml);
        token = t ? xmlUnescape(t[1]) : null;
        if (!token) throw new Error('Bucket listing was truncated without a continuation token.');
        if (page === 199) throw new Error('Bucket listing exceeded the 200-page pagination limit.');
      } else break;
    }
    return items;
  }

  // How many bytes the bucket holds for exactly this key, or null if there is no such object.
  // (A listing by exact key works with the CORS rule the app has always needed - no HEAD required.)
  async function objectSize(key) {
    const res = await s3ok('GET', '', { query: { 'list-type': '2', prefix: key, 'max-keys': '1' }, readAs: 'text' });
    const xml = res._data;
    for (const m of xml.matchAll(/<Contents>([\s\S]*?)<\/Contents>/g)) {
      const k = /<Key>([\s\S]*?)<\/Key>/.exec(m[1]);
      if (!k || xmlUnescape(k[1]) !== key) continue;
      const sz = /<Size>(\d+)<\/Size>/.exec(m[1]);
      return sz ? Number(sz[1]) : 0;
    }
    return null;
  }

  // Reads back what the bucket actually stored and insists it is the size we sent. Nothing is
  // ever treated as saved until this passes.
  async function verifyStored(key, expectedBytes) {
    const got = await objectSize(key);
    if (got === expectedBytes) return;
    const err = new Error(got === null
      ? 'Backblaze didn\u2019t keep a file that was just sent \u2014 it will be sent again.'
      : 'Backblaze stored a file at the wrong size (' + got + ' of ' + expectedBytes + ' bytes) \u2014 it will be sent again.');
    err.verifyFailed = true;
    throw err;
  }

  /* ------------------------------------------------------------ connection test */

  // Tells apart the failures that matter. A browser reports a blocked cross-origin request
  // exactly like being offline, so when the signed request fails but the host itself answers,
  // it is almost certainly the bucket's CORS rule.
  async function testConnection(candidate) {
    let host;
    if (candidate) {
      host = cleanHost(candidate.endpoint);
      if (!host || !String(candidate.bucket || '').trim() || !String(candidate.keyId || '').trim() || !String(candidate.appKey || '').trim()) {
        return { ok: false, kind: 'config', message: 'Fill in all four fields first.' };
      }
    } else {
      if (!config.configured()) return { ok: false, kind: 'config', message: 'Fill in all four fields first.' };
      host = config.endpoint();
    }
    try {
      await s3ok('GET', '', { query: { 'list-type': '2', 'max-keys': '1' }, creds: candidate || null });
      return { ok: true };
    } catch (e) {
      if (!e.isNetworkError) {
        return { ok: false, kind: e.status === 401 ? 'auth' : 'other', message: e.message };
      }
      let reachable = false;
      try { await root.fetch('https://' + host + '/', { mode: 'no-cors', cache: 'no-store' }); reachable = true; } catch (e2) { /* unreachable */ }
      return reachable
        ? { ok: false, kind: 'cors', message: 'Backblaze answered, but this page isn\u2019t allowed to talk to the bucket. Add the CORS rule from the README (it must list ' + root.location.origin + ').' }
        : { ok: false, kind: 'network', message: 'Couldn\u2019t reach ' + host + ' \u2014 check the endpoint and your connection.' };
    }
  }

  /* ---------------------------------------------------------------------- notes */

  const metaKey = (id) => 'meta/' + id + '.json';
  const contentKey = (id, rev) => (Number.isFinite(rev) && rev > 0 ? 'content/' + id + '.' + rev + '.json' : 'content/' + id + '.json');
  const vaultKey = (id, rev) => (Number.isFinite(rev) && rev > 0 ? 'vault/' + id + '.' + rev + '.txt' : 'vault/' + id + '.txt');
  const mediaKey = (id, name) => 'media/' + id + '/' + name;

  function assertId(id) {
    if (typeof id !== 'string' || !UUID_RE.test(id)) {
      const err = new Error('Bad note id');
      err.status = 400;
      throw err;
    }
  }

  function notFound(message) {
    const err = new Error(message || 'Not found');
    err.status = 404;
    err.body = { error: err.message };
    return err;
  }

  function cleanCounts(c) {
    if (!c || typeof c !== 'object') return undefined;
    const n = (v) => (Number.isFinite(v) && v > 0 ? Math.min(Math.floor(v), 1e6) : 0);
    const out = { photos: n(c.photos), clips: n(c.clips), videos: n(c.videos) };
    return out.photos + out.clips + out.videos ? out : undefined;
  }

  function validUnlockAt(v) {
    const n = typeof v === 'number' ? v : (typeof v === 'string' && v.trim() !== '' ? Number(v) : NaN);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : null;
  }

  function metaFromBody(existing, body, now, size) {
    const lockType = body.lockType === 'quick' || body.lockType === 'time' ? body.lockType : 'none';
    const prevRev = existing && Number.isFinite(existing.rev) ? existing.rev : 0;
    return {
      id: existing ? existing.id : body.id,
      createdAt: existing ? existing.createdAt : now,
      updatedAt: now,
      rev: prevRev + 1,
      lockType,
      unlockAt: lockType === 'time' ? validUnlockAt(body.unlockAt) : null,
      // The title is stored in plain text for every note, locked or not, so a locked note can be
      // recognised on its card on any device. Only the preview (a slice of the body) stays plain
      // for unlocked notes alone - a locked note's text, photos and drawing are encrypted client-side.
      title: String(body.title || '').slice(0, 200),
      preview: lockType === 'none' ? String(body.preview || '') : null,
      // How big the stored content is (characters of its JSON). The app adds these up for its storage meter.
      size: Number.isFinite(size) ? size : undefined,
      // Bytes of photos/audio kept in the bucket for this note (as stored there, so encrypted
      // size for a locked note). The app adds these up for its second storage meter.
      mediaSize: Number.isFinite(body.mediaBytes) && body.mediaBytes > 0 ? Math.floor(body.mediaBytes) : undefined,
      // How many photos, clips and videos make up that size (shown in Settings -> Storage).
      counts: cleanCounts(body.mediaCounts),
    };
  }

  async function readMetaWithEtag(id) {
    const res = await s3('GET', metaKey(id), { readAs: 'bytes' });
    if (res.status === 404) return { meta: null, etag: null };
    if (!res.ok) throw await errorFromResponse(res);
    const etag = res.headers.get('etag') || null;
    try { return { meta: JSON.parse(dec.decode(res._data)), etag }; }
    catch (e) {
      return {
        meta: { id, createdAt: 0, updatedAt: 0, lockType: 'none', unlockAt: null, title: 'Damaged note (unreadable metadata)', preview: 'Metadata JSON in Backblaze could not be parsed.', corrupted: true },
        etag,
      };
    }
  }

  async function readMeta(id) {
    return (await readMetaWithEtag(id)).meta;
  }

  async function readContent(id, meta) {
    const key = (meta && meta.contentKey) || contentKey(id);
    const bytes = await getBytesOrNull(key);
    if (!bytes) throw notFound('Note content missing');
    return JSON.parse(dec.decode(bytes));
  }

  async function readVault(id, meta) {
    const key = (meta && meta.vaultKey) || vaultKey(id);
    const bytes = await getBytesOrNull(key);
    return bytes ? dec.decode(bytes) : null;
  }

  function loadMetaCache() {
    try { return JSON.parse(lsGet(META_CACHE_KEY) || '{}') || {}; } catch (e) { return {}; }
  }

  function saveMetaCache(cache) {
    try { root.localStorage.setItem(META_CACHE_KEY, JSON.stringify(cache)); } catch (e) { /* too big or private mode: just refetch next time */ }
  }

  // Runs `fn` over `items` a few at a time.
  async function pool(items, size, fn) {
    let next = 0;
    const workers = [];
    for (let w = 0; w < Math.min(size, items.length); w++) {
      workers.push((async () => {
        while (next < items.length) { const i = next++; await fn(items[i]); }
      })());
    }
    await Promise.all(workers);
  }

  async function listNotes() {
    const objs = await listAll('meta/');
    const cache = loadMetaCache();
    const fresh = {};
    const notes = [];
    const todo = [];
    for (const o of objs) {
      const m = /^meta\/([0-9a-f-]{36})\.json$/i.exec(o.key);
      if (!m || !UUID_RE.test(m[1])) continue;
      const stamp = o.etag + '|' + o.size + '|' + o.modified;
      const hit = cache[m[1]];
      if (hit && hit.stamp === stamp && hit.meta) { fresh[m[1]] = hit; notes.push(hit.meta); }
      else todo.push({ id: m[1], stamp });
    }
    await pool(todo, 6, async (t) => {
      const meta = await readMeta(t.id);
      if (!meta) return;
      fresh[t.id] = { stamp: t.stamp, meta };
      notes.push(meta);
    });
    saveMetaCache(fresh);
    notes.sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
    return { notes };
  }

  async function getNote(id) {
    assertId(id);
    const metaBytes = await getBytesOrNull(metaKey(id));
    if (!metaBytes) throw notFound('Not found');
    const meta = JSON.parse(dec.decode(metaBytes));
    const content = await readContent(id, meta);
    return { meta, content };
  }

  // Create and update are one idempotent path: the id always comes from the app (generated once,
  // the moment a note starts being edited), so saving twice with the same id is just a second
  // write to the same keys - never a second note. That is what makes it safe to retry a save
  // that appeared to fail, or to autosave in the background.
  async function saveNote(id, body, onProgress) {
    assertId(id);
    if (!body || body.content === undefined || body.content === null) {
      const err = new Error('Missing content');
      err.status = 400;
      throw err;
    }
    const { meta: existing, etag: existingEtag } = await readMetaWithEtag(id); // also refreshes the server clock
    // Optimistic concurrency check: if another device saved a newer revision since this edit began,
    // surface a 409 conflict instead of silently overwriting it (unless explicitly forced).
    if (existing && !existing.corrupted && !body.forceOverwrite) {
      const hasBaseRev = Number.isFinite(body.baseRev);
      const hasBaseUpdated = Number.isFinite(body.baseUpdatedAt);
      const revConflict = hasBaseRev && Number.isFinite(existing.rev) && existing.rev > body.baseRev;
      const timeConflict = !hasBaseRev && hasBaseUpdated && existing.updatedAt && existing.updatedAt > body.baseUpdatedAt;
      if (revConflict || timeConflict) {
        const err = new Error('This note was updated on another device since you opened it.');
        err.status = 409;
        err.conflict = true;
        err.serverMeta = existing;
        throw err;
      }
    }
    const now = body.lockType === 'time' ? clock.now() : Date.now();
    const contentJSON = JSON.stringify(body.content);
    const contentBytes = enc.encode(contentJSON);
    const meta = metaFromBody(existing && !existing.corrupted ? existing : null, { ...body, id }, now, contentBytes.length);

    // Write immutable revisioned content/vault objects before atomically flipping meta/{id}.json,
    // so an interrupted save or concurrent reader never sees half-updated content paired with old meta.
    const newContentKey = contentKey(id, meta.rev);
    meta.contentKey = newContentKey;
    let newVaultKey = null;
    if (meta.lockType === 'time' && body.password2) {
      newVaultKey = vaultKey(id, meta.rev);
      meta.vaultKey = newVaultKey;
    } else if (meta.lockType === 'time' && existing && !existing.corrupted && existing.vaultKey) {
      meta.vaultKey = existing.vaultKey;
    }

    // Order: content -> vault (for time-locked notes) -> meta.
    // Meta goes last and every file is verified before proceeding, so a dropped connection
    // never leaves a listed note missing its content or its time-lock vault password.
    await putBytes(newContentKey, contentBytes, await sha256Hex(contentBytes), onProgress ? (loaded, total) => onProgress(total ? loaded / total : 1) : null);
    await verifyStored(newContentKey, contentBytes.length);

    if (newVaultKey) {
      const vaultBytes = enc.encode(String(body.password2));
      await putBytes(newVaultKey, vaultBytes, await sha256Hex(vaultBytes), null);
      await verifyStored(newVaultKey, vaultBytes.length);
    }

    // Backblaze B2's S3-compatible PutObject API does not implement If-Match / If-None-Match
    // (returns 501 NotImplemented), so do a final pre-commit rev check right before flipping meta.
    if (existing && !existing.corrupted && !body.forceOverwrite && typeof body.baseRev === 'number') {
      const latestMeta = await readMeta(id).catch(() => null);
      if (latestMeta && !latestMeta.corrupted && typeof latestMeta.rev === 'number' && latestMeta.rev > body.baseRev) {
        deleteObject(newContentKey).catch(() => {});
        if (newVaultKey) deleteObject(newVaultKey).catch(() => {});
        const err = new Error('This note was updated on another device since you opened it.');
        err.status = 409;
        err.conflict = true;
        err.serverMeta = latestMeta;
        throw err;
      }
    }

    const metaBytes = enc.encode(JSON.stringify(meta));
    await putBytes(metaKey(id), metaBytes, await sha256Hex(metaBytes), null);
    await verifyStored(metaKey(id), metaBytes.length);

    // Best-effort cleanup of superseded content/vault objects now that meta points to the new revision.
    if (existing && !existing.corrupted) {
      const prevContentKey = existing.contentKey || contentKey(id);
      if (prevContentKey && prevContentKey !== newContentKey) {
        await deleteObject(prevContentKey).catch(() => {});
      }
      const prevVaultKey = existing.vaultKey || vaultKey(id);
      if (meta.lockType !== 'time') {
        if (prevVaultKey) await deleteObject(prevVaultKey).catch(() => {});
        if (prevVaultKey !== vaultKey(id)) await deleteObject(vaultKey(id)).catch(() => {});
      } else if (meta.vaultKey && prevVaultKey && prevVaultKey !== meta.vaultKey) {
        await deleteObject(prevVaultKey).catch(() => {});
      }
    } else if (meta.lockType !== 'time') {
      await deleteObject(vaultKey(id)).catch(() => {});
    }

    // The save lists every media file it refers to. Anything else stored for this note is an
    // orphan and is swept (after a grace period, see pruneMedia).
    if (Array.isArray(body.mediaKeep)) {
      const keep = body.mediaKeep.filter((n) => typeof n === 'string' && NAME_RE.test(n));
      pruneMedia(id, keep).catch(() => {}); // cleanup must never fail the save
    }
    return { note: meta };
  }

  async function deleteNote(id) {
    assertId(id);
    // Media first, then content & vault, and meta last: an interrupted media delete never
    // leaves meta pointing at missing content, and the delete can simply be repeated.
    const meta = await readMeta(id).catch(() => null);
    await deleteAllMedia(id);
    const keysToDelete = new Set([contentKey(id), vaultKey(id)]);
    if (meta && meta.contentKey) keysToDelete.add(meta.contentKey);
    if (meta && meta.vaultKey) keysToDelete.add(meta.vaultKey);
    for (const k of keysToDelete) await deleteObject(k);
    await deleteObject(metaKey(id));
    return { deleted: true };
  }

  // The second password of a time-locked note, handed out only once its unlock date has passed.
  // (This check runs in the app - see the README for what that means for the time lock.)
  async function getVault(id) {
    assertId(id);
    const meta = await readMeta(id);
    if (!meta) throw notFound('Not found');
    if (meta.lockType !== 'time') { const e = new Error('Not a time-locked note'); e.status = 400; throw e; }
    // The phone's clock is not consulted: ask Backblaze what time it is right now.
    const serverNow = await clock.sync();
    const unlockAt = validUnlockAt(meta.unlockAt);
    if (!unlockAt || serverNow < unlockAt) {
      const e = new Error('Still locked');
      e.status = 403;
      e.body = { error: 'Still locked' };
      throw e;
    }
    return { password2: await readVault(id, meta) };
  }

  async function exportNote(id) {
    assertId(id);
    const { meta, content } = await getNote(id);
    let password2 = null;
    if (meta.lockType === 'time') {
      password2 = await readVault(id, meta);
    }
    const out = { meta, content, password2 };
    if (password2) out._hint = 'password2 is the value above. Combine it with your own password to open this note before its unlock date.';
    return out;
  }

  /* ---------------------------------------------------------------------- media */

  async function listMedia(noteId) {
    assertId(noteId);
    const prefix = 'media/' + noteId + '/';
    const items = [];
    for (const o of await listAll(prefix)) {
      const name = o.key.slice(prefix.length);
      if (NAME_RE.test(name)) items.push({ name, size: o.size, modified: o.modified });
    }
    return items;
  }

  async function deleteMedia(noteId, names) {
    await pool(names, 6, (name) => deleteObject(mediaKey(noteId, name)));
  }

  // Deletes uploads no saved version of the note refers to any more (a photo removed from the
  // note, a re-encrypted copy, an abandoned upload). Anything younger than an hour is left alone
  // so a save still in flight can't lose the files it is about to reference.
  async function pruneMedia(noteId, keepNames) {
    const keep = new Set(keepNames);
    const cutoff = clock.now() - ORPHAN_GRACE_MS;
    const stale = (await listMedia(noteId)).filter((i) => !keep.has(i.name) && i.modified < cutoff);
    await deleteMedia(noteId, stale.map((i) => i.name));
  }

  async function deleteAllMedia(noteId) {
    await deleteMedia(noteId, (await listMedia(noteId)).map((i) => i.name));
  }

  root.KSB2 = {
    config,
    clock,
    testConnection,
    // storage primitives (also used by media.js)
    getBytes, getBytesOrNull, getRange, getText, putBytes, putText, deleteObject, listAll, sha256Hex, objectSize, verifyStored,
    // notes
    listNotes, getNote, saveNote, deleteNote, getVault, exportNote,
    // media
    listMedia, deleteMedia, mediaKey,
    // handy for the tests
    _test: { signV4, signV4Query, validUnlockAt, uriEncode, metaFromBody, metaKey, contentKey, vaultKey },
  };
})(typeof window !== 'undefined' ? window : globalThis);
