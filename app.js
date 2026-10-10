'use strict';

/*
 * group-whisper-link: temporary, end-to-end encrypted group chat (up to 6 people).
 *
 * Network: star topology. Each guest swaps a pair of copy-pasted codes with the host and gets a WebRTC
 *          data channel to the host. The host's browser forwards messages. There is no server.
 *
 * Trust:   every member makes ephemeral keys (ECDH P-256 for key wrapping, ECDSA P-256 for signatures).
 *          When the host starts the chat the member list (names + public keys) is frozen and every member
 *          computes the same 125-bit "group code" from it. Members compare that one code by voice. If the
 *          host swapped anyone's key, someone's code will differ.
 *
 * Crypto:  after confirming the code, each member creates a random sender chain key and sends it to every
 *          other member, wrapped with a pairwise ECDH-derived AES key (the host only sees ciphertext).
 *          Each message uses a fresh key from a one-way HMAC ratchet (AES-256-GCM) and is signed with the
 *          sender's ECDSA key, so the host can't read, forge, alter, or replay messages.
 */
(() => {
  // Refuse to run inside another page (clickjacking) and cut any link back to an opener (tab-napping).
  try { window.opener = null; } catch (e) { /* ignore */ }
  if (window.top !== window.self) {
    document.body.textContent = 'For your safety this page will not run inside another page. Open it directly in its own browser tab.';
    return;
  }

  const PROTO = 'whisper-group/v2';
  const MAX_GUESTS = 5;
  const MAX_NAME = 20;
  const MAX_ROSTER_NAME = 24;
  const MAX_TEXT = 2000;
  const MAX_FRAME_CHARS = 40000;
  const MAX_CODE_CHARS = 24000;
  const MAX_SDP_CHARS = 16000;
  const MAX_INBOX = 500;
  const MAX_SKIP = 50;            // largest gap accepted in one message
  const MAX_SKIP_TOTAL = 300;     // total gaps accepted per sender
  const MAX_DECOMPRESSED = 64 * 1024;
  const MAX_CANDIDATES = 12;
  const MAX_DOM_ITEMS = 500;
  const WINDOW_MS = 5000;
  const SLOT_MAX_FRAMES = 250;    // frames one guest may send the host per window
  const HOST_MAX_FRAMES = 1000;   // frames the host may send a guest per window
  const MAX_BAD = 20;             // invalid messages from one sender per window before muting them
  const MUTE_MS = 60000;
  const RESERVED_NAMES = ['you', 'host', 'system'];
  const CONNECT_HINT_MS = 90000;
  const ICE_WAIT_MS = 6000;
  const STUN_SERVERS = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'] }];

  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const $ = (id) => document.getElementById(id);
  const delay = (ms) => new Promise((r) => setTimeout(r, ms));

  /* ---------- state ---------- */

  const G = {
    isHost: false,
    myName: '',
    myIndex: -1,
    keys: null,           // { ecdhPriv, signPriv, ecdhB, signB }
    slots: [],            // host: one per invited person
    slotSeq: 0,
    link: null,           // guest: { pc, dc }
    roster: null,         // [{ i, name, ecdh, sign, ecdhKey, signKey }]
    groupHash: null,
    code: '',
    ownChain: null,
    recvChains: {},
    inbox: [],
    early: [],
    left: new Set(),
    started: false,
    opened: false,
    verifiedMe: false,
    ended: false,
    expiresAt: 0,
    tick: null,
    connectTimer: null,
    drainQ: Promise.resolve(),
    skQ: Promise.resolve(),
    sendQ: Promise.resolve(),
    pair: {},             // per member: { toThem, fromThem } one-shot wrapping keys
    bad: {},              // per sender: invalid-message counters
    muted: {},            // per sender: ignore until this time
    hostWin: { start: 0, count: 0 },
    expiry: 0,
  };

  /* ---------- helpers ---------- */

  const b64u = {
    enc(bytes) {
      let s = '';
      for (let i = 0; i < bytes.length; i += 0x8000) {
        s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
      }
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    },
    dec(str) {
      let s = str.replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4) s += '=';
      const bin = atob(s);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    },
  };

  const SCREENS = ['start', 'lobby', 'join', 'verify', 'chat', 'ended'];
  function show(name) {
    for (const n of SCREENS) $('screen-' + n).hidden = n !== name;
    const heading = $('screen-' + name).querySelector('h2');
    if (heading) {
      heading.tabIndex = -1;
      heading.focus({ preventScroll: true });
    }
  }

  function setStatusEl(el, msg, kind) {
    el.textContent = msg || '';
    if (kind) el.dataset.kind = kind;
    else delete el.dataset.kind;
  }
  const setStatus = (id, msg, kind) => setStatusEl($(id), msg, kind);

  // Only our own fixed messages are ever shown. Browser errors can echo attacker-controlled text.
  class UserError extends Error {}
  const errText = (e) => (e instanceof UserError ? e.message : 'Something went wrong. Please try again, or reload the page.');

  // Remove characters that can reorder or hide text (bidi overrides and isolates).
  const stripBidi = (t) => t.replace(/[\u202A-\u202E\u2066-\u2069]/g, '');

  // Names: NFKC-normalised letters, marks, digits, spaces and a little punctuation, in a single alphabet.
  // Returns '' when the name is not acceptable. Invisible and look-alike tricks are rejected here.
  function cleanName(s) {
    const t = String(s || '').normalize('NFKC').replace(/ +/g, ' ').trim();
    if (!t || t.length > MAX_ROSTER_NAME) return '';
    if (!/^[\p{L}\p{N}][\p{L}\p{M}\p{N} ._'()-]*$/u.test(t)) return '';
    if (/\p{Default_Ignorable_Code_Point}/u.test(t)) return '';
    const latin = /\p{Script=Latin}/u.test(t);
    const cyr = /\p{Script=Cyrillic}/u.test(t);
    const greek = /\p{Script=Greek}/u.test(t);
    if ((latin && cyr) || (latin && greek) || (cyr && greek)) return ''; // mixed alphabets are how look-alikes are built
    return t;
  }

  // Comparison form used to catch duplicates and reserved names.
  const foldName = (n) => n.normalize('NFKC').toLowerCase().replace(/[\s._'()-]+/g, '');

  function concat(...arrs) {
    const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
    let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  }

  function sendJson(dc, obj) {
    try {
      if (dc && dc.readyState === 'open') dc.send(JSON.stringify(obj));
    } catch (e) { /* closed meanwhile */ }
  }

  /* ---------- codes (SDP blobs) ---------- */

  async function pipeBytes(bytes, transform, maxOut) {
    const reader = new Blob([bytes]).stream().pipeThrough(transform).getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maxOut) {
        reader.cancel();
        throw new UserError('That code is too large.');
      }
      chunks.push(value);
    }
    const out = new Uint8Array(total);
    let o = 0;
    for (const c of chunks) { out.set(c, o); o += c.length; }
    return out;
  }

  async function packBlob(obj) {
    const raw = enc.encode(JSON.stringify(obj));
    if (typeof CompressionStream === 'function') {
      return 'WL1.' + b64u.enc(await pipeBytes(raw, new CompressionStream('deflate-raw'), MAX_DECOMPRESSED));
    }
    return 'WL0.' + b64u.enc(raw);
  }

  async function unpackBlob(text, expectedRole) {
    const t = String(text || '').replace(/\s+/g, '');
    if (t.length > MAX_CODE_CHARS) throw new UserError('That code is too long to be a group-whisper-link code.');
    const m = /^WL([01])\.([A-Za-z0-9_-]+)$/.exec(t);
    if (!m) throw new UserError("That doesn't look like a group-whisper-link code. Copy the whole thing, starting with WL.");
    let bytes;
    let obj;
    try {
      bytes = b64u.dec(m[2]);
      if (m[1] === '1') {
        if (typeof DecompressionStream !== 'function') throw new UserError('unsupported');
        bytes = await pipeBytes(bytes, new DecompressionStream('deflate-raw'), MAX_DECOMPRESSED);
      }
      obj = JSON.parse(dec.decode(bytes));
    } catch (e) {
      throw new UserError(e instanceof UserError ? e.message : 'The code is damaged or incomplete. Copy it again in full.');
    }
    if (!obj || obj.v !== 1) throw new UserError('Unsupported code version.');
    if (obj.r !== expectedRole) {
      throw new UserError(expectedRole === 'answer'
        ? 'That is an invite code. Paste the reply code the other person sent you.'
        : 'That is a reply code. Paste the invite code instead.');
    }
    if (typeof obj.s !== 'string' || obj.s.length > MAX_SDP_CHARS) throw new UserError('Malformed code.');
    return obj;
  }

  // The SDP must describe exactly one data channel and nothing else (no audio/video).
  function inspectSdp(sdp) {
    if (!/^v=0\r?\n/.test(sdp)) throw new UserError('Malformed connection data.');
    const mLines = sdp.match(/^m=.*$/gm) || [];
    if (mLines.length !== 1 || !/^m=application /.test(mLines[0])) {
      throw new UserError('This code asks for more than a text chat (audio or video). Refusing it.');
    }
    const fps = new Set();
    for (const m of sdp.matchAll(/^a=fingerprint:(\S+) ([0-9A-Fa-f:]+)\s*$/gm)) {
      if (m[1].toLowerCase() !== 'sha-256') throw new UserError('Unsupported fingerprint type.');
      fps.add(m[2].toUpperCase());
    }
    if (fps.size !== 1) throw new UserError('The code has no usable security fingerprint.');
  }

  function parsePk(b64) {
    let bytes;
    try { bytes = b64u.dec(b64); } catch (e) { throw new UserError('Malformed key.'); }
    if (bytes.length !== 65 || bytes[0] !== 4 || b64u.enc(bytes) !== b64) throw new UserError('Malformed key.');
    return bytes;
  }

  // True when s is canonical unpadded base64url of exactly `exact` bytes, or of min..max bytes.
  function isB64u(s, exact, max, min) {
    if (typeof s !== 'string' || !/^[A-Za-z0-9_-]+$/.test(s) || s.length > 20000) return false;
    try {
      const d = b64u.dec(s);
      if (exact !== undefined ? d.length !== exact : (d.length > max || d.length < (min || 0))) return false;
      return b64u.enc(d) === s;
    } catch (e) { return false; }
  }

  // Which network addresses from someone else's code are we willing to let the browser contact?
  function addressIsSafe(addr) {
    if (/^[0-9a-f-]{36}\.local$/i.test(addr)) return true; // browser-generated mDNS name
    const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(addr);
    if (v4) {
      const o = v4.slice(1).map(Number);
      if (o.some((x) => x > 255)) return false;
      if (o[0] === 0 || o[0] === 127 || o[0] >= 224) return false; // unspecified, loopback, multicast, reserved
      if (o[0] === 169 && o[1] === 254) return false;             // link-local
      return true;
    }
    if (/^[0-9a-f:]{2,45}$/i.test(addr) && addr.includes(':')) {
      const a = addr.toLowerCase();
      return !(a === '::' || a === '::1' || a.startsWith('fe80') || a.startsWith('ff'));
    }
    return false; // hostnames would trigger DNS lookups
  }

  function candidateIsSafe(line) {
    const p = line.slice('a=candidate:'.length).trim().split(/\s+/);
    if (p.length < 8 || p[6] !== 'typ') return false;
    const port = Number(p[5]);
    return p[2].toLowerCase() === 'udp'
      && ['host', 'srflx', 'prflx'].includes(p[7])
      && Number.isInteger(port) && port >= 1024 && port <= 65535
      && addressIsSafe(p[4]);
  }

  // Rebuild the other side's SDP keeping only what we need. Their candidate list decides which addresses
  // our browser will probe, so it is filtered and capped. Default address/port lines are neutralised.
  function sanitizeRemoteSdp(sdp) {
    const out = [];
    let kept = 0;
    for (const line of sdp.split(/\r?\n/)) {
      if (line === '') continue;
      if (line.startsWith('a=candidate:')) {
        if (kept < MAX_CANDIDATES && candidateIsSafe(line)) { out.push(line); kept++; }
        continue;
      }
      if (line.startsWith('c=')) { out.push('c=IN IP4 0.0.0.0'); continue; }
      if (line.startsWith('m=application ')) {
        if (!/^m=application \d+ UDP\/DTLS\/SCTP webrtc-datachannel$/.test(line)) throw new UserError('Unsupported connection type in this code.');
        out.push('m=application 9 UDP/DTLS/SCTP webrtc-datachannel');
        continue;
      }
      if (line.startsWith('a=remote-candidates') || line.startsWith('a=rtcp:')) continue;
      out.push(line);
    }
    if (!kept) throw new UserError('This code has no usable network address. Ask for a fresh one.');
    return out.join('\r\n') + '\r\n';
  }

  async function applyRemote(pc, type, sdp) {
    try {
      await pc.setRemoteDescription({ type, sdp });
    } catch (e) {
      throw new UserError("Your browser rejected the other side's connection data. Ask them to create a fresh code.");
    }
  }

  /* ---------- crypto ---------- */

  async function genIdentity() {
    const ecdh = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    const sign = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    G.keys = {
      ecdhPriv: ecdh.privateKey,
      signPriv: sign.privateKey,
      ecdhB: b64u.enc(new Uint8Array(await crypto.subtle.exportKey('raw', ecdh.publicKey))),
      signB: b64u.enc(new Uint8Array(await crypto.subtle.exportKey('raw', sign.publicKey))),
    };
  }

  const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford base32: no I, L, O, U

  function codeString(bytes, chars) {
    let bits = 0;
    let val = 0;
    let out = '';
    for (const b of bytes) {
      val = (val << 8) | b;
      bits += 8;
      while (bits >= 5) {
        out += ALPHABET[(val >>> (bits - 5)) & 31];
        bits -= 5;
      }
      val &= (1 << bits) - 1;
    }
    return out.slice(0, chars).match(/.{5}/g).join(' ');
  }

  async function hmac(keyBytes, byte) {
    const k = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', k, Uint8Array.of(byte)));
  }

  // One-way ratchet: message key = HMAC(chain, 1); next chain = HMAC(chain, 2). The old chain key is zeroed.
  async function ratchet(chain) {
    const mk = await hmac(chain.key, 1);
    const next = await hmac(chain.key, 2);
    chain.key.fill(0);
    chain.key = next;
    return { mk, n: chain.n++ };
  }

  function ivFor(n) {
    const iv = new Uint8Array(12);
    new DataView(iv.buffer).setBigUint64(4, BigInt(n));
    return iv;
  }

  // Binds every message to this exact group, sender and counter.
  function aadFor(sender, n) {
    const a = new Uint8Array(32 + 1 + 8);
    a.set(G.groupHash, 0);
    a[32] = sender;
    new DataView(a.buffer).setBigUint64(33, BigInt(n));
    return a;
  }

  function pad(bytes) {
    const total = Math.ceil((4 + bytes.length) / 256) * 256;
    const out = new Uint8Array(total);
    new DataView(out.buffer).setUint32(0, bytes.length);
    out.set(bytes, 4);
    return out;
  }

  function unpad(buf) {
    if (buf.length < 4) throw new UserError('bad padding');
    const len = new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(0);
    if (len > buf.length - 4) throw new UserError('bad padding');
    return buf.subarray(4, 4 + len);
  }

  // One-shot wrapping keys for every other member. They are derived once, the long-lived ECDH private key is
  // dropped straight away, and each wrapping key is deleted as soon as it has been used. Once the chain keys
  // have been exchanged nothing is left that could unwrap a recorded copy of them (forward secrecy).
  async function derivePairKeys(roster, groupHash, me) {
    const pair = {};
    for (const m of roster) {
      if (m.i === me) continue;
      const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: m.ecdhKey }, G.keys.ecdhPriv, 256);
      const hk = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
      new Uint8Array(shared).fill(0);
      const wrapKey = (from, to, usage) => crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: groupHash, info: enc.encode(`${PROTO} wrap ${from}>${to}`) },
        hk, { name: 'AES-GCM', length: 256 }, false, [usage]);
      pair[m.i] = { toThem: await wrapKey(me, m.i, 'encrypt'), fromThem: await wrapKey(m.i, me, 'decrypt') };
    }
    return pair;
  }

  function pairDone(j) {
    const p = G.pair[j];
    if (p && !p.toThem && !p.fromThem) delete G.pair[j];
  }

  async function wrapChainKeyFor(j, ck) {
    const p = G.pair[j];
    if (!p || !p.toThem) throw new UserError('No key available for that member.');
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: enc.encode(`${G.myIndex}>${j}`) }, p.toThem, ck));
    p.toThem = null;
    pairDone(j);
    return { t: 'relay', k: 'sk', f: G.myIndex, to: j, iv: b64u.enc(iv), ct: b64u.enc(ct) };
  }

  async function onSk(m) {
    const f = m.f;
    const p = G.pair[f];
    if (f === G.myIndex || G.recvChains[f] || !p || !p.fromThem) return;
    const iv = b64u.dec(m.iv);
    if (iv.length !== 12) throw new UserError('bad iv');
    const ck = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: enc.encode(`${f}>${G.myIndex}`) }, p.fromThem, b64u.dec(m.ct)));
    if (ck.length !== 32) throw new UserError('bad chain key');
    G.recvChains[f] = { key: ck, n: 0, skipped: 0 };
    p.fromThem = null;
    pairDone(f);
    updateReadiness();
    drain();
  }

  async function sealGroup(text) {
    const { mk, n } = await ratchet(G.ownChain);
    const key = await crypto.subtle.importKey('raw', mk, 'AES-GCM', false, ['encrypt']);
    mk.fill(0);
    const aad = aadFor(G.myIndex, n);
    const pt = pad(enc.encode(JSON.stringify({ text })));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivFor(n), additionalData: aad }, key, pt));
    const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, G.keys.signPriv, concat(aad, ct)));
    return { t: 'relay', k: 'm', f: G.myIndex, to: 'all', n, ct: b64u.enc(ct), sig: b64u.enc(sig) };
  }

  // Too many invalid messages "from" one member in a short time: stop spending CPU on them for a while.
  function noteBad(f) {
    const now = Date.now();
    let b = G.bad[f];
    if (!b || now - b.start > WINDOW_MS) b = G.bad[f] = { start: now, count: 0 };
    if (++b.count > MAX_BAD) {
      G.muted[f] = now + MUTE_MS;
      addSystem(`Ignoring messages claiming to be from ${G.roster[f].name} for a minute: too many invalid ones.`);
    }
  }

  async function processMsg(m, chain) {
    const sender = G.roster[m.f];
    if ((G.muted[m.f] || 0) > Date.now()) return;
    const aad = aadFor(m.f, m.n);
    const ct = b64u.dec(m.ct);
    const sig = b64u.dec(m.sig);
    const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, sender.signKey, sig, concat(aad, ct));
    if (!ok) {
      noteBad(m.f);
      addSystem(`A message claiming to be from ${sender.name} had an invalid signature and was ignored.`);
      return;
    }
    if (m.n < chain.n) return; // replay
    const gap = m.n - chain.n;
    if (gap > MAX_SKIP || chain.skipped + gap > MAX_SKIP_TOTAL) {
      addSystem(`Ignored a message from ${sender.name}: too many messages are missing before it.`);
      return;
    }
    for (let i = 0; i < gap; i++) {
      const skipped = await ratchet(chain);
      skipped.mk.fill(0);
    }
    chain.skipped += gap;
    const { mk } = await ratchet(chain);
    const key = await crypto.subtle.importKey('raw', mk, 'AES-GCM', false, ['decrypt']);
    mk.fill(0);
    let obj;
    try {
      const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivFor(m.n), additionalData: aad }, key, ct));
      obj = JSON.parse(dec.decode(unpad(pt)));
    } catch (e) {
      addSystem(`Could not decrypt a message from ${sender.name}.`);
      return;
    }
    if (gap) addSystem(`${gap} message${gap > 1 ? 's' : ''} from ${sender.name} never arrived (dropped or delayed on the way).`);
    if (obj && typeof obj.text === 'string' && obj.text.length <= MAX_TEXT) addMessage('them', obj.text, sender.name);
  }

  function drain() {
    G.drainQ = G.drainQ.then(runDrain).catch(() => {});
  }

  // Messages are taken one at a time, so a message that fails can never take its neighbours down with it.
  async function runDrain() {
    while (G.verifiedMe && !G.ended) {
      const idx = G.inbox.findIndex((m) => G.recvChains[m.f]);
      if (idx < 0) return;
      const m = G.inbox.splice(idx, 1)[0];
      try {
        await processMsg(m, G.recvChains[m.f]);
      } catch (e) {
        addSystem(`A message from ${G.roster[m.f].name} could not be processed and was skipped.`);
      }
    }
  }

  /* ---------- relay routing ---------- */

  // Strict shape check: ids and sizes must be exactly right and every blob canonical base64url.
  function validRelay(m) {
    if (!m || m.t !== 'relay') return false;
    if (!Number.isInteger(m.f) || m.f < 0 || m.f > MAX_GUESTS) return false;
    if (m.k === 'sk') {
      return Number.isInteger(m.to) && m.to >= 0 && m.to <= MAX_GUESTS && isB64u(m.iv, 12) && isB64u(m.ct, 48);
    }
    if (m.k === 'm') {
      return m.to === 'all' && Number.isSafeInteger(m.n) && m.n >= 0
        && isB64u(m.sig, 64) && isB64u(m.ct, undefined, 13000, 272);
    }
    return false;
  }

  // Send a relay message from this member: guests hand it to the host, the host fans it out.
  function sendRelay(msg) {
    if (G.isHost) hubForward(msg, null);
    else sendJson(G.link.dc, msg);
  }

  function hubForward(msg, fromSlot) {
    const targets = msg.to === 'all' ? G.slots.filter((s) => s !== fromSlot) : G.slots.filter((s) => s.index === msg.to);
    for (const s of targets) sendJson(s.dc, msg);
    if (fromSlot && (msg.to === 'all' || msg.to === 0)) handleRelay(msg);
  }

  function handleRelay(m) {
    if (!G.roster) {
      if (G.early.length < MAX_INBOX) G.early.push(m);
      return;
    }
    if (m.f >= G.roster.length || m.f === G.myIndex) return;
    if (m.k === 'sk') {
      if (m.to !== G.myIndex) return;
      G.skQ = G.skQ.then(() => onSk(m)).catch(() => {
        addSystem(`Could not read the key from ${G.roster[m.f].name}. Check that you both saw the same group code.`);
      });
    } else if (m.k === 'm') {
      G.inbox.push(m);
      if (G.inbox.length > MAX_INBOX) G.inbox.shift();
      drain();
    }
  }

  /* ---------- WebRTC ---------- */

  function makePc(onFailed) {
    const pc = new RTCPeerConnection({ iceServers: $('use-stun').checked ? STUN_SERVERS : [] });
    pc.onconnectionstatechange = () => {
      if (G.ended || pc.connectionState !== 'failed') return;
      onFailed();
    };
    return pc;
  }

  function waitForIce(pc) {
    return new Promise((resolve) => {
      if (pc.iceGatheringState === 'complete') return resolve();
      const timer = setTimeout(done, ICE_WAIT_MS);
      function done() {
        clearTimeout(timer);
        pc.removeEventListener('icegatheringstatechange', onChange);
        resolve();
      }
      function onChange() {
        if (pc.iceGatheringState === 'complete') done();
      }
      pc.addEventListener('icegatheringstatechange', onChange);
    });
  }

  const FAIL_HINT = "Couldn't connect. This can happen behind a strict firewall or NAT, because there is no relay server. Try again, on another network, or with STUN on.";

  /* ---------- host: lobby ---------- */

  async function createGroup() {
    G.isHost = true;
    try {
      await genIdentity();
    } catch (e) {
      setStatus('start-status', 'Could not create keys: ' + errText(e), 'error');
      return;
    }
    show('lobby');
    renderLobby();
    addSlot();
  }

  function joinedSlots() {
    return G.slots.filter((s) => s.joined && s.dc && s.dc.readyState === 'open');
  }

  // people: [{ name, me, host }]. "(you)" and "(host)" come from position, never from comparing names.
  function renderPeople(listEl, people) {
    listEl.textContent = '';
    for (const p of people) {
      const li = document.createElement('li');
      const tags = [p.me && 'you', p.host && 'host'].filter(Boolean);
      li.textContent = p.name + (tags.length ? ' (' + tags.join(', ') + ')' : '');
      if (p.me) li.className = 'me';
      listEl.append(li);
    }
  }

  function renderLobby() {
    renderPeople($('lobby-members'), [{ name: G.myName, me: true, host: true }, ...joinedSlots().map((s) => ({ name: s.name }))]);
    $('btn-start').disabled = joinedSlots().length < 1;
    $('btn-add-slot').disabled = G.slots.length >= MAX_GUESTS;
  }

  function broadcastLobby() {
    const names = [G.myName, ...joinedSlots().map((s) => s.name)];
    for (const s of joinedSlots()) sendJson(s.dc, { t: 'lobby', names });
  }

  function slotStatus(slot, msg, kind) {
    setStatusEl(slot.el.querySelector('.slot-status'), msg, kind);
  }

  async function addSlot() {
    if (G.slots.length >= MAX_GUESTS || G.started) return;
    const slot = { id: ++G.slotSeq, pc: null, dc: null, joined: false, name: '', ecdh: '', sign: '', index: -1, timer: null, win: { start: 0, count: 0 } };
    const el = $('slot-template').content.firstElementChild.cloneNode(true);
    slot.el = el;
    el.querySelector('.slot-title').textContent = 'Person ' + slot.id;
    el.querySelector('.copy-invite').addEventListener('click', () => copyFrom(el.querySelector('.invite-out'), el.querySelector('.slot-status')));
    el.querySelector('.paste-reply').addEventListener('click', () => pasteInto(el.querySelector('.reply-in'), el.querySelector('.slot-status')));
    el.querySelector('.connect').addEventListener('click', () => connectSlot(slot));
    el.querySelector('.remove').addEventListener('click', () => removeSlot(slot));
    $('slots').append(el);
    G.slots.push(slot);
    renderLobby();

    slotStatus(slot, 'Creating the invite code…');
    try {
      slot.pc = makePc(() => slotStatus(slot, FAIL_HINT, 'error'));
      slot.pc.ondatachannel = (ev) => ev.channel.close(); // we never expect a guest to open channels
      slot.dc = slot.pc.createDataChannel('chat');
      wireSlotChannel(slot);
      await slot.pc.setLocalDescription(await slot.pc.createOffer());
      await waitForIce(slot.pc);
      const sdp = slot.pc.localDescription.sdp;
      inspectSdp(sdp);
      el.querySelector('.invite-out').value = await packBlob({ v: 1, r: 'offer', s: sdp });
      el.querySelector('.connect').disabled = false;
      slotStatus(slot, 'Invite ready. Send it to this person only, then paste their reply.', 'ok');
    } catch (e) {
      slotStatus(slot, 'Could not create the invite: ' + errText(e), 'error');
    }
  }

  function closeSlot(slot) {
    clearTimeout(slot.timer);
    try { if (slot.dc) slot.dc.close(); } catch (e) { /* ignore */ }
    try { if (slot.pc) slot.pc.close(); } catch (e) { /* ignore */ }
    slot.el.remove();
  }

  function removeSlot(slot) {
    closeSlot(slot);
    G.slots = G.slots.filter((s) => s !== slot);
    renderLobby();
    broadcastLobby();
  }

  async function connectSlot(slot) {
    const btn = slot.el.querySelector('.connect');
    btn.disabled = true;
    try {
      slotStatus(slot, 'Checking the reply…');
      const msg = await unpackBlob(slot.el.querySelector('.reply-in').value, 'answer');
      inspectSdp(msg.s);
      const safeSdp = sanitizeRemoteSdp(msg.s);
      await applyRemote(slot.pc, 'answer', safeSdp);
      slotStatus(slot, 'Connecting…');
      clearTimeout(slot.timer);
      slot.timer = setTimeout(() => {
        if (!slot.joined) slotStatus(slot, "Still not connected. Check that the reply came from this person's invite. If you are on different networks, make sure STUN is ticked on both sides.", 'error');
      }, CONNECT_HINT_MS);
    } catch (e) {
      btn.disabled = false;
      slotStatus(slot, errText(e), 'error');
    }
  }

  function wireSlotChannel(slot) {
    const ch = slot.dc;
    ch.onopen = () => slotStatus(slot, 'Connected. Waiting for their details…');
    ch.onclose = () => onSlotClosed(slot);
    ch.onmessage = (ev) => {
      if (typeof ev.data !== 'string' || ev.data.length > MAX_FRAME_CHARS) return;
      // The host relays everything a guest sends to every other member, so one guest must not be able to flood it.
      const now = Date.now();
      if (now - slot.win.start > WINDOW_MS) { slot.win.start = now; slot.win.count = 0; }
      if (++slot.win.count > SLOT_MAX_FRAMES) {
        if (!slot.flooded) {
          slot.flooded = true;
          slotStatus(slot, (slot.name || 'This person') + ' was disconnected for sending data too fast.', 'error');
          if (G.started && slot.joined) addSystem((slot.name || 'A member') + ' was disconnected for sending data too fast.');
          try { slot.dc.close(); } catch (e) { /* ignore */ }
        }
        return;
      }
      let m;
      try { m = JSON.parse(ev.data); } catch (e) { return; }
      onSlotMessage(slot, m);
    };
  }

  // Checks a joining member's name and both public keys, including that the keys are real curve points.
  async function validateIdentity(name, ecdh, sign) {
    const clean = cleanName(name);
    if (!clean || clean !== name || clean.length > MAX_NAME || RESERVED_NAMES.includes(foldName(clean))) throw new UserError('bad name');
    parsePk(ecdh);
    parsePk(sign);
    await crypto.subtle.importKey('raw', b64u.dec(ecdh), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    await crypto.subtle.importKey('raw', b64u.dec(sign), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return clean;
  }

  function onSlotMessage(slot, m) {
    if (!m || typeof m.t !== 'string') return;
    if (m.t === 'hello') {
      if (G.started || slot.joined || slot.helloBusy) return;
      slot.helloBusy = true;
      validateIdentity(m.name, m.ecdh, m.sign).then((name) => {
        const taken = G.keys.ecdhB === m.ecdh || G.keys.signB === m.sign
          || G.slots.some((o) => o !== slot && o.joined && (o.ecdh === m.ecdh || o.sign === m.sign));
        if (taken) throw new UserError('duplicate keys');
        if (G.started || G.ended || slot.gone) return;
        slot.name = name;
        slot.ecdh = m.ecdh;
        slot.sign = m.sign;
        slot.joined = true;
        clearTimeout(slot.timer);
        slot.el.classList.add('joined');
        slotStatus(slot, slot.name + ' joined.', 'ok');
        renderLobby();
        broadcastLobby();
      }).catch(() => {
        slotStatus(slot, 'This person sent invalid details and was rejected. Remove this slot and invite them again.', 'error');
        try { slot.dc.close(); } catch (e) { /* ignore */ }
      });
    } else if (m.t === 'relay') {
      if (!G.started || !slot.joined || !validRelay(m) || m.f !== slot.index) return;
      hubForward(m, slot);
    } else if (m.t === 'bye') {
      onSlotClosed(slot);
    }
  }

  function onSlotClosed(slot) {
    if (G.ended || slot.gone) return;
    slot.gone = true;
    if (!G.started) {
      if (slot.joined) {
        slot.joined = false;
        slot.el.classList.remove('joined');
        slotStatus(slot, (slot.name || 'This person') + ' disconnected. Remove this slot or invite them again.', 'error');
        renderLobby();
        broadcastLobby();
      }
      return;
    }
    if (!slot.joined) return;
    G.left.add(slot.index);
    delete G.pair[slot.index];
    for (const s of G.slots) if (s !== slot) sendJson(s.dc, { t: 'left', i: slot.index });
    addSystem(slot.name + ' left the chat.');
    renderMembers();
    updateReadiness();
    try { slot.dc.close(); } catch (e) { /* ignore */ }
    try { slot.pc.close(); } catch (e) { /* ignore */ }
    if (G.slots.every((s) => G.left.has(s.index))) addSystem('Everyone else has left. You are alone in the chat.');
  }

  async function startChat() {
    const joined = joinedSlots();
    if (!joined.length || G.started) return;
    $('btn-start').disabled = true;
    $('btn-add-slot').disabled = true;
    try {
      const used = new Set([foldName(G.myName)]);
      const members = [{ i: 0, name: G.myName, ecdh: G.keys.ecdhB, sign: G.keys.signB }];
      joined.forEach((s, k) => {
        let nm = s.name;
        let c = 2;
        while (used.has(foldName(nm))) nm = `${s.name.slice(0, 14)} (${c++})`;
        used.add(foldName(nm));
        s.index = k + 1;
        s.name = nm;
        members.push({ i: s.index, name: nm, ecdh: s.ecdh, sign: s.sign });
      });
      // Everything that can fail is done before anyone is told the group has started.
      await prepareGroup(members, 0);
      for (const s of G.slots) if (!joined.includes(s)) closeSlot(s);
      G.slots = joined;
      G.started = true;
      const expiry = Number($('expiry').value);
      for (const s of joined) sendJson(s.dc, { t: 'roster', roster: members, expiry });
      showVerify(expiry);
    } catch (e) {
      endSession('Could not start the chat: ' + errText(e), true);
    }
  }

  /* ---------- guest: join ---------- */

  async function createReply() {
    G.isHost = false;
    $('btn-reply').disabled = true;
    $('reply-box').hidden = true;
    try {
      setStatus('join-status', 'Checking the invite…');
      const msg = await unpackBlob($('invite-in').value, 'offer');
      inspectSdp(msg.s);
      const safeSdp = sanitizeRemoteSdp(msg.s);

      if (G.link) {
        try { G.link.pc.close(); } catch (e) { /* ignore */ }
        G.link = null;
      }
      await genIdentity();
      const link = { pc: null, dc: null };
      G.link = link;
      link.pc = makePc(() => {
        if (G.opened) endSession('The connection to the host was lost.', false);
        else setStatus('join-status', FAIL_HINT, 'error');
      });
      link.pc.ondatachannel = (ev) => {
        const ch = ev.channel;
        const safe = ch.label === 'chat' && ch.ordered && ch.maxRetransmits === null
          && ch.maxPacketLifeTime === null && !ch.negotiated;
        if (link.dc || !safe) {
          ch.close();
          if (!link.dc && !safe) setStatus('join-status', 'The host tried to open an unsafe data channel, so it was refused.', 'error');
          return;
        }
        link.dc = ch;
        wireGuestChannel(link.dc);
        if (link.dc.readyState === 'open') onGuestOpen();
      };
      await applyRemote(link.pc, 'offer', safeSdp);
      await link.pc.setLocalDescription(await link.pc.createAnswer());
      await waitForIce(link.pc);
      const sdp = link.pc.localDescription.sdp;
      inspectSdp(sdp);
      $('reply-out').value = await packBlob({ v: 1, r: 'answer', s: sdp });
      $('reply-box').hidden = false;
      setStatus('join-status', 'Reply code ready. Send it to the host only and keep this page open.', 'ok');
      clearTimeout(G.connectTimer);
      G.connectTimer = setTimeout(() => {
        if (!G.opened && !G.ended) setStatus('join-status', "Still not connected. Check that the host pasted your reply code. If you are on different networks, make sure STUN is ticked on both sides.", 'error');
      }, CONNECT_HINT_MS);
    } catch (e) {
      setStatus('join-status', errText(e), 'error');
    } finally {
      $('btn-reply').disabled = false;
    }
  }

  function wireGuestChannel(ch) {
    ch.onopen = onGuestOpen;
    ch.onclose = () => {
      if (G.opened && !G.ended) endSession('The host disconnected, so the group chat has ended.', false);
    };
    ch.onmessage = (ev) => {
      if (typeof ev.data !== 'string' || ev.data.length > MAX_FRAME_CHARS) return;
      const now = Date.now();
      if (now - G.hostWin.start > WINDOW_MS) { G.hostWin.start = now; G.hostWin.count = 0; }
      if (++G.hostWin.count > HOST_MAX_FRAMES) {
        if (G.roster) addSystem('The host is sending data far too fast. Some of it was ignored.');
        return;
      }
      let m;
      try { m = JSON.parse(ev.data); } catch (e) { return; }
      onHostMessage(m);
    };
  }

  function onGuestOpen() {
    if (G.opened || G.ended) return;
    G.opened = true;
    clearTimeout(G.connectTimer);
    sendJson(G.link.dc, { t: 'hello', name: G.myName, ecdh: G.keys.ecdhB, sign: G.keys.signB });
    $('join-step1').hidden = true;
    $('reply-box').hidden = true;
    $('join-wait').hidden = false;
    renderPeople($('join-members'), []);
    setStatus('join-status', '');
  }

  function parseRoster(r) {
    if (!Array.isArray(r) || r.length < 2 || r.length > MAX_GUESTS + 1) throw new UserError('The host sent a group list of the wrong size.');
    const ecdhs = new Set();
    const signs = new Set();
    const names = new Set();
    r.forEach((m, k) => {
      if (!m || m.i !== k || typeof m.name !== 'string' || typeof m.ecdh !== 'string' || typeof m.sign !== 'string') throw new UserError('The host sent a malformed group list.');
      const clean = cleanName(m.name);
      if (!clean || clean !== m.name || RESERVED_NAMES.includes(foldName(clean))) throw new UserError('The host listed a member with an unacceptable name.');
      if (names.has(foldName(clean))) throw new UserError('The host listed two members with the same name.');
      names.add(foldName(clean));
      parsePk(m.ecdh);
      parsePk(m.sign);
      ecdhs.add(m.ecdh);
      signs.add(m.sign);
    });
    if (ecdhs.size !== r.length || signs.size !== r.length) throw new UserError('The host listed duplicate keys.');
    return r.map((m) => ({ i: m.i, name: m.name, ecdh: m.ecdh, sign: m.sign }));
  }

  async function onHostMessage(m) {
    if (!m || typeof m.t !== 'string' || G.ended) return;
    if (m.t === 'lobby') {
      if (G.started || !Array.isArray(m.names)) return;
      const names = m.names.slice(0, MAX_GUESTS + 1).map((n) => cleanName(n)).filter(Boolean);
      renderPeople($('join-members'), names.map((n, i) => ({ name: n, host: i === 0 })));
    } else if (m.t === 'roster') {
      if (G.started) return;
      G.started = true;
      try {
        const members = parseRoster(m.roster);
        const mine = members.filter((x) => x.ecdh === G.keys.ecdhB && x.sign === G.keys.signB);
        if (mine.length !== 1 || mine[0].i === 0) {
          throw new UserError("The host's group list doesn't contain your keys, so it may have been tampered with.");
        }
        G.renamedFrom = mine[0].name === G.myName ? '' : G.myName;
        G.myName = mine[0].name;
        const expiry = Number.isInteger(m.expiry) && m.expiry >= 0 && m.expiry <= 1440 ? m.expiry : 30;
        await prepareGroup(members, mine[0].i);
        showVerify(expiry);
      } catch (e) {
        endSession('The group could not be set up: ' + errText(e), true);
      }
    } else if (m.t === 'relay') {
      if (validRelay(m)) handleRelay(m);
    } else if (m.t === 'left') {
      if (!G.roster || !Number.isInteger(m.i) || m.i <= 0 || m.i >= G.roster.length || m.i === G.myIndex || G.left.has(m.i)) return;
      G.left.add(m.i);
      addSystem(G.roster[m.i].name + ' left the chat (reported by the host).');
      renderMembers();
      updateReadiness();
    } else if (m.t === 'bye') {
      endSession('The host ended the group chat.', false);
    }
  }

  /* ---------- verification and chat ---------- */

  // Imports every member's keys (rejecting anything that is not a real curve point), derives the group code and
  // the one-shot wrapping keys, then drops the ECDH private key. Nothing is published to G until all of it worked.
  async function prepareGroup(members, myIndex) {
    const roster = await Promise.all(members.map(async (m) => ({
      ...m,
      ecdhKey: await crypto.subtle.importKey('raw', b64u.dec(m.ecdh), { name: 'ECDH', namedCurve: 'P-256' }, false, []),
      signKey: await crypto.subtle.importKey('raw', b64u.dec(m.sign), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']),
    })));
    const canonical = [PROTO, String(members.length), ...members.map((m) => [m.i, m.name, m.ecdh, m.sign].join('|'))].join('\n');
    const groupHash = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(canonical)));
    const pair = await derivePairKeys(roster, groupHash, myIndex);
    G.keys.ecdhPriv = null;
    G.myIndex = myIndex;
    G.roster = roster;
    G.groupHash = groupHash;
    G.pair = pair;
    G.code = codeString(groupHash.subarray(0, 19), 30);
  }

  function showVerify(expiry) {
    $('group-code').textContent = G.code;
    $('group-code').setAttribute('aria-label', 'Group code: ' + G.code.split('').join(' '));
    renderPeople($('verify-members'), G.roster.map((m) => ({ name: m.name, me: m.i === G.myIndex, host: m.i === 0 })));
    $('verify-count').textContent = G.roster.length + ' people are in this group, counting you and the host.';
    $('verify-expiry').textContent = expiry ? 'Set by the host: the chat ends and wipes itself after ' + expiry + ' minutes.' : 'Set by the host: no time limit.';
    const note = $('verify-note');
    note.textContent = G.renamedFrom ? 'Notice: you asked to be called "' + G.renamedFrom + '", but the host listed you as "' + G.myName + '".' : '';
    note.hidden = !G.renamedFrom;
    G.opened = true;
    startTimer(expiry);
    show('verify');
    for (const m of G.early.splice(0)) handleRelay(m);
  }

  async function confirmMatch() {
    $('btn-match').disabled = true;
    G.verifiedMe = true;
    G.ownChain = { key: crypto.getRandomValues(new Uint8Array(32)), n: 0, skipped: 0 };
    show('chat');
    renderMembers();
    updateReadiness();
    addSystem('Group code confirmed on your side. Messages are end-to-end encrypted, and everyone in the group, including the host, can read them.');
    const ck = G.ownChain.key.slice();
    for (const m of G.roster) {
      if (m.i === G.myIndex) continue;
      try {
        sendRelay(await wrapChainKeyFor(m.i, ck));
      } catch (e) {
        setStatus('chat-status', 'Could not share your key with ' + m.name + '.', 'error');
      }
    }
    ck.fill(0);
    drain();
    $('msg-input').focus();
  }

  function renderMembers() {
    const box = $('chat-members');
    box.textContent = 'Members: ';
    G.roster.forEach((m, k) => {
      const span = document.createElement('span');
      const tags = [m.i === G.myIndex && 'you', m.i === 0 && 'host'].filter(Boolean);
      span.textContent = m.name + (tags.length ? ' (' + tags.join(', ') + ')' : '');
      if (G.left.has(m.i)) span.className = 'left';
      box.append(span);
      if (k < G.roster.length - 1) box.append(', ');
    });
  }

  // "Waiting for X" is cryptographic: it clears only when X's key has arrived. A member the host reports as
  // having left is only the host's word, so that is stated and never styled as success.
  function updateReadiness() {
    if (!G.verifiedMe || !G.roster) return;
    const el = $('peer-state');
    const missing = G.roster.filter((m) => m.i !== G.myIndex && !G.left.has(m.i) && !G.recvChains[m.i]).map((m) => m.name);
    if (missing.length) {
      el.textContent = 'Waiting for ' + missing.join(', ') + ' to confirm the code…';
      delete el.dataset.kind;
      return;
    }
    const gone = G.left.size;
    if (!gone) {
      el.textContent = 'Everyone is ready';
      el.dataset.kind = 'ok';
    } else if (G.isHost) {
      el.textContent = 'Everyone still here is ready (' + gone + ' left)';
      el.dataset.kind = 'ok';
    } else {
      el.textContent = 'Everyone else is ready (the host says ' + gone + ' left)';
      delete el.dataset.kind;
    }
  }

  function fmtTime(d) {
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function trimMessages() {
    const list = $('messages');
    while (list.childElementCount > MAX_DOM_ITEMS) list.firstElementChild.remove();
  }

  function addMessage(who, text, name) {
    const list = $('messages');
    const wrap = document.createElement('div');
    wrap.className = 'msg ' + who;
    if (who === 'them') {
      const label = document.createElement('div');
      label.className = 'who';
      label.textContent = name;
      wrap.append(label);
    }
    const bubble = document.createElement('div');
    bubble.className = 'bubble';
    bubble.textContent = stripBidi(text);
    const time = document.createElement('time');
    time.textContent = fmtTime(new Date());
    wrap.append(bubble, time);
    list.append(wrap);
    trimMessages();
    list.scrollTop = list.scrollHeight;
  }

  const sysSeen = new Map();
  function addSystem(text) {
    const now = Date.now();
    if (now - (sysSeen.get(text) || 0) < 5000) return; // the same notice at most every 5 seconds
    sysSeen.set(text, now);
    if (sysSeen.size > 200) sysSeen.clear();
    const el = document.createElement('div');
    el.className = 'sys';
    el.textContent = text;
    $('messages').append(el);
    trimMessages();
    $('messages').scrollTop = $('messages').scrollHeight;
  }

  async function sendMessage() {
    const input = $('msg-input');
    const text = input.value.replace(/\s+$/, '');
    if (!text || !G.verifiedMe) return;
    if (text.length > MAX_TEXT) {
      setStatus('chat-status', 'Message is too long (max ' + MAX_TEXT + ' characters).', 'error');
      return;
    }
    input.value = '';
    const job = G.sendQ.then(async () => {
      sendRelay(await sealGroup(text));
    });
    G.sendQ = job.catch(() => {});
    try {
      await job;
      addMessage('me', text, 'You');
      setStatus('chat-status', '');
    } catch (e) {
      input.value = text;
      setStatus('chat-status', 'Could not send: ' + errText(e), 'error');
    }
  }

  /* ---------- timer / teardown ---------- */

  function startTimer(minutes) {
    clearInterval(G.tick);
    if (!minutes) {
      $('countdown').textContent = 'No time limit';
      return;
    }
    G.expiresAt = Date.now() + minutes * 60000;
    G.tick = setInterval(updateTimer, 1000);
    updateTimer();
  }

  function updateTimer() {
    const left = G.expiresAt - Date.now();
    if (left <= 0) {
      endSession('The time limit was reached, so the chat was ended and wiped.', true);
      return;
    }
    const m = Math.floor(left / 60000);
    const s = Math.floor((left % 60000) / 1000);
    $('countdown').textContent = m + ':' + String(s).padStart(2, '0') + ' left';
  }

  async function endSession(reason, notify) {
    if (G.ended) return;
    G.ended = true;
    if (notify) {
      if (G.isHost) for (const s of G.slots) sendJson(s.dc, { t: 'bye' });
      else if (G.link) sendJson(G.link.dc, { t: 'bye' });
      await delay(250);
    }
    clearInterval(G.tick);
    clearTimeout(G.connectTimer);
    for (const s of G.slots) {
      clearTimeout(s.timer);
      try { if (s.dc) s.dc.close(); } catch (e) { /* ignore */ }
      try { if (s.pc) s.pc.close(); } catch (e) { /* ignore */ }
    }
    if (G.link) {
      try { if (G.link.dc) G.link.dc.close(); } catch (e) { /* ignore */ }
      try { if (G.link.pc) G.link.pc.close(); } catch (e) { /* ignore */ }
    }
    if (G.ownChain) G.ownChain.key.fill(0);
    for (const k of Object.keys(G.recvChains)) G.recvChains[k].key.fill(0);
    G.ownChain = null;
    G.recvChains = {};
    G.pair = {};
    G.bad = {};
    G.muted = {};
    G.keys = null;
    G.roster = null;
    G.groupHash = null;
    G.inbox = [];
    G.early = [];
    G.slots = [];
    G.link = null;
    G.renamedFrom = '';
    $('messages').textContent = '';
    $('slots').textContent = '';
    for (const id of ['msg-input', 'invite-in', 'reply-out']) $(id).value = '';
    $('group-code').textContent = '';
    $('ended-reason').textContent = reason;
    show('ended');
  }

  /* ---------- clipboard ---------- */

  async function copyFrom(el, statusEl) {
    el.focus();
    el.select();
    try {
      await navigator.clipboard.writeText(el.value);
      setStatusEl(statusEl, 'Copied to clipboard.', 'ok');
    } catch (e) {
      setStatusEl(statusEl, 'Select the text and press Ctrl+C (or Cmd+C) to copy it.');
    }
  }

  async function pasteInto(el, statusEl) {
    try {
      el.value = await navigator.clipboard.readText();
    } catch (e) {
      setStatusEl(statusEl, 'Your browser blocked automatic paste. Click in the box and press Ctrl+V (or Cmd+V).');
      el.focus();
    }
  }

  /* ---------- wiring ---------- */

  function requireName() {
    const name = cleanName($('my-name').value);
    if (!name || name.length > MAX_NAME || RESERVED_NAMES.includes(foldName(name))) {
      setStatus('start-status', 'Use 1 to 20 letters, numbers or spaces from a single alphabet. "You", "Host" and "System" are not allowed.', 'error');
      $('my-name').focus();
      return false;
    }
    G.myName = name;
    setStatus('start-status', '');
    return true;
  }

  function init() {
    const supported = !!(window.RTCPeerConnection && window.crypto && crypto.subtle && window.isSecureContext);
    if (!supported) {
      $('unsupported').hidden = false;
      $('btn-host').disabled = true;
      $('btn-join').disabled = true;
      return;
    }

    $('btn-host').addEventListener('click', () => { if (requireName()) createGroup(); });
    $('btn-join').addEventListener('click', () => {
      if (!requireName()) return;
      G.isHost = false;
      show('join');
      $('invite-in').focus();
    });
    $('btn-add-slot').addEventListener('click', addSlot);
    $('btn-start').addEventListener('click', startChat);
    $('btn-reply').addEventListener('click', createReply);
    $('copy-reply').addEventListener('click', () => copyFrom($('reply-out'), $('join-status')));
    $('paste-invite').addEventListener('click', () => pasteInto($('invite-in'), $('join-status')));
    for (const b of document.querySelectorAll('button.cancel')) {
      b.addEventListener('click', () => location.reload());
    }
    $('btn-match').addEventListener('click', confirmMatch);
    $('btn-nomatch').addEventListener('click', () => {
      endSession("You reported that the group details don't match. Someone may have tampered with the group, so the chat was cancelled.", true);
    });
    $('btn-end').addEventListener('click', () => {
      endSession(G.isHost ? 'You ended the group chat for everyone.' : 'You left the chat.', true);
    });
    $('btn-restart').addEventListener('click', () => location.reload());

    $('composer').addEventListener('submit', (e) => {
      e.preventDefault();
      sendMessage();
    });
    $('msg-input').addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
        e.preventDefault();
        sendMessage();
      }
    });
    $('reply-out').addEventListener('focus', (e) => e.target.select());

    window.addEventListener('beforeunload', (e) => {
      if (G.keys && !G.ended) e.preventDefault();
    });
  }

  init();
})();
