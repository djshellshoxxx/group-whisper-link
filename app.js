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
  const PROTO = 'whisper-group/v1';
  const MAX_GUESTS = 5;
  const MAX_NAME = 20;
  const MAX_ROSTER_NAME = 24;
  const MAX_TEXT = 2000;
  const MAX_FRAME_CHARS = 40000;
  const MAX_CODE_CHARS = 24000;
  const MAX_SDP_CHARS = 16000;
  const MAX_INBOX = 500;
  const MAX_SKIP = 1000;
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

  const errText = (e) => (e && e.message) || String(e);

  // Strip control and bidi-override characters so a name can't spoof or break the layout.
  function cleanName(s) {
    return String(s || '')
      .replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]/g, '')
      .trim();
  }

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

  async function pipeBytes(bytes, transform) {
    const stream = new Blob([bytes]).stream().pipeThrough(transform);
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  async function packBlob(obj) {
    const raw = enc.encode(JSON.stringify(obj));
    if (typeof CompressionStream === 'function') {
      return 'WL1.' + b64u.enc(await pipeBytes(raw, new CompressionStream('deflate-raw')));
    }
    return 'WL0.' + b64u.enc(raw);
  }

  async function unpackBlob(text, expectedRole) {
    const t = String(text || '').replace(/\s+/g, '');
    if (t.length > MAX_CODE_CHARS) throw new Error('That code is too long to be a group-whisper-link code.');
    const m = /^WL([01])\.([A-Za-z0-9_-]+)$/.exec(t);
    if (!m) throw new Error("That doesn't look like a group-whisper-link code. Copy the whole thing, starting with WL.");
    let bytes;
    let obj;
    try {
      bytes = b64u.dec(m[2]);
      if (m[1] === '1') {
        if (typeof DecompressionStream !== 'function') throw new Error('unsupported');
        bytes = await pipeBytes(bytes, new DecompressionStream('deflate-raw'));
      }
      obj = JSON.parse(dec.decode(bytes));
    } catch (e) {
      throw new Error('The code is damaged or incomplete. Copy it again in full.');
    }
    if (!obj || obj.v !== 1) throw new Error('Unsupported code version.');
    if (obj.r !== expectedRole) {
      throw new Error(expectedRole === 'answer'
        ? 'That is an invite code. Paste the reply code the other person sent you.'
        : 'That is a reply code. Paste the invite code instead.');
    }
    if (typeof obj.s !== 'string' || obj.s.length > MAX_SDP_CHARS) throw new Error('Malformed code.');
    return obj;
  }

  // The SDP must describe exactly one data channel and nothing else (no audio/video).
  function inspectSdp(sdp) {
    if (!/^v=0\r?\n/.test(sdp)) throw new Error('Malformed connection data.');
    const mLines = sdp.match(/^m=.*$/gm) || [];
    if (mLines.length !== 1 || !/^m=application /.test(mLines[0])) {
      throw new Error('This code asks for more than a text chat (audio or video). Refusing it.');
    }
    const fps = new Set();
    for (const m of sdp.matchAll(/^a=fingerprint:(\S+) ([0-9A-Fa-f:]+)\s*$/gm)) {
      if (m[1].toLowerCase() !== 'sha-256') throw new Error('Unsupported fingerprint type.');
      fps.add(m[2].toUpperCase());
    }
    if (fps.size !== 1) throw new Error('The code has no usable security fingerprint.');
  }

  function parsePk(b64) {
    let bytes;
    try { bytes = b64u.dec(b64); } catch (e) { throw new Error('Malformed key.'); }
    if (bytes.length !== 65 || bytes[0] !== 4) throw new Error('Malformed key.');
    return bytes;
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
    if (buf.length < 4) throw new Error('bad padding');
    const len = new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(0);
    if (len > buf.length - 4) throw new Error('bad padding');
    return buf.subarray(4, 4 + len);
  }

  // Pairwise AES key for wrapping a sender chain key from member `from` to member `to`.
  async function pairKey(from, to) {
    const peer = G.roster[from === G.myIndex ? to : from];
    const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: peer.ecdhKey }, G.keys.ecdhPriv, 256);
    const hk = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: G.groupHash, info: enc.encode(`${PROTO} wrap ${from}>${to}`) },
      hk, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }

  async function wrapChainKeyFor(j, ck) {
    const key = await pairKey(G.myIndex, j);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: enc.encode(`${G.myIndex}>${j}`) }, key, ck));
    return { t: 'relay', k: 'sk', f: G.myIndex, to: j, iv: b64u.enc(iv), ct: b64u.enc(ct) };
  }

  async function onSk(m) {
    const f = m.f;
    if (f === G.myIndex || G.recvChains[f] || G.left.has(f)) return;
    const iv = b64u.dec(m.iv);
    if (iv.length !== 12) throw new Error('bad iv');
    const key = await pairKey(f, G.myIndex);
    const ck = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: enc.encode(`${f}>${G.myIndex}`) }, key, b64u.dec(m.ct)));
    if (ck.length !== 32) throw new Error('bad chain key');
    G.recvChains[f] = { key: ck, n: 0 };
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

  async function processMsg(m, chain) {
    const sender = G.roster[m.f];
    const aad = aadFor(m.f, m.n);
    const ct = b64u.dec(m.ct);
    const sig = b64u.dec(m.sig);
    const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, sender.signKey, sig, concat(aad, ct));
    if (!ok) {
      addSystem(`A message claiming to be from ${sender.name} had an invalid signature and was ignored.`);
      return;
    }
    if (m.n < chain.n) return; // replay
    if (m.n - chain.n > MAX_SKIP) {
      addSystem(`Ignored a message from ${sender.name} that skipped too far ahead.`);
      return;
    }
    let lost = 0;
    while (chain.n < m.n) {
      const skipped = await ratchet(chain);
      skipped.mk.fill(0);
      lost++;
    }
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
    if (lost) addSystem(`${lost} message${lost > 1 ? 's' : ''} from ${sender.name} never arrived (the host may have dropped them).`);
    if (obj && typeof obj.text === 'string' && obj.text.length <= MAX_TEXT) addMessage('them', obj.text, sender.name);
  }

  function drain() {
    G.drainQ = G.drainQ.then(runDrain).catch(() => {});
  }

  async function runDrain() {
    if (!G.verifiedMe || G.ended) return;
    const batch = G.inbox;
    G.inbox = [];
    const keep = [];
    for (const m of batch) {
      if (G.ended) return;
      const chain = G.recvChains[m.f];
      if (!chain) keep.push(m);
      else await processMsg(m, chain);
    }
    G.inbox = keep.concat(G.inbox);
  }

  /* ---------- relay routing ---------- */

  function validRelay(m) {
    if (!m || m.t !== 'relay') return false;
    if (!Number.isInteger(m.f) || m.f < 0 || m.f > MAX_GUESTS) return false;
    if (m.k === 'sk') {
      return Number.isInteger(m.to) && m.to >= 0 && m.to <= MAX_GUESTS
        && typeof m.iv === 'string' && m.iv.length <= 24 && typeof m.ct === 'string' && m.ct.length <= 200;
    }
    if (m.k === 'm') {
      return m.to === 'all' && Number.isSafeInteger(m.n) && m.n >= 0
        && typeof m.ct === 'string' && m.ct.length <= 24000 && typeof m.sig === 'string' && m.sig.length <= 200;
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
        addSystem(`Could not read the key from ${G.roster[m.f].name}.`);
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

  function renderNames(listEl, names, meName) {
    listEl.textContent = '';
    for (const n of names) {
      const li = document.createElement('li');
      li.textContent = n === meName ? n + ' (you)' : n;
      if (n === meName) li.className = 'me';
      listEl.append(li);
    }
  }

  function lobbyNames() {
    return [G.myName, ...joinedSlots().map((s) => s.name)];
  }

  function renderLobby() {
    renderNames($('lobby-members'), lobbyNames(), G.myName);
    $('btn-start').disabled = joinedSlots().length < 1;
    $('btn-add-slot').disabled = G.slots.length >= MAX_GUESTS;
  }

  function broadcastLobby() {
    const names = lobbyNames();
    for (const s of joinedSlots()) sendJson(s.dc, { t: 'lobby', names });
  }

  function slotStatus(slot, msg, kind) {
    setStatusEl(slot.el.querySelector('.slot-status'), msg, kind);
  }

  async function addSlot() {
    if (G.slots.length >= MAX_GUESTS || G.started) return;
    const slot = { id: ++G.slotSeq, pc: null, dc: null, joined: false, name: '', ecdh: '', sign: '', index: -1, timer: null };
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
      slot.dc = slot.pc.createDataChannel('chat');
      wireSlotChannel(slot);
      await slot.pc.setLocalDescription(await slot.pc.createOffer());
      await waitForIce(slot.pc);
      const sdp = slot.pc.localDescription.sdp;
      inspectSdp(sdp);
      el.querySelector('.invite-out').value = await packBlob({ v: 1, r: 'offer', s: sdp });
      el.querySelector('.connect').disabled = false;
      slotStatus(slot, 'Invite ready. Send it to this person, then paste their reply.', 'ok');
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
      await slot.pc.setRemoteDescription({ type: 'answer', sdp: msg.s });
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
      let m;
      try { m = JSON.parse(ev.data); } catch (e) { return; }
      onSlotMessage(slot, m);
    };
  }

  function onSlotMessage(slot, m) {
    if (!m || typeof m.t !== 'string') return;
    if (m.t === 'hello') {
      if (G.started || slot.joined) return;
      try {
        const name = cleanName(m.name);
        if (!name || name !== m.name || name.length > MAX_NAME) throw new Error('bad name');
        parsePk(m.ecdh);
        parsePk(m.sign);
        slot.name = name;
        slot.ecdh = m.ecdh;
        slot.sign = m.sign;
      } catch (e) {
        slotStatus(slot, 'This person sent invalid details and was rejected.', 'error');
        return;
      }
      slot.joined = true;
      clearTimeout(slot.timer);
      slot.el.classList.add('joined');
      slotStatus(slot, slot.name + ' joined.', 'ok');
      renderLobby();
      broadcastLobby();
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
      const used = new Set([G.myName.toLowerCase()]);
      const members = [{ i: 0, name: G.myName, ecdh: G.keys.ecdhB, sign: G.keys.signB }];
      joined.forEach((s, k) => {
        let nm = s.name;
        let c = 2;
        while (used.has(nm.toLowerCase())) nm = `${s.name.slice(0, 14)} (${c++})`;
        used.add(nm.toLowerCase());
        s.index = k + 1;
        s.name = nm;
        members.push({ i: s.index, name: nm, ecdh: s.ecdh, sign: s.sign });
      });
      for (const s of G.slots) if (!joined.includes(s)) closeSlot(s);
      G.slots = joined;
      G.started = true;
      const expiry = Number($('expiry').value);
      for (const s of joined) sendJson(s.dc, { t: 'roster', roster: members, expiry });
      await enterVerify(members, 0, expiry);
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
        if (link.dc || ev.channel.label !== 'chat') {
          ev.channel.close();
          return;
        }
        link.dc = ev.channel;
        wireGuestChannel(link.dc);
        if (link.dc.readyState === 'open') onGuestOpen();
      };
      await link.pc.setRemoteDescription({ type: 'offer', sdp: msg.s });
      await link.pc.setLocalDescription(await link.pc.createAnswer());
      await waitForIce(link.pc);
      const sdp = link.pc.localDescription.sdp;
      inspectSdp(sdp);
      $('reply-out').value = await packBlob({ v: 1, r: 'answer', s: sdp });
      $('reply-box').hidden = false;
      setStatus('join-status', 'Reply code ready. Send it to the host and keep this page open.', 'ok');
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
    renderNames($('join-members'), [], G.myName);
    setStatus('join-status', '');
  }

  function parseRoster(r) {
    if (!Array.isArray(r) || r.length < 2 || r.length > MAX_GUESTS + 1) throw new Error('bad roster size');
    const ecdhs = new Set();
    const signs = new Set();
    r.forEach((m, k) => {
      if (!m || m.i !== k || typeof m.name !== 'string' || typeof m.ecdh !== 'string' || typeof m.sign !== 'string') throw new Error('bad roster entry');
      if (!m.name || m.name.length > MAX_ROSTER_NAME || cleanName(m.name) !== m.name) throw new Error('bad roster name');
      parsePk(m.ecdh);
      parsePk(m.sign);
      ecdhs.add(m.ecdh);
      signs.add(m.sign);
    });
    if (ecdhs.size !== r.length || signs.size !== r.length) throw new Error('duplicate keys in roster');
    return r.map((m) => ({ i: m.i, name: m.name, ecdh: m.ecdh, sign: m.sign }));
  }

  async function onHostMessage(m) {
    if (!m || typeof m.t !== 'string' || G.ended) return;
    if (m.t === 'lobby') {
      if (G.started || !Array.isArray(m.names)) return;
      const names = m.names.slice(0, MAX_GUESTS + 1).map((n) => cleanName(n).slice(0, MAX_ROSTER_NAME)).filter(Boolean);
      renderNames($('join-members'), names, G.myName);
    } else if (m.t === 'roster') {
      if (G.started) return;
      G.started = true;
      try {
        const members = parseRoster(m.roster);
        const mine = members.filter((x) => x.ecdh === G.keys.ecdhB && x.sign === G.keys.signB);
        if (mine.length !== 1 || mine[0].i === 0) {
          throw new Error("The host's group list doesn't contain your keys, so it may have been tampered with.");
        }
        G.myName = mine[0].name;
        const expiry = Number.isInteger(m.expiry) && m.expiry >= 0 && m.expiry <= 1440 ? m.expiry : 30;
        await enterVerify(members, mine[0].i, expiry);
      } catch (e) {
        endSession('The group could not be set up: ' + errText(e), true);
      }
    } else if (m.t === 'relay') {
      if (validRelay(m)) handleRelay(m);
    } else if (m.t === 'left') {
      if (!G.roster || !Number.isInteger(m.i) || m.i <= 0 || m.i >= G.roster.length || m.i === G.myIndex || G.left.has(m.i)) return;
      G.left.add(m.i);
      addSystem(G.roster[m.i].name + ' left the chat.');
      renderMembers();
      updateReadiness();
    } else if (m.t === 'bye') {
      endSession('The host ended the group chat.', false);
    }
  }

  /* ---------- verification and chat ---------- */

  async function enterVerify(members, myIndex, expiry) {
    G.myIndex = myIndex;
    G.roster = await Promise.all(members.map(async (m) => ({
      ...m,
      ecdhKey: await crypto.subtle.importKey('raw', b64u.dec(m.ecdh), { name: 'ECDH', namedCurve: 'P-256' }, false, []),
      signKey: await crypto.subtle.importKey('raw', b64u.dec(m.sign), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']),
    })));
    const canonical = [PROTO, String(members.length), ...members.map((m) => [m.i, m.name, m.ecdh, m.sign].join('|'))].join('\n');
    G.groupHash = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(canonical)));
    G.code = codeString(G.groupHash.subarray(0, 16), 25);
    $('group-code').textContent = G.code;
    $('group-code').setAttribute('aria-label', 'Group code: ' + G.code.split('').join(' '));
    renderNames($('verify-members'), members.map((m) => m.name), members[myIndex].name);
    G.opened = true;
    startTimer(expiry);
    show('verify');
    for (const m of G.early.splice(0)) handleRelay(m);
  }

  async function confirmMatch() {
    $('btn-match').disabled = true;
    G.verifiedMe = true;
    G.ownChain = { key: crypto.getRandomValues(new Uint8Array(32)), n: 0 };
    show('chat');
    renderMembers();
    updateReadiness();
    addSystem('Group code confirmed on your side. Messages are end-to-end encrypted.');
    const ck = G.ownChain.key.slice();
    try {
      for (const m of G.roster) {
        if (m.i === G.myIndex || G.left.has(m.i)) continue;
        sendRelay(await wrapChainKeyFor(m.i, ck));
      }
    } catch (e) {
      setStatus('chat-status', 'Could not share your key: ' + errText(e), 'error');
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
      span.textContent = m.i === G.myIndex ? 'You (' + m.name + ')' : m.name;
      if (G.left.has(m.i)) span.className = 'left';
      box.append(span);
      if (k < G.roster.length - 1) box.append(', ');
    });
  }

  function updateReadiness() {
    if (!G.verifiedMe || !G.roster) return;
    const el = $('peer-state');
    const missing = G.roster.filter((m) => m.i !== G.myIndex && !G.left.has(m.i) && !G.recvChains[m.i]).map((m) => m.name);
    if (missing.length) {
      el.textContent = 'Waiting for ' + missing.join(', ') + ' to confirm the code…';
      delete el.dataset.kind;
    } else {
      el.textContent = 'Everyone is ready';
      el.dataset.kind = 'ok';
    }
  }

  function fmtTime(d) {
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
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
    bubble.textContent = text;
    const time = document.createElement('time');
    time.textContent = fmtTime(new Date());
    wrap.append(bubble, time);
    list.append(wrap);
    list.scrollTop = list.scrollHeight;
  }

  function addSystem(text) {
    const el = document.createElement('div');
    el.className = 'sys';
    el.textContent = text;
    $('messages').append(el);
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
    G.keys = null;
    G.roster = null;
    G.groupHash = null;
    G.inbox = [];
    G.early = [];
    G.slots = [];
    G.link = null;
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
    const name = cleanName($('my-name').value).slice(0, MAX_NAME);
    if (!name) {
      setStatus('start-status', 'Enter a display name first.', 'error');
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
      endSession("You reported that the group codes don't match. Someone may have tampered with the group, so the chat was cancelled.", true);
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
      if (G.opened && !G.ended) e.preventDefault();
    });
  }

  init();
})();
