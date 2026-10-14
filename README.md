# group-whisper-link

Temporary, end-to-end encrypted **group chat for up to 6 people**. It runs entirely in the browser and is hosted on GitHub Pages. There is no server, no account, and nothing is stored. A sibling of [whisper-link](https://github.com/djshellshoxxx/whisper-link) (the two-person version).

> **Who can read what:** everyone in the group, **including the host**, can read every message. The host is a member like everyone else and holds every member's message key. "End-to-end encrypted" here means people *outside* the group (the network, GitHub, the services that carry your codes) cannot read the chat, and that no member, host included, can forge another member's messages. If you don't trust the host, don't join.

## How to use it

**Host (the person who creates the group)**
1. Open the site, enter a display name, choose the auto-end timer, and click **Create a group**.
2. In the lobby, click **Add a person** for each invitee (up to 5). Send each person **their own invite code**, to that person only.
3. Paste each person's **reply code** into their slot and click **Connect**. Names appear in the group list as people join.
4. Click **Start chat**. **No one can join after this.**

**Everyone else**
1. Open the site, enter a display name, click **Join a group**, and paste the invite code you were given.
2. Click **Create my reply code** and send it back to the host. Keep the page open. You connect automatically.

**Everyone**
1. A **group code** and a **member list** appear. On a **voice or video call (or in person)**:
   - **Each person reads out their own code**, one at a time. Every code must be identical, to the last character.
   - **Check the member list.** It must contain exactly the people on the call, with the right names. A missing, extra or misnamed member means something is wrong.
2. If everything matches, click **Codes and members match** and chat. Click **Something is wrong** if not. **Leave and wipe**, the timer, or closing the tab destroys your keys and messages.

## How it works

- **Network:** star topology. Each guest swaps two copy-pasted codes (a WebRTC offer and answer) with the host and gets a direct data channel to the host. The host's browser relays messages between members. There is no signalling server.
- **Identities:** every member makes ephemeral keys in memory: ECDH P-256 (key wrapping) and ECDSA P-256 (signatures). Private keys are non-extractable. Names are limited to letters, numbers and a little punctuation from a single alphabet; invisible characters, mixed-alphabet look-alikes and duplicates are rejected.
- **One group code:** when the host clicks Start, the member list (names and public keys) is frozen and sent to everyone. Each member hashes it into the same 150-bit group code. If anyone was given different keys, names or members than the others, at least one code will differ, so reading the codes aloud protects the whole group.
- **Keys:** after confirming, each member makes a random sender chain key and sends it to every other member, wrapped with an AES-256-GCM key derived from a pairwise ECDH exchange. Those wrapping keys are used once and deleted, and the ECDH private key is dropped as soon as the group is set up.
- **Messages:** every message uses a fresh AES-256-GCM key from a one-way HMAC-SHA-256 ratchet (old keys are zeroed), is bound to the group, sender and counter, is padded to 256-byte blocks, and is **signed** by the sender. No one can forge or alter another member's message, and replays are ignored.
- **Forward secrecy:** once the chain keys have been exchanged, a key captured later cannot unwrap the recorded setup messages or decrypt earlier messages. There is **no post-compromise security**: someone who captures a member's live session state can read that member's later messages until the chat ends.
- **Hardening:**
  - Strict Content-Security-Policy (no inline scripts, no third-party loads), and messages are only ever written with `textContent`.
  - The page refuses to run inside another page (clickjacking) and drops any link to the page that opened it.
  - Codes are size-limited and checked. Codes that ask for audio/video are rejected. The other side's network addresses are filtered (no loopback, link-local, multicast, TCP, hostnames, or low ports) and capped at 12, and an unsafe data-channel configuration is refused.
  - Every key is checked to be a real curve point, and every blob has a strict size and encoding. One bad message can never discard other people's messages.
  - Floods are capped: a guest sending data too fast is disconnected, invalid messages from one member are ignored for a minute after too many, and notices and on-screen messages are limited.
  - Error messages are fixed text, never echoes of what someone else sent. Bidirectional-text override characters are removed from messages.
  - The message box turns off spellcheck and autocorrect, so a browser's cloud spellcheck is not sent your drafts.
- **Temporary:** nothing is written to localStorage, IndexedDB, or cookies. The host's timer choice applies to everyone.

## Limits (please read)

- **The host can read everything, and the host must stay.** If the host leaves or loses connection, the group chat ends for everyone. If a guest leaves, the others carry on.
- **A host can censor.** The host's browser relays every message, so it can silently drop, delay or reorder them, and it can tell members that someone "left". Gaps are noticed only when a *later* message from the same sender arrives; dropping the final message cannot be detected. Statements about who left are labelled "reported by the host" because they are only the host's word. A gap of more than 50 messages from one sender (or 300 in total) stops that sender's messages for you.
- **The group code proves everyone saw the same member list, not who the members are.** You must also check the list against the people on the call. Invite codes are not tied to a person: whoever sends back a reply code first fills the slot, under any name they choose. A malicious host can add a hidden extra member or rename someone, and only your own check of the member list will catch it. A host who sees different people read out different codes cannot hide it, so have everyone read their code, not just compare with the host.
- **Members can prove who said what.** Messages are signed, so there is no deniability.
- **Your IP address is in the codes.** The invite and reply codes contain network addresses (your local and, with STUN on, public IP). Whoever carries the code (your messenger, email provider) can read them. The host sees every member's IP address; members don't see each other's.
- **Pasting an invite makes your browser contact the addresses in it.** Only use invites from people you trust. Unsafe address types are filtered, but addresses on your own network are still tried, because that is how chats on the same network connect. At most 12 are used.
- **With "Use public STUN servers" ticked,** Google and Cloudflare also see your IP address. Untick it for same-network chats.
- **No relay server.** Strict firewalls and some mobile or symmetric NATs block direct connections to the host. A TURN relay would fix that but can't be hosted on GitHub Pages.
- **Fixed group.** The member list is locked when the chat starts, so people can't be added later (start a new group instead).
- **You must trust the code you load.** The JavaScript comes from this repo via GitHub Pages. If the repo or the GitHub account were compromised, the code could be altered. GitHub Pages serves every project site under one account from the same web origin, so another site under the same account could script this one. Protect the account with 2FA, review changes, don't host untrusted content under the same account, and consider hosting your own copy on its own domain.
- **GitHub Pages can't send security headers.** The Content-Security-Policy is applied via a `<meta>` tag, which cannot set `frame-ancestors`. Framing is blocked by the page's own script instead, which is weaker than a header.
- **Endpoints:** nothing protects you from malware, a malicious browser extension, or screen capture on any member's device, or from a member saving or sharing what they see. Wiping is best-effort: browsers and operating systems can leave traces in memory that a web page can't erase. "Copy" puts a code on the clipboard, where clipboard-history tools may keep it.
- Everyone must be online at the same time. There is no offline delivery and no history.
- This is a small, custom, un-audited protocol. Don't rely on it where a failure would be dangerous.

## Deploy on GitHub Pages

1. Repo **Settings → Pages**.
2. **Build and deployment → Source: Deploy from a branch**.
3. Branch **main**, folder **/ (root)**, then **Save**.
4. After a minute the site is at `https://<your-username>.github.io/group-whisper-link/`.

## Files

| File | Purpose |
|---|---|
| `index.html` | Page structure and Content-Security-Policy |
| `app.js` | WebRTC, group cryptography and UI logic |
| `style.css` | Styling (dark cyber theme) |
