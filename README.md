# group-whisper-link

Temporary, end-to-end encrypted **group chat for up to 6 people**. It runs entirely in the browser and is hosted on GitHub Pages. There is no server, no account, and nothing is stored. A sibling of [whisper-link](https://github.com/djshellshoxxx/whisper-link) (the two-person version).

## How to use it

**Host (the person who creates the group)**
1. Open the site, enter a display name, choose the auto-end timer, and click **Create a group**.
2. In the lobby, click **Add a person** for each invitee (up to 5). Send each person **their own invite code**.
3. Paste each person's **reply code** into their slot and click **Connect**. Names appear in the group list as people join.
4. Click **Start chat**. **No one can join after this.**

**Everyone else**
1. Open the site, enter a display name, click **Join a group**, and paste the invite code you were given.
2. Click **Create my reply code** and send it back to the host. Keep the page open. You connect automatically.

**Everyone**
1. A **group code** appears. Compare it on a **voice or video call (or in person)**. Everybody must see exactly the same code. If anyone's differs, click **They don't match** and stop.
2. Click **The codes match** and chat. **Leave and wipe**, the timer, or closing the tab destroys your keys and messages.

## How it works

- **Network:** star topology. Each guest swaps two copy-pasted codes (a WebRTC offer and answer) with the host and gets a direct data channel to the host. The host's browser forwards messages between members. There is no signalling server.
- **Identities:** every member makes ephemeral keys in memory: ECDH P-256 (key wrapping) and ECDSA P-256 (signatures). Private keys are non-extractable.
- **One group code:** when the host clicks Start, the member list (names + public keys) is frozen and sent to everyone. Each member hashes it into the same 125-bit group code. If the host (or anyone on the path) gave different people different keys, at least one code will differ, so comparing **one** code protects the whole group.
- **Keys:** after confirming the code, each member makes a random sender chain key and sends it to every other member, wrapped with an AES-256-GCM key derived from a pairwise ECDH exchange. The host only ever forwards ciphertext.
- **Messages:** every message uses a fresh AES-256-GCM key from a one-way HMAC-SHA-256 ratchet (old keys are zeroed), is bound to the group, sender and counter, is padded to 256-byte blocks, and is **signed** by the sender. The host can't read, forge, or alter messages, and replays are ignored. A host that silently drops a message is detected through the message counter.
- **Hardening:** strict Content-Security-Policy (no inline scripts, no third-party loads), messages are only ever written with `textContent`, and codes that ask for audio/video or extra channels are rejected.
- **Temporary:** nothing is written to localStorage, IndexedDB, or cookies. The host's timer choice applies to everyone.

## Limits (please read)

- **The host must stay.** If the host leaves or loses connection, the group chat ends for everyone. If a guest leaves, the others carry on.
- **The host sees metadata:** every member's IP address, who is online, and the timing and size of messages (but not the contents). Members cannot see each other's IP addresses.
- **With "Use public STUN servers" ticked,** Google and Cloudflare also see your IP address. Untick it for same-network chats.
- **No relay server.** Strict firewalls and some mobile or symmetric NATs block direct connections to the host. A TURN relay would fix that, but it can't be hosted on GitHub Pages.
- **Fixed group.** The member list is locked when the chat starts, so people can't be added later (start a new group instead). Nobody who joins late can read earlier messages.
- **You must trust the code you load.** The JavaScript comes from this repo via GitHub Pages. If the repo or the GitHub account were compromised, the code could be altered. Protect the account with 2FA, review changes, and consider hosting your own copy.
- **Verification is essential.** Without comparing the group code out-of-band, encryption only stops passive eavesdroppers.
- **Endpoints:** nothing protects you from malware or screen capture on any member's device, or from a member saving or sharing what they see.
- Everyone must be online at the same time. There is no offline delivery and no history.

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
| `style.css` | Styling (light and dark mode) |
