# Architecture and Design Rationale

Sources: README "How it works" and "Limits", the header comment and constants in `app.js`, and the CSP in `index.html`.

- **Star topology.** Each guest connects directly to the host over a WebRTC data channel. The host forwards messages between members. This keeps the connection count linear, and the host is the only relay (`app.js` header).
- **No signalling server.** Invite and reply codes carry the WebRTC offer and answer, so GitHub Pages only serves files.
- **Two key types per member.** ECDH P-256 wraps keys and ECDSA P-256 signs messages. Private keys are non-extractable.
- **The host can read every group message.** Each sender wraps a chain key for every other member, including the host. The host forwards encrypted frames and decrypts messages as a group member.
- **Signed, replay-bound messages.** Each message uses a fresh key from a one-way HMAC-SHA-256 ratchet, is bound to group, sender and counter, and is signed. Recipients verify the sender’s signature. A host can drop or delay delivery.
- **Bounded input.** The constants `MAX_GUESTS = 5`, `MAX_TEXT = 2000`, `MAX_FRAME_CHARS`, `MAX_CODE_CHARS` and `MAX_SDP_CHARS` cap what is accepted.
- **Group code for out-of-band checks.** Members compare a group code on a call; a mismatch means someone's keys or fingerprints differ.
- **Nothing persisted.** No localStorage, IndexedDB or cookies (README).
