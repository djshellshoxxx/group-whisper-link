# Codebase Map: where to find what

| I want to... | Look in |
|---|---|
| Page layout and the Content-Security-Policy | `index.html` |
| Host and guest flows, WebRTC, codes, group key, ratchet, signing, UI | `app.js` (about 1,000 lines; the header comment describes the protocol) |
| Limits and size caps | the `MAX_*` constants at the top of `app.js` |
| Styling and dark mode | `style.css` |
| GitHub Pages | `.nojekyll` |

There is no build step and no automated test suite in the repository.
