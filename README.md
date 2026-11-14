# LocalVault AI v2.0 (Zero-Cloud Client-Side AI Developer Suite)

100% browser and terminal-based AI developer utility suite powered by **WebGPU** and **Transformers.js v3** (`@huggingface/transformers ^3.3.3`). Requires **zero API keys**, incurs **zero cloud token costs**, and operates with **zero data exfiltration**.

---

## 1. Architecture & 16-File Repository Structure

| File | Responsibility |
| :--- | :--- |
| `package.json` | Node.js manifest with `@huggingface/transformers` (`^3.3.3`), Vite bundler, `localvault` CLI bin script, and regression test runner. |
| `vite.config.js` | Vite ESNext bundler configuration with Cross-Origin Isolation headers (`COOP: same-origin`, `COEP: credentialless`) and ES module Web Worker output. |
| `public/coi-serviceworker.js` | Cross-Origin Isolation Service Worker injecting COOP/COEP headers on static hosts (GitHub Pages) so `SharedArrayBuffer` and multi-threaded WebGPU/WASM run at full speed. |
| `index.html` | Responsive dark-mode single-page application UI with `importmap` pointing to jsDelivr for `@huggingface/transformers`. |
| `src/styles.css` | Developer dark-mode stylesheet using `Inter` & `JetBrains Mono`, CSS custom variables, and responsive grid layout. |
| `src/main.js` | UI controller binding the 4-layer PII scrubber, AES-256-GCM vault, network firewall audit log, audio studio, and WebGPU worker bridge. |
| `src/worker.js` | Dedicated Web Worker handling asynchronous WebGPU/WASM inference (Whisper ASR + SmolLM2/Qwen2.5 SLMs) with `InterruptableStoppingCriteria`. |
| `src/pii-engine.js` | 4-Layer Hybrid PII & Secret Firewall + Shannon entropy scanner + Luhn validator + `rehydrateText()` fuzzy placeholder restoration. |
| `src/crypto-vault.js` | Zero-Knowledge Cryptographic Vault using native Web Crypto API (`PBKDF2-SHA256` with 100,000 iterations + `AES-256-GCM`) to lock/unlock and export `.lvvault` files. |
| `src/network-firewall.js` | Client-side network exfiltration monitor intercepting `fetch`, `XMLHttpRequest`, and `navigator.sendBeacon`, blocking `POST`/`PUT` payload exfiltration, and enforcing Strict Air-Gap Lockdown. |
| `src/note-structurer.js` | Offline audio transcript structurer supporting 4 engineering modes (`meeting`, `lecture`, `incident`, `executive`) with auto-PII scrubbing. |
| `src/audio-utils.js` | 16kHz mono resampler (`OfflineAudioContext`), pure-JS 16kHz WAV synthesizer for mic-free testing, and RIFF/WAVE Blob exporter. |
| `bin/localvault-cli.mjs` | Node.js CLI executable for running the 4-layer PII scrubber and note structurer in terminals or CI/CD pipelines. |
| `tests/verify.mjs` | Zero-dependency Node.js regression test suite verifying all 16 files, Luhn check digits, Shannon entropy, 4-layer scrubbing, fuzzy re-hydration, AES-256-GCM, WAV synthesis, and note structuring. |
| `README.md` | Full technical documentation and architecture overview. |
| `.github/workflows/deploy.yml` | GitHub Actions CI/CD workflow running `npm test` and deploying the Vite production bundle to GitHub Pages on Node.js 24 native actions. |

---

## 2. Quick Start (Local & CLI)

```bash
# Install dependencies
npm install

# Run the zero-dependency regression test suite
npm test

# Run the terminal CLI scrubber on a file or string
npm run cli -- scrub .env

# Structure an incident post-mortem from terminal
npm run cli -- structure "Database outage on 198.51.100.12 fixed by rotating API_KEY=sk-proj-1234567890abcdefghijklmnop" --mode=incident

# Launch local development server with COOP/COEP headers
npm run dev

# Build static production bundle for GitHub Pages
npm run build
```

