# LocalVault AI v2.1

LocalVault AI is a local-first browser toolkit for heuristic PII/secret scrubbing, encrypted placeholder storage, browser request monitoring, audio decoding and optional local model inference.

## What it does

- **PII and secret scrubbing:** detects common email addresses, IP addresses, phone numbers, payment-card-like values, access tokens, private-key blocks, database connection strings, custom blocklist terms and contextual person names. Detection is heuristic and is not guaranteed to find every sensitive value.
- **Encrypted vault:** uses Web Crypto AES-256-GCM with PBKDF2-SHA256, 310,000 iterations, a random 16-byte salt and random 12-byte IV. New vaults require a passphrase of at least 12 characters. No default passphrase is generated or stored.
- **Audio:** accepts browser-decodable audio files and microphone recordings, converts them to mono 16 kHz Float32 samples and can export a synthetic WAV test tone.
- **Notes:** creates deterministic Markdown structures for meeting, lecture, incident and executive formats. It classifies source sentences; it is not a generative or fact-checking summarizer.
- **Local inference:** an isolated worker uses Transformers.js for SmolLM2-135M-Instruct or Qwen2.5-0.5B-Instruct text generation and Whisper Tiny English transcription. Model weights are fetched from approved Hugging Face hosts when needed. WebGPU is attempted first, with WASM fallback.
- **Request monitor:** watches supported page-level fetch, XHR and sendBeacon calls. The strict air-gap option also tells the inference worker to block its guarded external fetch calls.
- **CLI:** supports scrub, deterministic note structuring and Shannon entropy calculation.

## Important security boundaries

LocalVault is a developer utility, not a certified security product. Its scrubber can miss sensitive values and can produce false positives. Review sanitized text before sharing it.

The request monitor is not a complete browser or operating-system firewall. It does not control browser-managed redirects, every module import, WebSocket, WebRTC, browser extensions, other tabs, other applications or operating-system networking. The service worker used for cross-origin isolation also does not turn a static host into a complete security boundary.

The encrypted vault has not undergone an independent cryptographic audit. The passphrase is not recoverable by the application. Keep a secure backup of the encrypted `.lvvault` file and remember the passphrase.

The local model may require internet access for the first model download. Strict lockdown can prevent model assets that have not yet been cached from loading. The browser's reported WebGPU availability does not guarantee that every model/device combination will run successfully.

Microphone access requires a secure context (HTTPS or localhost) and user permission. Browser audio decoder support varies by codec and platform. Recordings are limited to ten minutes; audio files are limited to 50 MB.

## Requirements

- Node.js 20 or newer and npm.
- A modern browser; WebGPU is optional.
- HTTPS or localhost for Web Crypto, service workers and microphone access.

## Install and run

```bash
npm install
npm run dev
```

Open the local development URL printed by Vite.

## Tests and production build

```bash
npm test
npm run check
npm run build
npm run preview
```

## CLI examples

```bash
npm run cli -- scrub .env
npm run cli -- scrub "Contact alex@example.org"
npm run cli -- structure notes.txt --mode=incident
npm run cli -- entropy "example-token-123"
```

## GitHub Pages

The Vite `base: './'` setting supports a project Pages site. The Actions workflow runs syntax checks and regression tests, builds `dist`, and deploys only for pushes to `main` or manual workflow dispatches. Configure the repository's Pages source to **GitHub Actions**.

## Repository layout

```text
.github/workflows/deploy.yml
package.json
vite.config.js
public/coi-serviceworker.js
index.html
src/styles.css
src/main.js
src/worker.js
src/pii-engine.js
src/crypto-vault.js
src/network-firewall.js
src/note-structurer.js
src/audio-utils.js
bin/localvault-cli.mjs
tests/verify.mjs
README.md
```

## License

MIT
