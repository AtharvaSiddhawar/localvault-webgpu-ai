
# LocalVault AI v2.0

**A local-first developer toolkit for browser-based privacy utilities and local AI inference.**

LocalVault combines sensitive-data detection, encrypted vault storage, browser request monitoring, audio utilities, transcript structuring and a dedicated local inference worker.

It does not require an application API key or a hosted inference API. However, model and library files may need to be downloaded from approved external hosts the first time they are used.

---

## Features

### 1. PII and secret scrubbing

The PII engine includes:

- Structural pattern detection for common credentials and identifiers.
- Shannon entropy scanning for possible high-entropy secrets.
- Luhn check-digit validation.
- Custom user-defined blocklist terms.
- A developer loopback allowlist.
- Context-based person-name detection.
- Placeholder replacement and rehydration.

Detection is heuristic. It cannot guarantee that every sensitive value will be found.

The contextual person-name feature is a rule-based heuristic, not a complete named-entity recognition model.

### 2. Encrypted vault

The vault uses the browser's Web Crypto API:

| Component | Configuration |
|---|---|
| Encryption | AES-256-GCM |
| Key derivation | PBKDF2-SHA256 |
| New vault iterations | 310,000 |
| Salt | 16 bytes |
| Initialization vector | 12 bytes |
| Authentication tag | 128 bits |

New vaults require a passphrase of at least 12 characters.

The application does not supply a default passphrase. Keep your passphrase and exported vault file safe; losing the passphrase can make encrypted data unrecoverable.

This implementation has not undergone an independent cryptographic security audit.

### 3. Network request monitoring

The page-level request guard monitors supported:

- `fetch()`
- `XMLHttpRequest`
- `navigator.sendBeacon()`

It allows same-origin resources and approved HTTPS model/library hosts, while blocking unsupported methods and payload-bearing requests.

The inference worker also has its own `fetch()` request guard.

**Important limitations:** These controls are not a complete browser or operating-system firewall. They do not cover every browser-managed connection, module import, redirect, WebSocket, WebRTC or other networking mechanism. The page's lockdown switch does not guarantee that all worker or browser network activity is disabled.

### 4. Audio utilities

The audio module provides:

- Synthetic test-tone generation.
- Mono 16-bit PCM WAV encoding.
- Browser WAV Blob export.
- Audio resampling to 16kHz mono.

The current UI uses synthetic test audio. Microphone recording and uploaded-audio capture are not implemented.

### 5. Note structuring

The deterministic note structurer supports four formats:

- `meeting`
- `lecture`
- `incident`
- `executive`

It classifies available sentences using keyword rules and can scrub sensitive data before formatting.

It is not an AI-powered summarizer. It does not independently verify facts or create missing meeting details.

### 6. Local model inference

The dedicated worker supports:

- `HuggingFaceTB/SmolLM2-135M-Instruct`
- `Qwen/Qwen2.5-0.5B-Instruct`
- `onnx-community/whisper-tiny.en`

WebGPU is selected when an adapter is available; otherwise, the worker attempts a WASM fallback.

Model availability and performance depend on browser support, device hardware, memory and model compatibility.

---

## Technology stack

| Technology | Purpose |
|---|---|
| HTML, CSS, JavaScript | Browser interface |
| Vite | Development and production build |
| Web Crypto API | Vault encryption |
| WebGPU | Hardware-accelerated inference where supported |
| Transformers.js v3 | Browser model pipelines |
| Web Workers | Separate inference execution |
| Node.js | CLI and regression tests |
| GitHub Actions | Build, test and deployment |

---

## Repository structure

| File | Responsibility |
|---|---|
| `package.json` | Dependencies and scripts |
| `vite.config.js` | Vite configuration |
| `public/coi-serviceworker.js` | Cross-origin isolation helper |
| `index.html` | Application interface |
| `src/styles.css` | Responsive interface styling |
| `src/main.js` | Browser UI controller |
| `src/worker.js` | Local model inference |
| `src/pii-engine.js` | PII and secret detection |
| `src/crypto-vault.js` | Encrypted vault |
| `src/network-firewall.js` | Page-level request guard |
| `src/note-structurer.js` | Deterministic Markdown structuring |
| `src/audio-utils.js` | WAV and resampling utilities |
| `bin/localvault-cli.mjs` | Node.js command-line interface |
| `tests/verify.mjs` | Regression tests |
| `README.md` | Project documentation |
| `.github/workflows/deploy.yml` | Automated verification and deployment |

---

## Quick start

### Requirements

- Node.js 18 or later.
- npm.
- A modern browser.
- A compatible GPU and browser for WebGPU acceleration; WASM is the fallback.

### Install dependencies

```bash
npm install
```

### Run regression tests

```bash
npm test
```

### Start the development server

```bash
npm run dev
```

### Build the production application

```bash
npm run build
```

### Preview the production build

```bash
npm run preview
```

---

## CLI usage

### Scrub a file

```bash
npm run cli -- scrub .env
```

### Scrub literal text

```bash
npm run cli -- scrub "Email alice@example.com"
```

### Structure an incident report

```bash
npm run cli -- structure notes.txt --mode=incident
```

### Calculate Shannon entropy

```bash
npm run cli -- entropy "example-token-123"
```

### Display help

```bash
npm run cli -- --help
```

---

## GitHub Pages deployment

The GitHub Actions workflow:

1. Checks out the repository.
2. Installs dependencies.
3. Runs the regression suite.
4. Builds the Vite production application.
5. Verifies the build output.
6. Uploads the Pages artifact.
7. Deploys to GitHub Pages.

The deployed application is available at:

https://atharvasiddhawar.github.io/localvault-webgpu-ai/

The first model use may require an internet connection to retrieve model and library files.

---

## Privacy and security notes

LocalVault is designed to process application text and run supported inference in the browser or locally through Node.js.

That does not mean that all network activity is disabled or that every sensitive value is guaranteed to be detected.

Before using the application with real sensitive data:

- Review the sanitized output.
- Never treat heuristic detection as a substitute for careful review.
- Protect exported vault files and passphrases.
- Understand that browser extensions, compromised devices and other software are outside this application's security boundary.
- Do not use the request monitor as the only control for preventing data disclosure.

---

## License

MIT
