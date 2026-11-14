# LocalVault AI v2.0 — Zero-Cloud WebGPU Developer Security & Audio Suite

> **Runs 100% in your browser and terminal. Zero API keys. Verifiable Runtime Air-Gap. AES-256-GCM Encrypted Vault.**

LocalVault AI v2.0 is a production-grade, client-side AI developer suite powered by **WebGPU** and **Transformers.js v3** (`@huggingface/transformers`). It solves the architectural flaws found in existing browser AI demos and regex-only PII scrubbers.

---

## How v2.0 Fixes Every Flaw in Existing Tools

### 1. Automatic COOP/COEP Service Worker (`public/coi-serviceworker.js`)
- **The Flaw in Existing Repos**: GitHub Pages and static hosts do not send `Cross-Origin-Opener-Policy` or `Cross-Origin-Embedder-Policy` headers, disabling `SharedArrayBuffer` and throttling WASM fallback by up to 10x.
- **The v2.0 Fix**: Ships with a built-in Service Worker that automatically injects COOP/COEP headers on static hosts so `window.crossOriginIsolated === true` works out of the box on GitHub Pages.

### 2. 4-Layer PII & High-Entropy Secret Firewall (`src/pii-engine.js`)
- **The Flaw in Existing Repos**: Simple regexes miss multi-line SSH/PEM keys, database connection strings (`postgres://user:pass@host`), and custom `.env` or YAML secrets, while accidentally breaking developer configs by redacting `127.0.0.1` or `localhost`.
- **The v2.0 Fix**:
  - **Layer 1 (Structural & Cryptographic)**: Redacts multi-line `-----BEGIN ... PRIVATE KEY-----` blocks, `postgres://` / `mongodb+srv://` / `redis://` URIs, OpenAI/Anthropic/AWS/GitHub/HuggingFace/Stripe keys, Luhn-verified credit cards, SSNs, IBAN/Crypto wallets, emails, phones, and IPv4/IPv6 addresses.
  - **Layer 2 (Shannon Entropy + AST Key-Value Scanner)**: Computes Shannon Information Entropy and inspects `.env`, JSON, YAML, and code assignments (`PASSWORD`, `SECRET`, `API_KEY`, `AUTH_TOKEN`, `Authorization: Bearer`) to catch unknown proprietary secrets.
  - **Layer 3 (Developer Loopback Allowlist & Custom Blocklist)**: Automatically preserves `127.0.0.1`, `0.0.0.0`, `::1`, and `localhost` so local dev debugging works without friction, while letting you add custom project codenames.
  - **Layer 4 (In-Browser WebGPU SLM Contextual NER)**: Uses `SmolLM2-360M-Instruct` or `Qwen2.5-0.5B-Instruct` on your GPU to catch unlabeled contextual names.

### 3. Fuzzy-Resilient Token Re-Hydration
- **The Flaw in Existing Repos**: Public LLMs frequently alter placeholder tokens in their responses (turning `[EMAIL_1]` into `[email_1]`, `{{EMAIL_1}}`, or `EMAIL-1`), breaking exact-match restoration.
- **The v2.0 Fix**: `rehydrateText()` uses fuzzy token matching to restore your secrets accurately even when ChatGPT, Claude, or Cursor mutates brackets, hyphens, or casing.

### 4. AES-256-GCM Encrypted Vault Export & Import (`src/crypto-vault.js`)
- **The Flaw in Existing Repos**: Token maps are either lost on tab close or exported as plaintext JSON.
- **The v2.0 Fix**: Uses the native **Web Crypto API** (`PBKDF2-SHA256` with 100,000 iterations + `AES-256-GCM`) to lock and export `.lvvault` files that can only be unlocked with your passphrase.

### 5. Verifiable Runtime Network Firewall & Air-Gap Switch (`src/network-firewall.js`)
- **The Flaw in Existing Repos**: Users must blindly trust claims of "zero telemetry."
- **The v2.0 Fix**: Intercepts `window.fetch`, `XMLHttpRequest`, and `navigator.sendBeacon` in real time, hard-blocks all `POST`/`PUT` requests, logs every read-only model weight fetch in a live audit table, and provides a 1-click **Strict Air-Gap Lockdown** switch.

### 6. Integrated Whisper Audio Studio + 16kHz WAV Synthesizer + Auto-PII Scrubbing
- Includes a built-in **16kHz mono WAV synthesizer** (test the audio pipeline without a microphone), **Whisper timestamped chunks** (`[00:00 -> 00:05]`), **In-Flight Generation Interrupt (`Stop`)**, and automatic PII scrubbing on transcripts before structuring notes.

---

## Quick Start

```bash
npm install
npm test
npm run dev
npm run build
