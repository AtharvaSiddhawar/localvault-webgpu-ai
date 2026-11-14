/**
 * LocalVault AI v2.0 — Main Controller
 */

import {
  PII_CATEGORIES,
  scrubText,
  rehydrateText,
  buildContextualPiiPrompt,
  parseLlmEntityResponse
} from './pii-engine.js';
import {
  encryptVaultMap,
  decryptVaultMap
} from './crypto-vault.js';
import {
  NetworkFirewall
} from './network-firewall.js';
import {
  buildNoteStructuringMessages,
  structureTranscriptInstant
} from './note-structurer.js';
import {
  DEMO_TRANSCRIPTS,
  decodeAudioBlobTo16kHzMono,
  generateSyntheticTestAudio,
  MicrophoneRecorder
} from './audio-utils.js';

const SAMPLE_PII_TEXT = `# Production Incident Config & Customer Escalation
Reported by: Dr. Evelyn Vance
Customer: Marcus Sterling (marcus.s@clientdomain.org)
Support Phone: +1 (415) 890-4321
Customer SSN: 412-58-9014
Billing Card (Visa Luhn): 4532 0151 1283 0366

# Infrastructure & High-Entropy Secrets (.env / YAML)
DATABASE_URL="postgres://db_admin:9vK!x82QpLm#44zR@prod-cluster.internal:5432/customers"
OPENAI_API_KEY="sk-proj-98a7bc65def4321098a7bc65def43210"
ANTHROPIC_API_KEY="sk-ant-api03-77a8b9c0d1e2f3g4h5i6j7k8l9m0n1"
WEBHOOK_SECRET = "whsec_K9mP4xR2vL8nQ5wZ1jF7yB3cT6hN0dG"
LOCAL_DEV_HOST = "127.0.0.1"
PROD_NODE_IP = "192.168.42.118"

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB8x9fK2L1mQ7vN3pX8cR4tW6yZ0bH5jM1kL9vP2qW3xQ==
-----END OPENSSH PRIVATE KEY-----`;

class LocalVaultAppV2 {
  constructor() {
    this.worker = null;
    this.recorder = new MicrophoneRecorder();
    this.firewall = new NetworkFirewall((logs) => this.renderFirewallLogs(logs));
    this.firewall.install();

    this.enabledPiiCategories = Object.fromEntries(
      Object.entries(PII_CATEGORIES).map(([k, v]) => [k, v.defaultEnabled])
    );
    this.extraLlmEntities = [];
    this.currentTokenMap = {};
    this.decodedAudioData = null;
    this.currentWavBlob = null;

    this.initWorker();
    this.bindTabs();
    this.initAirGapToggle();
    this.initHardwareTelemetry();
    this.initPiiWorkspace();
    this.initCryptoVaultControls();
    this.initAudioWorkspace();
  }

  initWorker() {
    try {
      this.worker = new Worker(new URL('./worker.js', import.meta.url), {
        type: 'module'
      });
      this.worker.addEventListener('message', (e) => this.handleWorkerMessage(e.data));
      this.worker.postMessage({ type: 'PING_HARDWARE' });
    } catch (err) {
      this.setStatusText(`Worker status: ${err.message}`);
    }
  }

  initAirGapToggle() {
    const airgapPill = document.getElementById('btn-airgap-toggle');
    const airgapLabel = document.getElementById('airgap-status-text');
    if (!airgapPill) return;

    airgapPill.addEventListener('click', () => {
      const nextState = !this.firewall.airGapLocked;
      this.firewall.setAirGapLockdown(nextState);
      this.worker?.postMessage({
        type: 'SET_AIRGAP_MODE',
        payload: { locked: nextState }
      });
      airgapPill.classList.toggle('locked', nextState);
      if (airgapLabel) {
        airgapLabel.textContent = nextState
          ? 'Air-Gap: LOCKED (100% Offline)'
          : 'Air-Gap: Unlocked (CDN Allowed)';
      }
      this.setStatusText(
        nextState
          ? 'Strict Air-Gap Lockdown enabled: All external network requests blocked.'
          : 'Air-Gap unlocked: Read-only HuggingFace weight caching allowed.'
      );
    });
  }

  handleWorkerMessage(msg) {
    const { type, payload } = msg || {};

    if (type === 'HARDWARE_INFO') {
      const badge = document.getElementById('gpu-status-text');
      const dot = document.getElementById('gpu-status-dot');
      if (badge && dot) {
        if (payload.device === 'webgpu') {
          badge.textContent = `WebGPU (${payload.supportsFp16 ? 'FP16 Shaders' : 'FP32/Q4'})`;
          dot.className = 'dot dot-emerald';
        } else {
          badge.textContent = 'WASM CPU Mode';
          dot.className = 'dot dot-amber';
        }
      }
      return;
    }

    if (type === 'STATUS') {
      this.setStatusText(payload);
      return;
    }

    if (type === 'MODEL_PROGRESS') {
      this.updateProgressBanner(payload);
      return;
    }

    if (type === 'MODEL_READY') {
      this.hideProgressBanner();
      this.setStatusText(`Ready: ${payload.modelId} (${payload.device.toUpperCase()})`);
      return;
    }

    if (type === 'TRANSCRIBE_RESULT') {
      this.hideProgressBanner();
      const transcriptArea = document.getElementById('raw-transcript-input');
      if (transcriptArea) {
        transcriptArea.value = payload.text;
      }
      this.setStatusText(
        `Whisper ASR completed in ${payload.elapsedMs}ms (${payload.device.toUpperCase()})`
      );
      const transcribeBtn = document.getElementById('btn-run-whisper');
      if (transcribeBtn) transcribeBtn.disabled = false;
      this.runInstantStructure();
      return;
    }

    if (type === 'LLM_STREAM_TOKEN') {
      const speedEl = document.getElementById('llm-speed-badge');
      if (speedEl && payload.tokensPerSec) {
        speedEl.textContent = `${payload.tokensPerSec} tok/s`;
      }
      if (payload.taskTag === 'structure') {
        const notesOutput = document.getElementById('structured-notes-output');
        if (notesOutput) {
          notesOutput.value = payload.accumulatedText;
        }
      }
      return;
    }

    if (type === 'LLM_COMPLETE') {
      this.hideProgressBanner();
      const speedEl = document.getElementById('llm-speed-badge');
      if (speedEl && payload.tokensPerSec) {
        speedEl.textContent = `${payload.tokensPerSec} tok/s`;
      }
      if (payload.taskTag === 'structure') {
        const notesOutput = document.getElementById('structured-notes-output');
        if (notesOutput && payload.text) {
          notesOutput.value = payload.text;
        }
        const llmBtn = document.getElementById('btn-llm-structure');
        if (llmBtn) llmBtn.disabled = false;
        this.setStatusText(
          `SLM Notes completed in ${payload.elapsedMs}ms (${payload.tokensPerSec} tok/s)`
        );
      } else if (payload.taskTag === 'pii_audit') {
        const discovered = parseLlmEntityResponse(payload.text);
        if (discovered.length > 0) {
          this.extraLlmEntities = [...this.extraLlmEntities, ...discovered];
          this.executePiiScrub();
        }
        const auditBtn = document.getElementById('btn-llm-pii-scan');
        if (auditBtn) auditBtn.disabled = false;
        this.setStatusText(
          `Contextual WebGPU Scan complete (+${discovered.length} entities redacted)`
        );
      }
      return;
    }

    if (type === 'ERROR') {
      this.hideProgressBanner();
      this.setStatusText(`Notice: ${payload.message}`);
      document.querySelectorAll('button').forEach((b) => {
        b.disabled = false;
      });
    }
  }

  setStatusText(text) {
    const el = document.getElementById('engine-status-text');
    if (el) el.textContent = text;
  }

  updateProgressBanner(progress) {
    const banner = document.getElementById('model-progress-banner');
    const label = document.getElementById('progress-file-label');
    const pctLabel = document.getElementById('progress-pct-label');
    const fill = document.getElementById('progress-bar-fill');

    if (!banner) return;
    banner.classList.remove('hidden');

    if (progress.status === 'progress' || typeof progress.progress === 'number') {
      const pct = Math.min(100, Math.round(progress.progress || 0));
      if (label) label.textContent = `Caching ONNX shard in browser: ${progress.file || 'model.onnx'}`;
      if (pctLabel) pctLabel.textContent = `${pct}%`;
      if (fill) fill.style.width = `${pct}%`;
    } else if (progress.status === 'Ready' || progress.status === 'ready') {
      this.hideProgressBanner();
    }
  }

  hideProgressBanner() {
    const banner = document.getElementById('model-progress-banner');
    if (banner) banner.classList.add('hidden');
  }

  bindTabs() {
    const buttons = document.querySelectorAll('.tab-btn');
    const panels = document.querySelectorAll('.tab-panel');
    buttons.forEach((btn) => {
      btn.addEventListener('click', () => {
        const target = btn.getAttribute('data-tab');
        buttons.forEach((b) => b.classList.toggle('active', b === btn));
        panels.forEach((p) => p.classList.toggle('active', p.id === target));
      });
    });
  }

  async initHardwareTelemetry() {
    const vendorEl = document.getElementById('spec-gpu-vendor');
    const archEl = document.getElementById('spec-gpu-arch');
    const fp16El = document.getElementById('spec-fp16');
    const coiEl = document.getElementById('spec-coi-status');
    const coiHeaderPill = document.getElementById('coi-status-text');

    const isIsolated = Boolean(window.crossOriginIsolated);
    if (coiEl) {
      coiEl.textContent = isIsolated
        ? 'Isolated (SharedArrayBuffer Active)'
        : 'Standard (COI Service Worker Ready)';
    }
    if (coiHeaderPill) {
      coiHeaderPill.textContent = isIsolated ? 'COOP/COEP: Isolated' : 'COOP/COEP: Standard';
    }

    if (!('gpu' in navigator)) {
      if (vendorEl) vendorEl.textContent = 'WebGPU Unavailable (WASM Mode)';
      if (archEl) archEl.textContent = 'CPU WebAssembly Threads';
      if (fp16El) fp16El.textContent = 'INT8 / FP32';
      return;
    }

    try {
      const adapter = await navigator.gpu.requestAdapter();
      if (!adapter) {
        if (vendorEl) vendorEl.textContent = 'WASM Fallback Adapter';
        return;
      }
      const info = adapter.info || {};
      const hasFp16 = adapter.features.has('shader-f16');
      if (vendorEl) vendorEl.textContent = info.vendor || info.description || 'WebGPU Hardware Adapter';
      if (archEl) archEl.textContent = info.architecture || info.device || 'Native GPU Compute';
      if (fp16El) fp16El.textContent = hasFp16 ? 'Supported (shader-f16)' : 'FP32 / Q4 Compute';
    } catch {
      if (vendorEl) vendorEl.textContent = 'WASM CPU Mode';
    }
  }

  renderFirewallLogs(logs) {
    const tbody = document.getElementById('firewall-audit-tbody');
    const countBadge = document.getElementById('firewall-log-count');
    if (countBadge) {
      countBadge.textContent = `${logs.length} Events Logged`;
    }
    if (!tbody) return;
    tbody.innerHTML = '';
    if (logs.length === 0) {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td colspan="4" style="color:#94a3b8;">Zero outbound network calls recorded.</td>';
      tbody.appendChild(tr);
      return;
    }
    for (const item of logs) {
      const tr = document.createElement('tr');
      const color = item.blocked ? '#f43f5e' : '#10b981';
      tr.innerHTML = `
        <td><code>${item.time}</code></td>
        <td class="mono-token">${item.method}</td>
        <td><code>${item.url}</code></td>
        <td style="color:${color};font-weight:600;">${item.status}</td>
      `;
      tbody.appendChild(tr);
    }
  }

  initPiiWorkspace() {
    const chipContainer = document.getElementById('pii-category-chips');
    const rawInput = document.getElementById('pii-raw-input');
    const styleSelect = document.getElementById('pii-style-select');
    const preserveLocalhostChk = document.getElementById('chk-preserve-localhost');
    const customTermsInput = document.getElementById('custom-blocklist-input');
    const loadSampleBtn = document.getElementById('btn-load-sample-pii');
    const copyScrubbedBtn = document.getElementById('btn-copy-scrubbed');
    const llmScanBtn = document.getElementById('btn-llm-pii-scan');
    const stopLlmBtn = document.getElementById('btn-abort-llm');
    const rehydrateInput = document.getElementById('rehydrate-input');
    const runRehydrateBtn = document.getElementById('btn-run-rehydrate');

    if (chipContainer) {
      chipContainer.innerHTML = '';
      for (const [key, cfg] of Object.entries(PII_CATEGORIES)) {
        const label = document.createElement('label');
        label.className = 'chip-label';
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.checked = this.enabledPiiCategories[key];
        checkbox.addEventListener('change', () => {
          this.enabledPiiCategories[key] = checkbox.checked;
          this.executePiiScrub();
        });
        const span = document.createElement('span');
        span.textContent = cfg.label;
        label.appendChild(checkbox);
        label.appendChild(span);
        chipContainer.appendChild(label);
      }
    }

    if (rawInput) {
      rawInput.value = SAMPLE_PII_TEXT;
      rawInput.addEventListener('input', () => this.executePiiScrub());
    }

    if (styleSelect) {
      styleSelect.addEventListener('change', () => this.executePiiScrub());
    }

    if (preserveLocalhostChk) {
      preserveLocalhostChk.addEventListener('change', () => this.executePiiScrub());
    }

    if (customTermsInput) {
      customTermsInput.addEventListener('input', () => this.executePiiScrub());
    }

    if (loadSampleBtn) {
      loadSampleBtn.addEventListener('click', () => {
        if (rawInput) rawInput.value = SAMPLE_PII_TEXT;
        this.extraLlmEntities = [];
        this.executePiiScrub();
      });
    }

    if (copyScrubbedBtn) {
      copyScrubbedBtn.addEventListener('click', async () => {
        const out = document.getElementById('pii-scrubbed-output');
        if (out && out.value) {
          await navigator.clipboard.writeText(out.value);
          this.setStatusText('Sanitized prompt copied to clipboard!');
        }
      });
    }

    if (llmScanBtn) {
      llmScanBtn.addEventListener('click', () => {
        const scrubbedOut = document.getElementById('pii-scrubbed-output');
        const modelSelect = document.getElementById('slm-model-select');
        if (!scrubbedOut || !scrubbedOut.value.trim()) return;
        llmScanBtn.disabled = true;
        const messages = buildContextualPiiPrompt(scrubbedOut.value);
        this.worker?.postMessage({
          type: 'GENERATE_TEXT',
          payload: {
            messages,
            modelId: modelSelect?.value || 'HuggingFaceTB/SmolLM2-360M-Instruct',
            maxNewTokens: 160,
            temperature: 0.0,
            taskTag: 'pii_audit'
          }
        });
      });
    }

    if (stopLlmBtn) {
      stopLlmBtn.addEventListener('click', () => {
        this.worker?.postMessage({ type: 'ABORT_GENERATION' });
      });
    }

    if (runRehydrateBtn && rehydrateInput) {
      runRehydrateBtn.addEventListener('click', () => {
        const restored = rehydrateText(rehydrateInput.value, this.currentTokenMap);
        rehydrateInput.value = restored;
        this.setStatusText('Fuzzy-resilient re-hydration complete!');
      });
    }

    this.executePiiScrub();
  }

  executePiiScrub() {
    const rawInput = document.getElementById('pii-raw-input');
    const scrubbedOut = document.getElementById('pii-scrubbed-output');
    const styleSelect = document.getElementById('pii-style-select');
    const preserveLocalhostChk = document.getElementById('chk-preserve-localhost');
    const customTermsInput = document.getElementById('custom-blocklist-input');
    const countBadge = document.getElementById('pii-redaction-count');
    const riskBadge = document.getElementById('pii-risk-badge');
    const tableBody = document.getElementById('pii-vault-tbody');

    if (!rawInput || !scrubbedOut) return;

    const customTerms = (customTermsInput?.value || '')
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length >= 2);

    const result = scrubText(rawInput.value, {
      enabledCategories: this.enabledPiiCategories,
      extraEntities: this.extraLlmEntities,
      customTerms,
      preserveLocalhost: preserveLocalhostChk ? preserveLocalhostChk.checked : true,
      redactionStyle: styleSelect?.value || 'token'
    });

    scrubbedOut.value = result.scrubbedText;
    this.currentTokenMap = result.tokenToOriginal;

    if (countBadge) {
      countBadge.textContent = `${result.stats.totalRedactions} Redactions (${result.stats.uniqueEntities} Unique)`;
    }

    if (riskBadge) {
      const { score, level } = result.stats.risk;
      riskBadge.textContent = `Risk: ${level} (${score}/100)`;
      riskBadge.className = 'badge ' + (
        level === 'CRITICAL' ? 'badge-risk-critical' :
        level === 'HIGH' ? 'badge-risk-high' : 'badge-risk-safe'
      );
    }

    this.renderVaultTable(result.entities, tableBody);
  }

  renderVaultTable(entities, tableBody) {
    if (!tableBody) return;
    tableBody.innerHTML = '';
    if (!entities || entities.length === 0) {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td colspan="5" style="color:#94a3b8;">No sensitive entities detected.</td>';
      tableBody.appendChild(tr);
      return;
    }
    for (const ent of entities) {
      const tr = document.createElement('tr');
      const preview = ent.original.length > 36
        ? ent.original.slice(0, 33) + '...'
        : ent.original;
      tr.innerHTML = `
        <td class="mono-token">${ent.token}</td>
        <td>${PII_CATEGORIES[ent.category]?.label || ent.category}</td>
        <td><code>${preview.replace(/</g, '&lt;')}</code></td>
        <td><code>${ent.entropy} bits</code></td>
        <td>${ent.count}x</td>
      `;
      tableBody.appendChild(tr);
    }
  }

  initCryptoVaultControls() {
    const passInput = document.getElementById('vault-passphrase-input');
    const exportBtn = document.getElementById('btn-export-encrypted-vault');
    const importFile = document.getElementById('vault-import-file');

    if (exportBtn) {
      exportBtn.addEventListener('click', async () => {
        try {
          const passphrase = passInput?.value || '';
          const encryptedJson = await encryptVaultMap(this.currentTokenMap, passphrase);
          const blob = new Blob([encryptedJson], { type: 'application/json;charset=utf-8' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `localvault-encrypted-${new Date().toISOString().slice(0, 10)}.lvvault`;
          a.click();
          URL.revokeObjectURL(url);
          this.setStatusText('Exported AES-256-GCM encrypted .lvvault file!');
        } catch (err) {
          this.setStatusText(`Vault Encryption Notice: ${err.message}`);
        }
      });
    }

    if (importFile) {
      importFile.addEventListener('change', async (e) => {
        const file = e.target.files?.[0];
        if (!file) return;
        try {
          const passphrase = passInput?.value || '';
          const rawJson = await file.text();
          const restoredMap = await decryptVaultMap(rawJson, passphrase);
          this.currentTokenMap = { ...this.currentTokenMap, ...restoredMap };
          const syntheticEntities = Object.entries(this.currentTokenMap).map(([token, original]) => ({
            token,
            category: 'CUSTOM',
            original,
            entropy: 'AES-GCM',
            count: 1
          }));
          this.renderVaultTable(syntheticEntities, document.getElementById('pii-vault-tbody'));
          this.setStatusText(
            `Unlocked & imported ${Object.keys(restoredMap).length} tokens from encrypted vault!`
          );
        } catch (err) {
          this.setStatusText(`Vault Decryption Error: ${err.message}`);
        }
      });
    }
  }

  initAudioWorkspace() {
    const recordBtn = document.getElementById('btn-mic-record');
    const fileInput = document.getElementById('audio-file-input');
    const synthBtn = document.getElementById('btn-synth-test-audio');
    const downloadWavBtn = document.getElementById('btn-download-wav');
    const runWhisperBtn = document.getElementById('btn-run-whisper');
    const loadLectureBtn = document.getElementById('btn-demo-lecture');
    const loadMeetingBtn = document.getElementById('btn-demo-meeting');
    const instantStructureBtn = d
