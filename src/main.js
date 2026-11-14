
/**
 * LocalVault AI — Browser UI Controller
 *
 * Connects PII scrubbing, encrypted vault storage, network monitoring,
 * audio utilities, note structuring and local inference.
 *
 * Security:
 * - No default vault password.
 * - The AI receives only the latest scrubbed text.
 * - AI output is kept separate from the sanitized source.
 * - Firewall audit entries are rendered as text, never HTML.
 * - The exfiltration demo is simulated without sending a request.
 *
 * Note: First-time model/library downloads may require internet access.
 */

import { PIIEngine, rehydrateText } from './pii-engine.js';
import { CryptoVault } from './crypto-vault.js';
import { NetworkFirewall } from './network-firewall.js';
import { structureTranscript } from './note-structurer.js';
import { synthesizeTestWav, exportWavBlob } from './audio-utils.js';

export function initLocalVaultApp() {
  if (typeof document === 'undefined') return null;

  const piiEngine = new PIIEngine();
  const cryptoVault = new CryptoVault();

  const firewall = new NetworkFirewall();
  let firewallInstallError = null;

  try {
    firewall.install(window);
  } catch (error) {
    firewallInstallError = error?.message || String(error);
  }

  let latestVaultMap = {};
  let latestScrubbedText = null;
  let latestAudioSamples = null;
  let worker = null;
  let workerBusy = false;
  let activeWorkerTask = null;
  let activePrompt = '';

  const getElement = (id) => document.getElementById(id);

  function setStatus(element, message, state = 'warn') {
    if (!element) return;

    element.textContent = message;
    element.className = `status-pill status-${state}`;
  }

  function showError(element, error) {
    if (!element) return;

    const message = error?.message || String(error || 'Unknown error');
    element.value = `ERROR: ${message}`;
  }

  function setWorkerBusy(busy, task = null) {
    workerBusy = Boolean(busy);
    activeWorkerTask = workerBusy ? task : null;

    const askButton = getElement('btn-ask-slm');
    const abortButton = getElement('btn-abort-slm');
    const transcribeButton = getElement('btn-transcribe');

    if (askButton) askButton.disabled = workerBusy || !worker;
    if (transcribeButton) transcribeButton.disabled = workerBusy || !worker;

    if (abortButton) {
      abortButton.disabled =
        !workerBusy || activeWorkerTask !== 'generate';
    }
  }

  function downloadBlob(blob, filename) {
    if (!(blob instanceof Blob)) {
      throw new Error('The requested download is not a valid file.');
    }

    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');

    anchor.href = url;
    anchor.download = filename;
    anchor.style.display = 'none';

    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();

    window.setTimeout(() => URL.revokeObjectURL(url), 1500);
  }

  // ------------------------------------------------------------
  // Separate output area for local AI responses.
  // This keeps the sanitized source visible and unchanged.
  // ------------------------------------------------------------

  function createSlmOutput() {
    const existing = getElement('slm-output');
    if (existing) return existing;

    const piiOutput = getElement('pii-output');
    if (!piiOutput) return null;

    const card = piiOutput.closest('.lv-card');
    if (!card) return null;

    const label = document.createElement('label');
    label.htmlFor = 'slm-output';
    label.textContent = 'Local AI Response';

    const output = document.createElement('textarea');
    output.id = 'slm-output';
    output.className = 'lv-textarea mono';
    output.rows = 7;
    output.readOnly = true;
    output.placeholder = 'Local model responses will appear here.';

    const stats = getElement('pii-stats-bar');

    if (stats && stats.parentElement === card) {
      stats.insertAdjacentElement('afterend', label);
      label.insertAdjacentElement('afterend', output);
    } else {
      card.append(label, output);
    }

    return output;
  }

  // ------------------------------------------------------------
  // Runtime capability indicators
  // ------------------------------------------------------------

  const webgpuBadge = getElement('webgpu-badge');
  const coiBadge = getElement('coi-badge');

  if (coiBadge) {
    const isolated = Boolean(window.crossOriginIsolated);

    setStatus(
      coiBadge,
      isolated ? 'COI: Isolated' : 'COI: Fallback Mode',
      isolated ? 'ok' : 'warn'
    );
  }

  if (webgpuBadge) {
    if (navigator.gpu?.requestAdapter) {
      navigator.gpu.requestAdapter()
        .then((adapter) => {
          setStatus(
            webgpuBadge,
            adapter ? 'WebGPU: Available' : 'WebGPU: WASM Fallback',
            adapter ? 'ok' : 'warn'
          );
        })
        .catch(() => {
          setStatus(webgpuBadge, 'WebGPU: WASM Fallback', 'warn');
        });
    } else {
      setStatus(webgpuBadge, 'WebGPU: WASM Fallback', 'warn');
    }
  }

  // ------------------------------------------------------------
  // Dedicated inference worker
  // ------------------------------------------------------------

  try {
    worker = new Worker(
      new URL('./worker.js', import.meta.url),
      { type: 'module' }
    );
  } catch (error) {
    console.error('LocalVault worker initialization failed:', error);

    setStatus(
      webgpuBadge,
      'Local worker unavailable',
      'warn'
    );
  }

  if (worker) {
    worker.addEventListener('message', (event) => {
      const data = event.data || {};

      if (data.type === 'status') {
        const message = data.message || 'Local model is loading.';

        const stats = getElement('pii-stats-bar');
        if (stats) stats.textContent = message;

        return;
      }

      if (data.type === 'generation-complete') {
        const output = getElement('slm-output') || createSlmOutput();

        if (output) {
          const generated = String(data.text || '');

          output.value = generated.startsWith(activePrompt)
            ? generated.slice(activePrompt.length).trim()
            : generated;

          if (!output.value) {
            output.value = 'The model returned an empty response.';
          }
        }

        const stats = getElement('pii-stats-bar');

        if (stats) {
          stats.textContent =
            `Local inference complete · ${data.device || 'unknown device'} · ` +
            `${data.model || 'unknown model'}`;
        }

        setWorkerBusy(false);
        return;
      }

      if (data.type === 'transcription-complete') {
        const transcript = getElement('transcript-input');

        if (transcript) {
          transcript.value = String(data.text || '');
        }

        const structured = getElement('structured-output');

        if (structured) {
          structured.value = data.text
            ? 'Transcription completed. Review the transcript, then select Structure & Auto-Scrub Notes.'
            : 'The model did not return a transcript.';
        }

        setWorkerBusy(false);
        return;
      }

      if (data.type === 'aborted') {
        const stats = getElement('pii-stats-bar');

        if (stats) stats.textContent = 'Generation cancelled.';

        setWorkerBusy(false);
        return;
      }

      if (data.type === 'error') {
        const message =
          data.error || 'The local worker reported an error.';

        const stats = getElement('pii-stats-bar');

        if (stats) {
          stats.textContent = `Worker error: ${message}`;
        }

        if (activeWorkerTask === 'generate') {
          const output = getElement('slm-output');

          if (output) {
            output.value = `GENERATION ERROR: ${message}`;
          }
        }

        if (activeWorkerTask === 'transcribe') {
          const structured = getElement('structured-output');

          if (structured) {
            structured.value = `TRANSCRIPTION ERROR: ${message}`;
          }
        }

        setWorkerBusy(false);
      }
    });

    worker.addEventListener('error', (event) => {
      const message =
        event.message || 'The local worker stopped unexpectedly.';

      const stats = getElement('pii-stats-bar');

      if (stats) {
        stats.textContent = `Worker error: ${message}`;
      }

      worker.terminate();
      worker = null;

      setWorkerBusy(false);
      setStatus(webgpuBadge, 'Local worker unavailable', 'warn');
    });

    worker.addEventListener('messageerror', () => {
      const stats = getElement('pii-stats-bar');

      if (stats) {
        stats.textContent = 'Worker message could not be decoded.';
      }

      setWorkerBusy(false);
    });
  }

  setWorkerBusy(false);

  // ------------------------------------------------------------
  // Tab navigation
  // ------------------------------------------------------------

  const tabs = document.querySelectorAll('.lv-tab');
  const panels = document.querySelectorAll('.lv-panel');

  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      tabs.forEach((item) => {
        item.classList.remove('active');
        item.setAttribute('aria-selected', 'false');
      });

      panels.forEach((panel) => panel.classList.remove('active'));

      tab.classList.add('active');
      tab.setAttribute('aria-selected', 'true');

      const target = getElement(tab.dataset.tab);

      if (target) {
        target.classList.add('active');
      }
    });
  });

  // ------------------------------------------------------------
  // Tab 1: PII and secret scrubber
  // ------------------------------------------------------------

  const piiInput = getElement('pii-input');
  const piiOutput = getElement('pii-output');
  const piiStatsBar = getElement('pii-stats-bar');
  const customBlockInput = getElement('custom-block-input');

  getElement('btn-load-sample')?.addEventListener('click', () => {
    if (!piiInput) return;

    piiInput.value = [
      '# Synthetic LocalVault security test data',
      'DATABASE_URL=postgres://demo:FakePassword123!@198.51.100.42:5432/demo_db',
      'OPENAI_API_KEY=sk-proj-9a8b7c6d5e4f3g2h1i0j9k8l7m6n5o4p3q2r1s',
      'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
      'LOCAL_DEV_HOST=127.0.0.1',
      'Customer Jane Doe (email: jane.doe@example.org, SSN: 123-45-6789) reported card 4532-0151-1283-0366 failed.'
    ].join('\n');

    latestScrubbedText = null;
    latestVaultMap = {};

    if (piiOutput) piiOutput.value = '';

    const slmOutput = getElement('slm-output');
    if (slmOutput) slmOutput.value = '';

    if (piiStatsBar) {
      piiStatsBar.textContent =
        'Sample loaded. Select Scrub 4 Layers before using the AI model.';
    }
  });

  getElement('btn-add-block')?.addEventListener('click', () => {
    if (!customBlockInput) return;

    const term = customBlockInput.value.trim();

    if (!term) return;

    piiEngine.addBlocklistTerm(term);
    customBlockInput.value = '';

    if (piiStatsBar) {
      piiStatsBar.textContent = 'Custom blocklist term added.';
    }
  });

  getElement('btn-scrub')?.addEventListener('click', () => {
    if (!piiInput || !piiOutput) return;

    try {
      const result = piiEngine.scrub(piiInput.value);

      latestVaultMap = { ...result.vaultMap };
      latestScrubbedText = result.scrubbedText;

      piiOutput.value = result.scrubbedText;

      const slmOutput = getElement('slm-output');

      if (slmOutput) {
        slmOutput.value = '';
      }

      if (piiStatsBar) {
        const layers = result.stats.byLayer;

        piiStatsBar.textContent =
          `Total Redacted: ${result.stats.totalRedacted} | ` +
          `Layer 1: ${layers[1]} | ` +
          `Layer 2: ${layers[2]} | ` +
          `Layer 3: ${layers[3]} | ` +
          `Layer 4 heuristic: ${layers[4]}`;
      }
    } catch (error) {
      showError(piiOutput, error);
    }
  });

  getElement('btn-rehydrate')?.addEventListener('click', () => {
    if (!piiOutput) return;

    try {
      piiOutput.value = rehydrateText(
        piiOutput.value,
        latestVaultMap
      );
    } catch (error) {
      showError(piiOutput, error);
    }
  });

  // ------------------------------------------------------------
  // Tab 1: Local SLM generation
  // ------------------------------------------------------------

  getElement('btn-ask-slm')?.addEventListener('click', () => {
    if (!worker) {
      if (piiStatsBar) {
        piiStatsBar.textContent =
          'Local AI worker is unavailable in this browser session.';
      }

      return;
    }

    if (workerBusy) return;

    if (
      typeof latestScrubbedText !== 'string' ||
      !latestScrubbedText.trim()
    ) {
      if (piiStatsBar) {
        piiStatsBar.textContent =
          'Scrub your input first. The model only receives the latest scrubbed text.';
      }

      return;
    }

    activePrompt =
      'Summarize the following sanitized developer content. ' +
      'Do not invent missing facts or credentials.\n\n' +
      latestScrubbedText;

    try {
      setWorkerBusy(true, 'generate');

      worker.postMessage({
        type: 'generate',
        payload: {
          prompt: activePrompt,
          maxNewTokens: 192
        }
      });

      if (piiStatsBar) {
        piiStatsBar.textContent =
          'Preparing local model inference. First-time model downloads may require internet access.';
      }
    } catch (error) {
      setWorkerBusy(false);

      if (piiStatsBar) {
        piiStatsBar.textContent =
          `Could not start generation: ${error.message}`;
      }
    }
  });

  getElement('btn-abort-slm')?.addEventListener('click', () => {
    if (
      !worker ||
      !workerBusy ||
      activeWorkerTask !== 'generate'
    ) {
      return;
    }

    try {
      worker.postMessage({ type: 'abort' });
    } catch (error) {
      if (piiStatsBar) {
        piiStatsBar.textContent =
          `Could not abort generation: ${error.message}`;
      }

      setWorkerBusy(false);
    }
  });

  // ------------------------------------------------------------
  // Tab 2: Audio test utilities and note structuring
  // ------------------------------------------------------------

  const transcriptInput = getElement('transcript-input');
  const structuredOutput = getElement('structured-output');
  const noteModeSelect = getElement('note-mode-select');

  getElement('btn-synth-wav')?.addEventListener('click', () => {
    try {
      const synth = synthesizeTestWav({
        durationSeconds: 1.5,
        sampleRate: 16000
      });

      latestAudioSamples = synth.samples;

      const wavBlob = exportWavBlob(
        synth.samples,
        synth.sampleRate
      );

      downloadBlob(
        wavBlob,
        `localvault-test-${Date.now()}.wav`
      );

      if (structuredOutput) {
        structuredOutput.value =
          'A synthetic test-tone WAV was generated and downloaded. ' +
          'It is not recorded speech. Real microphone and file-audio input are not connected yet.';
      }
    } catch (error) {
      showError(structuredOutput, error);
    }
  });

  getElement('btn-transcribe')?.addEventListener('click', () => {
    if (!worker) {
      if (structuredOutput) {
        structuredOutput.value =
          'The local AI worker is unavailable.';
      }

      return;
    }

    if (workerBusy) return;

    if (!latestAudioSamples) {
      if (structuredOutput) {
        structuredOutput.value =
          'Generate the test WAV first. Real microphone and file-audio input are not implemented yet.';
      }

      return;
    }

    try {
      setWorkerBusy(true, 'transcribe');

      worker.postMessage({
        type: 'transcribe',
        payload: {
          audio: latestAudioSamples
        }
      });

      if (structuredOutput) {
        structuredOutput.value =
          'Transcribing the generated test tone. A test tone is not natural speech, so the result may not be meaningful.';
      }
    } catch (error) {
      setWorkerBusy(false);
      showError(structuredOutput, error);
    }
  });

  getElement('btn-structure-notes')?.addEventListener('click', () => {
    if (!transcriptInput || !structuredOutput) return;

    if (!transcriptInput.value.trim()) {
      structuredOutput.value =
        'Enter a transcript or notes before structuring.';

      return;
    }

    try {
      const mode = noteModeSelect?.value || 'meeting';

      const result = structureTranscript(
        transcriptInput.value,
        {
          mode,
          autoScrub: true,
          piiEngine
        }
      );

      latestVaultMap = {
        ...latestVaultMap,
        ...result.vaultMap
      };

      structuredOutput.value = result.markdown;
    } catch (error) {
      showError(structuredOutput, error);
    }
  });

  // ------------------------------------------------------------
  // Tab 3: Encrypted vault
  // ------------------------------------------------------------

  const vaultPassphrase = getElement('vault-passphrase');
  const vaultCiphertext = getElement('vault-ciphertext');
  const vaultPlaintext = getElement('vault-plaintext');

  getElement('btn-lock-vault')?.addEventListener('click', async () => {
    if (!vaultPassphrase || !vaultCiphertext || !vaultPlaintext) return;

    const passphrase = vaultPassphrase.value;

    if (!passphrase.trim()) {
      vaultPlaintext.value = 'ERROR: Enter a master passphrase.';
      vaultPassphrase.focus();
      return;
    }

    if (passphrase.length < 12) {
      vaultPlaintext.value =
        'ERROR: Use a passphrase with at least 12 characters.';

      vaultPassphrase.focus();
      return;
    }

    if (Object.keys(latestVaultMap).length === 0) {
      vaultPlaintext.value =
        'ERROR: No redacted data is available. Scrub input or structure notes first.';

      return;
    }

    try {
      const envelope = await cryptoVault.lock(
        latestVaultMap,
        passphrase
      );

      vaultCiphertext.value =
        cryptoVault.exportLvVault(envelope);

      vaultPlaintext.value =
        '[VAULT LOCKED — AES-256-GCM AUTHENTICATED]';
    } catch (error) {
      showError(vaultPlaintext, error);
    }
  });

  getElement('btn-unlock-vault')?.addEventListener('click', async () => {
    if (!vaultPassphrase || !vaultCiphertext || !vaultPlaintext) return;

    const passphrase = vaultPassphrase.value;

    if (!passphrase.trim()) {
      vaultPlaintext.value = 'ERROR: Enter the vault passphrase.';
      vaultPassphrase.focus();
      return;
    }

    if (!vaultCiphertext.value.trim()) {
      vaultPlaintext.value =
        'ERROR: Paste or import an encrypted vault file first.';

      return;
    }

    try {
      const unlocked = await cryptoVault.unlock(
        vaultCiphertext.value,
        passphrase
      );

      vaultPlaintext.value = JSON.stringify(
        unlocked,
        null,
        2
      );
    } catch (error) {
      showError(vaultPlaintext, error);
    }
  });

  getElement('btn-export-vault')?.addEventListener('click', () => {
    if (!vaultCiphertext || !vaultCiphertext.value.trim()) {
      if (vaultPlaintext) {
        vaultPlaintext.value =
          'ERROR: There is no encrypted vault to export.';
      }

      return;
    }

    try {
      const blob = new Blob(
        [vaultCiphertext.value],
        { type: 'application/json' }
      );

      downloadBlob(
        blob,
        `localvault-${Date.now()}.lvvault`
      );
    } catch (error) {
      showError(vaultPlaintext, error);
    }
  });

  // ------------------------------------------------------------
  // Tab 4: Network activity monitor
  // ------------------------------------------------------------

  const firewallStats = getElement('firewall-stats');
  const firewallLog = getElement('firewall-log');

  function renderFirewallAudit() {
    if (!firewallStats || !firewallLog) return;

    const stats = firewall.getStats();

    firewallStats.textContent =
      `Recorded Events: ${stats.totalEvents} | ` +
      `Allowed Read-Only: ${stats.allowed} | ` +
      `Blocked Events: ${stats.blocked}`;

    // Safe rendering: never insert audit values as HTML.
    const fragment = document.createDocumentFragment();

    for (const event of firewall.auditLog) {
      const row = document.createElement('div');
      const timestamp = document.createElement('span');
      const action = document.createElement('strong');
      const details = document.createElement('span');

      timestamp.textContent =
        `[${String(event.timestamp || '')}] `;

      action.textContent =
        String(event.action || 'EVENT');

      details.textContent =
        ` (${String(event.method || '')} ${String(event.url || '')}) — ` +
        String(event.reason || '');

      row.append(timestamp, action, details);
      fragment.appendChild(row);
    }

    firewallLog.replaceChildren(fragment);
  }

  firewall.onAuditEvent(() => renderFirewallAudit());

  if (firewallInstallError && firewallStats) {
    firewallStats.textContent =
      `Request monitor could not install: ${firewallInstallError}`;
  }

  getElement('airgap-toggle')?.addEventListener('change', (event) => {
    firewall.setAirGapLockdown(
      Boolean(event.target.checked)
    );

    renderFirewallAudit();
  });

  getElement('btn-test-exfil')?.addEventListener('click', () => {
    // Local policy simulation only. No outbound request is sent.
    firewall.inspectRequest(
      'https://telemetry-collector.example.org/exfiltrate',
      'POST',
      JSON.stringify({ simulation: true })
    );

    renderFirewallAudit();
  });

  renderFirewallAudit();

  return {
    piiEngine,
    cryptoVault,
    firewall,
    getLatestScrubbedText: () => latestScrubbedText,
    getLatestVaultMap: () => ({ ...latestVaultMap })
  };
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener(
      'DOMContentLoaded',
      () => initLocalVaultApp(),
      { once: true }
    );
  } else {
    initLocalVaultApp();
  }
}
