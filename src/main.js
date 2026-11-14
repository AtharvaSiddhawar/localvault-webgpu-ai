/** Browser UI orchestration. Keep browser-only APIs in this module. */
import { PIIEngine, rehydrateText } from './pii-engine.js';
import { CryptoVault } from './crypto-vault.js';
import { NetworkFirewall } from './network-firewall.js';
import { structureTranscript } from './note-structurer.js';
import { decodeAudioFile, exportWavBlob, synthesizeTestWav, WHISPER_SAMPLE_RATE } from './audio-utils.js';

export function initLocalVaultApp() {
  if (typeof document === 'undefined') return null;
  const $ = (id) => document.getElementById(id);
  const piiEngine = new PIIEngine();
  const cryptoVault = new CryptoVault();
  const firewall = new NetworkFirewall();
  let worker = null;
  let workerBusy = false;
  let activeTask = null;
  let latestScrubbedText = '';
  let latestVaultMap = {};
  let latestAudioSamples = null;
  let mediaRecorder = null;
  let recordingStream = null;
  let recordingChunks = [];
  let recordingTimer = null;

  const setStatus = (element, message, state = 'warn') => {
    if (!element) return;
    element.textContent = message;
    element.className = `status-pill status-${state}`;
  };
  const setText = (id, message) => { const el = $(id); if (el) el.textContent = message; };
  const showError = (element, error) => { if (element) element.value = `ERROR: ${error?.message || String(error)}`; };
  const downloadBlob = (blob, filename) => {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url; link.download = filename; link.hidden = true;
    document.body.appendChild(link); link.click(); link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1500);
  };
  const setBusy = (busy, task = null) => {
    workerBusy = Boolean(busy); activeTask = workerBusy ? task : null;
    if ($('btn-ask-slm')) $('btn-ask-slm').disabled = workerBusy || !worker || !latestScrubbedText;
    if ($('btn-transcribe')) $('btn-transcribe').disabled = workerBusy || !worker || !latestAudioSamples;
    if ($('btn-abort-slm')) $('btn-abort-slm').disabled = !workerBusy || task !== 'generate';
  };
  const loadWorker = () => {
    try { worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module', name: 'localvault-inference' }); }
    catch (error) { setStatus($('webgpu-badge'), `Worker unavailable: ${error.message}`, 'error'); return; }
    worker.addEventListener('message', ({ data = {} }) => {
      if (data.type === 'status') { setText('pii-stats-bar', data.message || 'Local model is working.'); if (data.task === 'transcribe') setText('audio-status', data.message || 'Transcribing audio…'); return; }
      if (data.type === 'pong') { setStatus($('webgpu-badge'), `Inference: ${data.device.toUpperCase()}`, 'ok'); return; }
      if (data.type === 'generation-complete') {
        $('slm-output').value = String(data.text || '').trim() || 'The model returned an empty response.';
        setText('pii-stats-bar', `Inference complete · ${data.device} · ${data.model}`); setBusy(false); return;
      }
      if (data.type === 'transcription-complete') {
        $('transcript-input').value = String(data.text || '');
        $('structured-output').value = data.text ? 'Transcription complete. Review the transcript, then structure and scrub the notes.' : 'The model did not return a transcript.';
        setText('audio-status', `Transcription complete · ${data.device} · ${data.model}`); setBusy(false); return;
      }
      if (data.type === 'aborted') { setText('pii-stats-bar', 'Generation cancelled.'); setBusy(false); return; }
      if (data.type === 'error') {
        const message = data.error || 'The inference worker reported an error.';
        if (activeTask === 'generate') $('slm-output').value = `GENERATION ERROR: ${message}`;
        if (activeTask === 'transcribe') $('structured-output').value = `TRANSCRIPTION ERROR: ${message}`;
        setText('pii-stats-bar', `Worker error: ${message}`); setText('audio-status', `Audio error: ${message}`); setBusy(false);
      }
    });
    worker.addEventListener('error', (event) => {
      setStatus($('webgpu-badge'), 'Inference worker error', 'error');
      setText('pii-stats-bar', event.message || 'The worker stopped unexpectedly.');
      worker?.terminate(); worker = null; setBusy(false);
    });
    worker.addEventListener('messageerror', () => { setText('pii-stats-bar', 'Worker message could not be decoded.'); setBusy(false); });
    worker.postMessage({ type: 'ping' });
  };

  // Status and browser worker initialization.
  setStatus($('coi-badge'), window.crossOriginIsolated ? 'Isolation: enabled' : 'Isolation: limited', window.crossOriginIsolated ? 'ok' : 'warn');
  if (navigator.gpu?.requestAdapter) navigator.gpu.requestAdapter().then((adapter) => setStatus($('webgpu-badge'), adapter ? 'WebGPU: available' : 'WebGPU: WASM fallback', adapter ? 'ok' : 'warn')).catch(() => setStatus($('webgpu-badge'), 'WebGPU: WASM fallback', 'warn'));
  else setStatus($('webgpu-badge'), 'WebGPU: WASM fallback', 'warn');
  try { firewall.install(window); } catch (error) { setText('firewall-stats', `Request monitor install error: ${error.message}`); }
  loadWorker();

  // Tab navigation.
  document.querySelectorAll('.tab').forEach((tab) => tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((item) => { item.classList.toggle('active', item === tab); item.setAttribute('aria-selected', String(item === tab)); });
    document.querySelectorAll('.panel').forEach((panel) => panel.classList.toggle('active', panel.id === tab.dataset.tab));
  }));

  // PII scrubber.
  $('btn-load-sample')?.addEventListener('click', () => {
    $('pii-input').value = [
      '# Synthetic LocalVault test text',
      'DATABASE_URL=postgres://demo:ExamplePassword123!@198.51.100.42:5432/demo',
      'OPENAI_API_KEY=sk-proj-9a8b7c6d5e4f3g2h1i0j9k8l7m6n5o4p3q2r1s',
      'LOCAL_DEV_HOST=127.0.0.1',
      'Customer Jane Doe can be reached at jane.doe@example.org.'
    ].join('\n');
    latestScrubbedText = ''; latestVaultMap = {};
    $('pii-output').value = ''; $('slm-output').value = '';
    setText('pii-stats-bar', 'Sample loaded. Select Scrub text before running local inference.'); setBusy(false);
  });
  $('btn-add-block')?.addEventListener('click', () => {
    const field = $('custom-block-input'); const value = field.value.trim();
    if (!value) return;
    piiEngine.addBlocklistTerm(value); field.value = ''; setText('pii-stats-bar', 'Custom blocklist term added.');
  });
  $('btn-scrub')?.addEventListener('click', () => {
    try {
      const result = piiEngine.scrub($('pii-input').value);
      latestVaultMap = { ...latestVaultMap, ...result.vaultMap };
      latestScrubbedText = result.scrubbedText;
      $('pii-output').value = result.scrubbedText; $('slm-output').value = '';
      const layers = result.stats.byLayer;
      setText('pii-stats-bar', `Redacted: ${result.stats.totalRedacted} · Layer 1: ${layers[1]} · Layer 2: ${layers[2]} · Layer 3: ${layers[3]} · Layer 4: ${layers[4]}`);
      setBusy(false);
    } catch (error) { showError($('pii-output'), error); }
  });
  $('btn-rehydrate')?.addEventListener('click', () => { $('pii-output').value = rehydrateText($('pii-output').value, latestVaultMap); });
  $('btn-ask-slm')?.addEventListener('click', () => {
    if (!worker || workerBusy) return;
    if (!latestScrubbedText.trim()) { setText('pii-stats-bar', 'Scrub the input first. The model receives only the latest sanitized text.'); return; }
    setBusy(true, 'generate'); $('slm-output').value = 'Loading the local model…';
    worker.postMessage({ type: 'generate', payload: { prompt: `Summarize this sanitized developer content. Do not invent facts or infer missing credentials.\n\n${latestScrubbedText}`, model: 'HuggingFaceTB/SmolLM2-135M-Instruct', maxNewTokens: 192 } });
  });
  $('btn-abort-slm')?.addEventListener('click', () => { if (worker && activeTask === 'generate') worker.postMessage({ type: 'abort' }); });

  // Audio decoding and inference.
  const setAudioSamples = (samples, description) => {
    latestAudioSamples = samples instanceof Float32Array ? samples : null;
    setText('audio-status', latestAudioSamples ? `${description} · ${latestAudioSamples.length / WHISPER_SAMPLE_RATE}s · 16 kHz mono ready` : description);
    setBusy(false);
  };
  const decodeBlob = async (blob, description) => {
    try { const decoded = await decodeAudioFile(blob); setAudioSamples(decoded.samples, description); }
    catch (error) { latestAudioSamples = null; setText('audio-status', `Audio error: ${error.message}`); setBusy(false); }
  };
  $('audio-file-input')?.addEventListener('change', async (event) => {
    const file = event.target.files?.[0]; if (!file) return;
    setText('audio-status', `Decoding ${file.name}…`);
    await decodeBlob(file, `Loaded ${file.name}`);
  });
  $('btn-synth-wav')?.addEventListener('click', () => {
    try { const wav = synthesizeTestWav({ durationSeconds: 1.5, sampleRate: WHISPER_SAMPLE_RATE }); setAudioSamples(wav.samples, 'Synthetic test tone generated'); downloadBlob(exportWavBlob(wav.samples, wav.sampleRate), `localvault-test-${Date.now()}.wav`); }
    catch (error) { setText('audio-status', `Audio error: ${error.message}`); }
  });
  $('btn-record-start')?.addEventListener('click', async () => {
    if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === 'undefined') { setText('audio-status', 'Microphone recording is not supported in this browser.'); return; }
    try {
      recordingStream = await navigator.mediaDevices.getUserMedia({ audio: { channelCount: 1, echoCancellation: true, noiseSuppression: true } });
      const mime = ['audio/webm;codecs=opus', 'audio/webm', 'audio/mp4'].find((type) => MediaRecorder.isTypeSupported?.(type));
      mediaRecorder = mime ? new MediaRecorder(recordingStream, { mimeType: mime }) : new MediaRecorder(recordingStream);
      recordingChunks = [];
      mediaRecorder.addEventListener('dataavailable', (event) => { if (event.data?.size) recordingChunks.push(event.data); });
      mediaRecorder.addEventListener('stop', async () => {
        clearTimeout(recordingTimer); recordingStream?.getTracks().forEach((track) => track.stop()); recordingStream = null;
        const blob = new Blob(recordingChunks, { type: mediaRecorder?.mimeType || 'audio/webm' });
        $('btn-record-start').disabled = false; $('btn-record-stop').disabled = true;
        await decodeBlob(blob, 'Microphone recording decoded');
      }, { once: true });
      mediaRecorder.start(500); $('btn-record-start').disabled = true; $('btn-record-stop').disabled = false;
      setText('audio-status', 'Recording microphone audio… Stop recording to decode it.');
      recordingTimer = window.setTimeout(() => { if (mediaRecorder?.state === 'recording') mediaRecorder.stop(); }, 600000);
    } catch (error) { recordingStream?.getTracks().forEach((track) => track.stop()); recordingStream = null; setText('audio-status', `Microphone error: ${error.message}`); }
  });
  $('btn-record-stop')?.addEventListener('click', () => { if (mediaRecorder?.state === 'recording') mediaRecorder.stop(); });
  $('btn-transcribe')?.addEventListener('click', () => {
    if (!worker || workerBusy || !latestAudioSamples) return;
    setBusy(true, 'transcribe'); $('structured-output').value = 'Loading local Whisper model and transcribing…';
    const audioCopy = new Float32Array(latestAudioSamples);
    worker.postMessage({ type: 'transcribe', payload: { audio: audioCopy, model: 'onnx-community/whisper-tiny.en' } }, [audioCopy.buffer]);
  });
  $('btn-structure-notes')?.addEventListener('click', () => {
    const text = $('transcript-input').value;
    if (!text.trim()) { $('structured-output').value = 'Enter a transcript or notes before structuring.'; return; }
    try {
      const result = structureTranscript(text, { mode: $('note-mode-select').value, autoScrub: true, piiEngine });
      latestVaultMap = { ...latestVaultMap, ...result.vaultMap };
      $('structured-output').value = result.markdown;
      setText('audio-status', `Notes structured · ${result.piiStats.totalRedacted} sensitive item(s) scrubbed`);
    } catch (error) { showError($('structured-output'), error); }
  });

  // Vault import/export/encrypt/decrypt. File contents are validated before use.
  $('btn-lock-vault')?.addEventListener('click', async () => {
    const passphrase = $('vault-passphrase').value;
    if (Object.keys(latestVaultMap).length === 0) { $('vault-plaintext').value = 'ERROR: Scrub text or notes before creating a vault.'; return; }
    try { const envelope = await cryptoVault.lock(latestVaultMap, passphrase); $('vault-ciphertext').value = cryptoVault.exportLvVault(envelope); $('vault-plaintext').value = '[VAULT LOCKED — AES-256-GCM AUTHENTICATED]'; $('vault-passphrase').value = ''; }
    catch (error) { showError($('vault-plaintext'), error); }
  });
  $('btn-unlock-vault')?.addEventListener('click', async () => {
    try { const data = await cryptoVault.unlock($('vault-ciphertext').value, $('vault-passphrase').value); $('vault-plaintext').value = JSON.stringify(data, null, 2); if (data && typeof data === 'object' && !Array.isArray(data)) latestVaultMap = { ...data }; $('vault-passphrase').value = ''; }
    catch (error) { showError($('vault-plaintext'), error); }
  });
  $('btn-export-vault')?.addEventListener('click', () => {
    try { const text = cryptoVault.exportLvVault(JSON.parse($('vault-ciphertext').value)); downloadBlob(new Blob([text], { type: 'application/json' }), `localvault-${Date.now()}.lvvault`); }
    catch (error) { showError($('vault-plaintext'), error); }
  });
  $('btn-import-vault')?.addEventListener('click', () => $('vault-file-input').click());
  $('vault-file-input')?.addEventListener('change', async (event) => {
    const file = event.target.files?.[0]; if (!file) return;
    try {
      if (file.size > 50 * 1024 * 1024) throw new Error('Vault file exceeds 50 MB.');
      const contents = await file.text();
      const parsed = JSON.parse(contents);
      $('vault-ciphertext').value = cryptoVault.exportLvVault(parsed);
      $('vault-plaintext').value = `Imported ${file.name}. Enter the passphrase and select Unlock.`;
    } catch (error) { showError($('vault-plaintext'), error); }
    finally { event.target.value = ''; }
  });

  // Page-level request monitoring + worker-level lockdown synchronization.
  const renderAudit = () => {
    const stats = firewall.getStats();
    setText('firewall-stats', `Recorded: ${stats.totalEvents} · Allowed: ${stats.allowed} · Blocked: ${stats.blocked} · Interceptors: ${stats.installed ? 'installed' : 'partial'}`);
    const log = $('firewall-log'); if (!log) return;
    const fragment = document.createDocumentFragment();
    for (const item of firewall.auditLog) {
      const row = document.createElement('div'); row.className = 'audit-row';
      const action = document.createElement('span'); action.className = 'audit-action'; action.textContent = `${item.action || 'EVENT'} `;
      const rest = document.createElement('span'); rest.textContent = `${item.timestamp || ''} · ${item.method || ''} ${item.url || ''} · ${item.reason || ''}`;
      row.append(action, rest); fragment.appendChild(row);
    }
    log.replaceChildren(fragment);
  };
  firewall.onAuditEvent(renderAudit);
  $('airgap-toggle')?.addEventListener('change', (event) => {
    const enabled = Boolean(event.target.checked);
    firewall.setAirGapLockdown(enabled);
    worker?.postMessage({ type: 'airgap', enabled });
    renderAudit();
  });
  $('btn-test-exfil')?.addEventListener('click', () => { firewall.inspectRequest('https://telemetry.example.invalid/collect', 'POST', JSON.stringify({ simulation: true })); renderAudit(); });
  renderAudit();

  window.addEventListener('pagehide', () => {
    clearTimeout(recordingTimer);
    if (mediaRecorder?.state === 'recording') mediaRecorder.stop();
    recordingStream?.getTracks().forEach((track) => track.stop());
    firewall.uninstall(window);
    worker?.terminate();
  }, { once: true });

  return { piiEngine, cryptoVault, firewall, getLatestScrubbedText: () => latestScrubbedText, getLatestVaultMap: () => ({ ...latestVaultMap }) };
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => initLocalVaultApp(), { once: true });
  else initLocalVaultApp();
}
