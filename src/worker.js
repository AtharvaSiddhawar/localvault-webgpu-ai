/** Dedicated inference worker. Model weights may be downloaded from Hugging Face. */
const ALLOWED_HOSTS = new Set([
  'huggingface.co', 'cdn-lfs.huggingface.co', 'cdn-lfs-us-1.huggingface.co',
  'cdn-lfs-eu-1.huggingface.co', 'cdn.jsdelivr.net', 'cas-bridge.xethub.hf.co',
  'transfer.xethub.hf.co', 'us.aws.cdn.hf.co'
]);
const TEXT_MODELS = new Set(['HuggingFaceTB/SmolLM2-135M-Instruct', 'Qwen/Qwen2.5-0.5B-Instruct']);
const ASR_MODELS = new Set(['onnx-community/whisper-tiny.en']);
const MAX_PROMPT = 20000;
const MAX_TOKENS = 512;
const MAX_AUDIO_SAMPLES = 16000 * 600;
let transformers = null;
let textPipeline = null;
let textModelName = null;
let textPipelineDevice = null;
let asrPipeline = null;
let asrModelName = null;
let asrPipelineDevice = null;
let activeOperation = null;
let operationId = 0;
let airGapLockdown = false;
let stoppingCriteria = null;
let guardInstalled = false;

function post(message) { try { self.postMessage(message); } catch { /* worker may be closing */ } }
function validateRequest(input, init = {}) {
  let url;
  try { const raw = typeof input === 'string' || input instanceof URL ? String(input) : input?.url; url = new URL(raw, self.location.href); }
  catch { return { allowed: false, reason: 'Invalid request URL.' }; }
  const method = String(init.method || input?.method || 'GET').toUpperCase();
  const body = Object.hasOwn(init, 'body') ? init.body : input?.body ?? null;
  if (!['GET', 'HEAD'].includes(method)) return { allowed: false, reason: 'Only GET and HEAD requests are permitted.' };
  if (body !== null && body !== undefined) return { allowed: false, reason: 'Requests with bodies are blocked.' };
  if (url.username || url.password) return { allowed: false, reason: 'URLs containing credentials are blocked.' };
  if (url.protocol === 'blob:' || url.protocol === 'data:') return { allowed: url.protocol !== 'blob:' || url.origin === self.location.origin, reason: 'Local resource.' };
  if (url.origin === self.location.origin) return { allowed: true, reason: 'Same-origin resource.' };
  if (airGapLockdown) return { allowed: false, reason: 'Strict air-gap lockdown is enabled in the inference worker.' };
  if (url.protocol !== 'https:' || (url.port && url.port !== '443')) return { allowed: false, reason: 'External model requests must use standard HTTPS.' };
  if (!ALLOWED_HOSTS.has(url.hostname.toLowerCase())) return { allowed: false, reason: 'External hostname is not approved.' };
  const credentials = init.credentials || input?.credentials || 'same-origin';
  if (credentials === 'include') return { allowed: false, reason: 'Cross-origin credentials are blocked.' };
  return { allowed: true, reason: 'Approved model asset host.' };
}
function installFetchGuard() {
  if (guardInstalled) return true;
  if (typeof self.fetch !== 'function') return false;
  const original = self.fetch.bind(self);
  try {
    self.fetch = (input, init = {}) => {
      const result = validateRequest(input, init || {});
      if (!result.allowed) return Promise.reject(new TypeError(`[LocalVault Worker Guard] ${result.reason}`));
      return original(input, init);
    };
    guardInstalled = true;
    return true;
  } catch { return false; }
}
async function loadTransformers() {
  if (transformers) return transformers;
  if (!installFetchGuard()) throw new Error('The worker request guard could not be installed. Model loading was stopped.');
  transformers = await import('@huggingface/transformers');
  transformers.env.allowLocalModels = false;
  transformers.env.allowRemoteModels = true;
  transformers.env.useBrowserCache = true;
  return transformers;
}
async function detectDevice() {
  if (navigator.gpu?.requestAdapter) { try { if (await navigator.gpu.requestAdapter()) return 'webgpu'; } catch { /* WASM fallback */ } }
  return 'wasm';
}
function assertModel(model, allowed, type) { if (typeof model !== 'string' || !allowed.has(model)) throw new Error(`Unsupported ${type} model.`); return model; }
function validateText(payload) {
  if (!payload || typeof payload.prompt !== 'string' || !payload.prompt.trim()) throw new Error('Enter sanitized text before local inference.');
  if (payload.prompt.length > MAX_PROMPT) throw new Error(`Prompt exceeds ${MAX_PROMPT} characters.`);
  const model = assertModel(payload.model || 'HuggingFaceTB/SmolLM2-135M-Instruct', TEXT_MODELS, 'text-generation');
  const count = Number(payload.maxNewTokens ?? 192);
  if (!Number.isSafeInteger(count) || count < 1) throw new Error('maxNewTokens must be a positive integer.');
  return { prompt: payload.prompt, model, maxNewTokens: Math.min(count, MAX_TOKENS) };
}
function validateAudio(payload) {
  if (!(payload?.audio instanceof Float32Array)) throw new Error('Audio must be supplied as a Float32Array.');
  if (payload.audio.length < 1 || payload.audio.length > MAX_AUDIO_SAMPLES) throw new Error('Audio must be between 1 sample and 10 minutes at 16 kHz.');
  for (const sample of payload.audio) if (!Number.isFinite(sample) || Math.abs(sample) > 1.5) throw new Error('Audio contains invalid or out-of-range samples.');
  return { audio: payload.audio, model: assertModel(payload.model || 'onnx-community/whisper-tiny.en', ASR_MODELS, 'speech-recognition') };
}
async function createPipeline(task, model, preferredDevice) {
  const lib = await loadTransformers();
  const devices = preferredDevice === 'webgpu' ? ['webgpu', 'wasm'] : ['wasm'];
  let lastError;
  for (const device of devices) {
    try {
      post({ type: 'status', task, status: 'loading', message: `Loading ${model} with ${device.toUpperCase()}…` });
      const dtype = device === 'webgpu' ? 'q4f16' : 'q8';
      const instance = await lib.pipeline(task, model, { device, dtype });
      return { instance, device };
    } catch (error) { lastError = error; }
  }
  throw new Error(`Could not load ${model}: ${lastError?.message || 'unknown model error'}`);
}
async function getTextPipeline(model, preferredDevice) {
  if (textPipeline && textModelName === model) return { instance: textPipeline, device: textPipelineDevice };
  const result = await createPipeline('text-generation', model, preferredDevice);
  textPipeline = result.instance; textModelName = model; textPipelineDevice = result.device; return result;
}
async function getAsrPipeline(model, preferredDevice) {
  if (asrPipeline && asrModelName === model) return { instance: asrPipeline, device: asrPipelineDevice };
  const result = await createPipeline('automatic-speech-recognition', model, preferredDevice);
  asrPipeline = result.instance; asrModelName = model; asrPipelineDevice = result.device; return result;
}
async function run(type, payload, handler) {
  if (activeOperation) { post({ type: 'error', error: 'The inference worker is already processing another task.' }); return; }
  const operation = { id: ++operationId, type, cancelled: false };
  activeOperation = operation;
  try {
    await handler(payload, operation);
    if (operation.cancelled) post({ type: 'aborted', message: 'The task was cancelled.', operationId: operation.id });
  } catch (error) {
    if (operation.cancelled) post({ type: 'aborted', message: 'The task was cancelled.', operationId: operation.id });
    else post({ type: 'error', error: error?.message || String(error), operationId: operation.id });
  } finally { if (activeOperation === operation) activeOperation = null; }
}
async function generate(payload, operation) {
  const input = validateText(payload);
  const preferred = await detectDevice(); if (operation.cancelled) return;
  const { instance, device } = await getTextPipeline(input.model, preferred); if (operation.cancelled) return;
  const Constructor = transformers?.InterruptableStoppingCriteria;
  if (typeof Constructor === 'function') { if (!stoppingCriteria) stoppingCriteria = new Constructor(); else stoppingCriteria.reset?.(); }
  const output = await instance(input.prompt, { max_new_tokens: input.maxNewTokens, do_sample: false, return_full_text: false, stopping_criteria: stoppingCriteria ? [stoppingCriteria] : undefined });
  if (operation.cancelled) return;
  const text = Array.isArray(output) ? String(output[0]?.generated_text ?? '') : String(output ?? '');
  post({ type: 'generation-complete', text, device, model: input.model, operationId: operation.id });
}
async function transcribe(payload, operation) {
  const input = validateAudio(payload);
  const preferred = await detectDevice(); if (operation.cancelled) return;
  const { instance, device } = await getAsrPipeline(input.model, preferred); if (operation.cancelled) return;
  const result = await instance(input.audio);
  if (operation.cancelled) return;
  post({ type: 'transcription-complete', text: String(result?.text || ''), device, model: input.model, operationId: operation.id });
}

self.addEventListener('message', (event) => {
  const data = event.data || {};
  if (data.type === 'airgap') { airGapLockdown = Boolean(data.enabled); post({ type: 'status', message: `Worker air-gap lockdown ${airGapLockdown ? 'enabled' : 'disabled'}.` }); return; }
  if (data.type === 'ping') { detectDevice().then((device) => post({ type: 'pong', device, networkGuard: guardInstalled, airGapLockdown })).catch((error) => post({ type: 'error', error: error.message })); return; }
  if (data.type === 'abort') {
    if (activeOperation?.type === 'generate') { activeOperation.cancelled = true; stoppingCriteria?.interrupt?.(); }
    return;
  }
  if (data.type === 'generate') { void run('generate', data.payload, generate); return; }
  if (data.type === 'transcribe') void run('transcribe', data.payload, transcribe);
});
