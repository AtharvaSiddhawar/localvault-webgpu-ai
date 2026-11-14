
/**
 * LocalVault AI v2.0 — Dedicated Model Inference Worker
 *
 * Supports:
 * - Text generation with Transformers.js
 * - Speech recognition with Whisper
 * - WebGPU with WASM fallback
 * - Model caching within the worker
 * - Input validation and cancellation
 * - A worker-scoped fetch request guard
 *
 * Security note:
 * The fetch guard is defense-in-depth, not a complete network firewall.
 * It does not control browser-managed redirects, module imports,
 * or every possible browser networking mechanism.
 */

const CDN_TRANSFORMERS_URL =
  'https://cdn.jsdelivr.net/npm/@huggingface/transformers@3.3.3/+esm';

const ALLOWED_EXTERNAL_HOSTS = new Set([
  'huggingface.co',
  'cdn-lfs.huggingface.co',
  'cdn-lfs-us-1.huggingface.co',
  'cdn-lfs-eu-1.huggingface.co',
  'cdn.jsdelivr.net',
  'cas-bridge.xethub.hf.co',
  'transfer.xethub.hf.co'
]);

const SUPPORTED_TEXT_MODELS = new Set([
  'HuggingFaceTB/SmolLM2-135M-Instruct',
  'Qwen/Qwen2.5-0.5B-Instruct'
]);

const SUPPORTED_ASR_MODELS = new Set([
  'onnx-community/whisper-tiny.en'
]);

const MAX_PROMPT_LENGTH = 20000;
const MAX_NEW_TOKENS = 512;
const MAX_AUDIO_SECONDS = 600;
const AUDIO_SAMPLE_RATE = 16000;

let transformersModule = null;

let activeTextPipeline = null;
let activeTextModel = null;

let activeAsrPipeline = null;
let activeAsrModel = null;

let stoppingCriteria = null;
let activeOperation = null;
let operationCounter = 0;

let workerFetchGuardInstalled = false;

/**
 * Safely sends a message to the parent thread.
 */
function sendMessage(message) {
  try {
    self.postMessage(message);
  } catch {
    // Ignore messaging errors during worker shutdown.
  }
}

/**
 * Worker-scoped network request policy.
 *
 * Only permits:
 * - Same-origin HTTP(S) requests.
 * - HTTPS GET/HEAD requests to exact approved hosts.
 * - Local blob/data resources.
 *
 * This guard checks requests passed through fetch(). It is not a
 * replacement for a browser-enforced Content Security Policy.
 */
function inspectWorkerRequest(input, init = {}) {
  const requestUrl =
    typeof input === 'string'
      ? input
      : input && typeof input.url === 'string'
        ? input.url
        : String(input);

  const requestMethod = String(
    init.method ||
    (input && typeof input === 'object' && input.method) ||
    'GET'
  ).trim().toUpperCase();

  if (!['GET', 'HEAD'].includes(requestMethod)) {
    return {
      allowed: false,
      reason: 'Only GET and HEAD requests are permitted.'
    };
  }

  const body = Object.prototype.hasOwnProperty.call(init, 'body')
    ? init.body
    : input && typeof input === 'object'
      ? input.body ?? null
      : null;

  if (body !== null && body !== undefined) {
    return {
      allowed: false,
      reason: 'Requests carrying a body are not permitted.'
    };
  }

  let parsed;

  try {
    parsed = new URL(requestUrl, self.location.href);
  } catch {
    return {
      allowed: false,
      reason: 'The request URL is invalid.'
    };
  }

  if (parsed.username || parsed.password) {
    return {
      allowed: false,
      reason: 'URLs containing embedded credentials are blocked.'
    };
  }

  if (parsed.protocol === 'data:') {
    return { allowed: true, reason: 'Local data resource.' };
  }

  if (parsed.protocol === 'blob:') {
    if (parsed.origin === self.location.origin) {
      return { allowed: true, reason: 'Same-origin blob resource.' };
    }

    return {
      allowed: false,
      reason: 'Cross-origin blob resources are blocked.'
    };
  }

  if (!['https:', 'http:'].includes(parsed.protocol)) {
    return {
      allowed: false,
      reason: 'Unsupported request protocol.'
    };
  }

  if (parsed.origin === self.location.origin) {
    return {
      allowed: true,
      reason: 'Same-origin application resource.'
    };
  }

  if (parsed.protocol !== 'https:') {
    return {
      allowed: false,
      reason: 'External requests must use HTTPS.'
    };
  }

  if (parsed.port && parsed.port !== '443') {
    return {
      allowed: false,
      reason: 'Non-standard external ports are blocked.'
    };
  }

  if (!ALLOWED_EXTERNAL_HOSTS.has(parsed.hostname.toLowerCase())) {
    return {
      allowed: false,
      reason: 'External hostname is not approved.'
    };
  }

  const credentialsMode =
    init.credentials ||
    (input && typeof input === 'object'
      ? input.credentials
      : 'same-origin');

  if (credentialsMode === 'include') {
    return {
      allowed: false,
      reason: 'Credential-bearing cross-origin requests are blocked.'
    };
  }

  return {
    allowed: true,
    reason: 'Approved HTTPS model/library destination.'
  };
}

/**
 * Install the fetch guard before Transformers.js is imported.
 */
function installWorkerFetchGuard() {
  if (workerFetchGuardInstalled) return true;

  if (typeof self.fetch !== 'function') {
    return false;
  }

  const originalFetch = self.fetch.bind(self);

  try {
    self.fetch = function localVaultWorkerFetch(input, init = {}) {
      const verdict = inspectWorkerRequest(input, init || {});

      if (!verdict.allowed) {
        return Promise.reject(
          new TypeError(
            `[LocalVault Worker Guard] ${verdict.reason}`
          )
        );
      }

      return originalFetch(input, init);
    };

    workerFetchGuardInstalled =
      self.fetch !== originalFetch;

    return workerFetchGuardInstalled;
  } catch {
    return false;
  }
}

/**
 * Load Transformers.js only after installing the worker fetch guard.
 */
async function loadTransformers() {
  if (transformersModule) return transformersModule;

  if (!installWorkerFetchGuard()) {
    throw new Error(
      'Worker network guard could not be installed. ' +
      'Model loading was stopped.'
    );
  }

  try {
    const packageName = '@huggingface/transformers';

    transformersModule = await import(
      /* @vite-ignore */ packageName
    );
  } catch {
    transformersModule = await import(
      /* @vite-ignore */ CDN_TRANSFORMERS_URL
    );
  }

  if (
    !transformersModule ||
    typeof transformersModule.pipeline !== 'function'
  ) {
    transformersModule = null;

    throw new Error(
      'Transformers.js could not be initialized.'
    );
  }

  if (transformersModule.env) {
    transformersModule.env.allowLocalModels = false;
    transformersModule.env.useBrowserCache = true;
    transformersModule.env.allowRemoteModels = true;
  }

  return transformersModule;
}

/**
 * Select WebGPU when an adapter is available.
 * Otherwise use WASM.
 */
async function detectDevice() {
  if (
    typeof navigator !== 'undefined' &&
    navigator.gpu &&
    typeof navigator.gpu.requestAdapter === 'function'
  ) {
    try {
      const adapter = await navigator.gpu.requestAdapter();

      if (adapter) return 'webgpu';
    } catch {
      // Fall back to WASM.
    }
  }

  return 'wasm';
}

/**
 * Reject unsupported model identifiers.
 */
function validateModel(model, supportedModels, label) {
  if (
    typeof model !== 'string' ||
    !supportedModels.has(model)
  ) {
    throw new Error(
      `Unsupported ${label} model. Choose a supported LocalVault model.`
    );
  }

  return model;
}

/**
 * Validate and normalize generation input.
 */
function validateGenerationPayload(payload) {
  if (!payload || typeof payload !== 'object') {
    throw new Error('Generation payload is missing.');
  }

  const prompt = payload.prompt;

  if (typeof prompt !== 'string' || !prompt.trim()) {
    throw new Error('Enter some sanitized text before generation.');
  }

  if (prompt.length > MAX_PROMPT_LENGTH) {
    throw new Error(
      `Prompt is too long. Maximum length is ${MAX_PROMPT_LENGTH} characters.`
    );
  }

  const model = validateModel(
    payload.model || 'HuggingFaceTB/SmolLM2-135M-Instruct',
    SUPPORTED_TEXT_MODELS,
    'text-generation'
  );

  const requestedTokens = Number(payload.maxNewTokens ?? 192);

  if (
    !Number.isFinite(requestedTokens) ||
    !Number.isInteger(requestedTokens) ||
    requestedTokens < 1
  ) {
    throw new Error('maxNewTokens must be a positive integer.');
  }

  return {
    prompt,
    model,
    maxNewTokens: Math.min(requestedTokens, MAX_NEW_TOKENS)
  };
}

/**
 * Validate audio data before passing it to Whisper.
 */
function validateAudioPayload(payload) {
  if (!payload || typeof payload !== 'object') {
    throw new Error('Audio payload is missing.');
  }

  const audio = payload.audio;

  if (!(audio instanceof Float32Array)) {
    throw new Error(
      'Audio must be supplied as a Float32Array.'
    );
  }

  const maximumSamples =
    AUDIO_SAMPLE_RATE * MAX_AUDIO_SECONDS;

  if (audio.length === 0 || audio.length > maximumSamples) {
    throw new Error(
      `Audio must be between 1 sample and ${MAX_AUDIO_SECONDS} minutes.`
    );
  }

  for (let i = 0; i < audio.length; i++) {
    const sample = audio[i];

    if (!Number.isFinite(sample) || Math.abs(sample) > 1.5) {
      throw new Error(
        'Audio contains invalid or out-of-range samples.'
      );
    }
  }

  const model = validateModel(
    payload.model || 'onnx-community/whisper-tiny.en',
    SUPPORTED_ASR_MODELS,
    'speech-recognition'
  );

  return { audio, model };
}

/**
 * Load or reuse the text-generation pipeline.
 */
async function getTextPipeline(model, device) {
  if (activeTextPipeline && activeTextModel === model) {
    return activeTextPipeline;
  }

  const { pipeline } = await loadTransformers();

  sendMessage({
    type: 'status',
    status: 'loading',
    message: `Initializing ${model} on ${device.toUpperCase()}...`
  });

  const pipelineOptions = {
    device,
    dtype: device === 'webgpu' ? 'q4f16' : 'q8'
  };

  const loadedPipeline = await pipeline(
    'text-generation',
    model,
    pipelineOptions
  );

  if (typeof loadedPipeline !== 'function') {
    throw new Error('Text-generation pipeline initialization failed.');
  }

  activeTextPipeline = loadedPipeline;
  activeTextModel = model;

  return activeTextPipeline;
}

/**
 * Load or reuse the speech-recognition pipeline.
 */
async function getAsrPipeline(model, device) {
  if (activeAsrPipeline && activeAsrModel === model) {
    return activeAsrPipeline;
  }

  const { pipeline } = await loadTransformers();

  sendMessage({
    type: 'status',
    status: 'loading',
    message: `Loading Whisper ASR on ${device.toUpperCase()}...`
  });

  const loadedPipeline = await pipeline(
    'automatic-speech-recognition',
    model,
    { device }
  );

  if (typeof loadedPipeline !== 'function') {
    throw new Error('Speech-recognition pipeline initialization failed.');
  }

  activeAsrPipeline = loadedPipeline;
  activeAsrModel = model;

  return activeAsrPipeline;
}

/**
 * Initialize an interruptible generation criterion.
 */
function getStoppingCriteria() {
  if (stoppingCriteria) {
    if (typeof stoppingCriteria.reset === 'function') {
      stoppingCriteria.reset();
    }

    return stoppingCriteria;
  }

  const Constructor =
    transformersModule?.InterruptableStoppingCriteria;

  if (typeof Constructor === 'function') {
    stoppingCriteria = new Constructor();
  }

  return stoppingCriteria;
}

/**
 * Run text generation.
 */
async function handleGenerateText(payload, operation) {
  const input = validateGenerationPayload(payload);

  const {
    prompt,
    model,
    maxNewTokens
  } = input;

  const { pipeline } = await loadTransformers();

  if (operation.cancelled) return;

  const device = await detectDevice();

  if (operation.cancelled) return;

  const textPipeline = await getTextPipeline(model, device);

  if (operation.cancelled) return;

  const criteria = getStoppingCriteria();

  const output = await textPipeline(prompt, {
    max_new_tokens: maxNewTokens,
    do_sample: false,
    stopping_criteria: criteria ? [criteria] : undefined
  });

  if (operation.cancelled) return;

  const generatedText =
    Array.isArray(output) && output[0]?.generated_text != null
      ? String(output[0].generated_text)
      : String(output ?? '');

  sendMessage({
    type: 'generation-complete',
    text: generatedText,
    device,
    model,
    operationId: operation.id
  });
}

/**
 * Run speech recognition.
 */
async function handleTranscribeAudio(payload, operation) {
  const { audio, model } = validateAudioPayload(payload);

  await loadTransformers();

  if (operation.cancelled) return;

  const device = await detectDevice();

  if (operation.cancelled) return;

  const asrPipeline = await getAsrPipeline(model, device);

  if (operation.cancelled) return;

  const result = await asrPipeline(audio);

  if (operation.cancelled) return;

  sendMessage({
    type: 'transcription-complete',
    text: String(result?.text || ''),
    device,
    model,
    operationId: operation.id
  });
}

/**
 * Run one task at a time.
 */
async function runOperation(type, payload, handler) {
  if (activeOperation) {
    sendMessage({
      type: 'error',
      error: 'The worker is already processing another task.'
    });

    return;
  }

  const operation = {
    id: ++operationCounter,
    type,
    cancelled: false
  };

  activeOperation = operation;

  try {
    await handler(payload, operation);

    if (operation.cancelled) {
      sendMessage({
        type: 'aborted',
        message: 'Generation interrupted by user.',
        operationId: operation.id
      });
    }
  } catch (error) {
    if (operation.cancelled) {
      sendMessage({
        type: 'aborted',
        message: 'Generation interrupted by user.',
        operationId: operation.id
      });
    } else {
      sendMessage({
        type: 'error',
        error: error?.message || String(error),
        operationId: operation.id
      });
    }
  } finally {
    if (activeOperation === operation) {
      activeOperation = null;
    }
  }
}

/**
 * Handle worker messages.
 */
if (
  typeof self !== 'undefined' &&
  typeof self.addEventListener === 'function'
) {
  self.addEventListener('message', async event => {
    const data = event.data || {};
    const { type, payload } = data;

    if (type === 'abort') {
      if (
        activeOperation &&
        activeOperation.type === 'generate' &&
        !activeOperation.cancelled
      ) {
        activeOperation.cancelled = true;

        if (
          stoppingCriteria &&
          typeof stoppingCriteria.interrupt === 'function'
        ) {
          stoppingCriteria.interrupt();
        }
      }

      return;
    }

    if (type === 'ping') {
      try {
        const device = await detectDevice();

        sendMessage({
          type: 'pong',
          device,
          networkGuard: workerFetchGuardInstalled
        });
      } catch (error) {
        sendMessage({
          type: 'error',
          error: error?.message || String(error)
        });
      }

      return;
    }

    if (type === 'generate') {
      void runOperation(
        'generate',
        payload,
        handleGenerateText
      );

      return;
    }

    if (type === 'transcribe') {
      void runOperation(
        'transcribe',
        payload,
        handleTranscribeAudio
      );
    }
  });
}
