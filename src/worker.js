/**
 * LocalVault AI v2.0 — Dedicated WebGPU / WASM Model Inference Worker (src/worker.js)
 * Handles asynchronous in-browser model pipelines via @huggingface/transformers (^3.3.3):
 * - Whisper ASR (onnx-community/whisper-tiny.en)
 * - SmolLM2 / Qwen2.5 SLMs (HuggingFaceTB/SmolLM2-135M-Instruct, Qwen/Qwen2.5-0.5B-Instruct)
 * - Contextual Named Entity Recognition (NER)
 * Supports instant mid-stream cancellation via InterruptableStoppingCriteria.
 */

const CDN_TRANSFORMERS_URL =
  'https://cdn.jsdelivr.net/npm/@huggingface/transformers@3.3.3/+esm';

let transformersModule = null;
let activeTextPipeline = null;
let activeAsrPipeline = null;
let stoppingCriteria = null;

async function loadTransformers() {
  if (transformersModule) return transformersModule;
  try {
    const pkgName = '@huggingface/transformers';
    transformersModule = await import(/* @vite-ignore */ pkgName);
  } catch {
    transformersModule = await import(/* @vite-ignore */ CDN_TRANSFORMERS_URL);
  }
  if (transformersModule?.env) {
    transformersModule.env.allowLocalModels = false;
    transformersModule.env.useBrowserCache = true;
  }
  return transformersModule;
}

async function detectDevice() {
  if (typeof navigator !== 'undefined' && 'gpu' in navigator) {
    try {
      const adapter = await navigator.gpu.requestAdapter();
      if (adapter) return 'webgpu';
    } catch {
      // Fallback to WASM
    }
  }
  return 'wasm';
}

async function handleGenerateText(payload) {
  const {
    prompt,
    model = 'HuggingFaceTB/SmolLM2-135M-Instruct',
    maxNewTokens = 192
  } = payload || {};

  const { pipeline, InterruptableStoppingCriteria } = await loadTransformers();
  if (!stoppingCriteria && InterruptableStoppingCriteria) {
    stoppingCriteria = new InterruptableStoppingCriteria();
  } else if (stoppingCriteria) {
    stoppingCriteria.reset();
  }

  const device = await detectDevice();
  if (!activeTextPipeline || activeTextPipeline.__modelId !== model) {
    self.postMessage({
      type: 'status',
      status: 'loading',
      message: `Initializing ${model} on ${device.toUpperCase()}...`
    });
    activeTextPipeline = await pipeline('text-generation', model, {
      device,
      dtype: device === 'webgpu' ? 'q4f16' : 'q8'
    });
    activeTextPipeline.__modelId = model;
  }

  const output = await activeTextPipeline(prompt, {
    max_new_tokens: maxNewTokens,
    do_sample: false,
    stopping_criteria: stoppingCriteria ? [stoppingCriteria] : undefined
  });

  const generatedText =
    Array.isArray(output) && output[0]?.generated_text
      ? output[0].generated_text
      : String(output || '');

  self.postMessage({
    type: 'generation-complete',
    text: generatedText,
    device,
    model
  });
}

async function handleTranscribeAudio(payload) {
  const {
    audio,
    model = 'onnx-community/whisper-tiny.en'
  } = payload || {};

  const { pipeline } = await loadTransformers();
  const device = await detectDevice();

  if (!activeAsrPipeline || activeAsrPipeline.__modelId !== model) {
    self.postMessage({
      type: 'status',
      status: 'loading',
      message: `Loading Whisper ASR (${model}) on ${device.toUpperCase()}...`
    });
    activeAsrPipeline = await pipeline('automatic-speech-recognition', model, {
      device
    });
    activeAsrPipeline.__modelId = model;
  }

  const result = await activeAsrPipeline(audio);
  self.postMessage({
    type: 'transcription-complete',
    text: result?.text || '',
    device,
    model
  });
}

if (typeof self !== 'undefined' && typeof self.addEventListener === 'function') {
  self.addEventListener('message', async (event) => {
    const { type, payload } = event.data || {};
    try {
      if (type === 'abort') {
        if (stoppingCriteria && typeof stoppingCriteria.interrupt === 'function') {
          stoppingCriteria.interrupt();
        }
        self.postMessage({ type: 'aborted', message: 'Generation interrupted by user.' });
        return;
      }

      if (type === 'ping') {
        const device = await detectDevice();
        self.postMessage({ type: 'pong', device });
        return;
      }

      if (type === 'generate') {
        await handleGenerateText(payload);
        return;
      }

      if (type === 'transcribe') {
        await handleTranscribeAudio(payload);
        return;
      }
    } catch (error) {
      self.postMessage({
        type: 'error',
        error: error?.message || String(error)
      });
    }
  });
}
