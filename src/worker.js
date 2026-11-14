/**
 * LocalVault AI v2.0 — Dedicated WebGPU / WASM Inference Worker
 */

let transformersModule = null;
let asrPipeline = null;
let asrModelId = null;
let llmPipeline = null;
let llmModelId = null;
let stoppingCriteria = null;
let activeDevice = 'wasm';
let supportsFp16 = false;
let airGapLocked = false;

const CDN_FALLBACK_URL = 'https://cdn.jsdelivr.net/npm/@huggingface/transformers@3.3.3/dist/transformers.min.js';

async function getTransformers() {
  if (transformersModule) return transformersModule;
  try {
    transformersModule = await import('@huggingface/transformers');
  } catch {
    if (airGapLocked) {
      throw new Error('Air-Gap Lockdown is active and @huggingface/transformers is not cached locally.');
    }
    transformersModule = await import(/* @vite-ignore */ CDN_FALLBACK_URL);
  }
  const { env, InterruptableStoppingCriteria } = transformersModule;
  if (env) {
    env.allowLocalModels = false;
    env.useBrowserCache = true;
    env.allowRemoteModels = !airGapLocked;
  }
  if (InterruptableStoppingCriteria && !stoppingCriteria) {
    stoppingCriteria = new InterruptableStoppingCriteria();
  }
  return transformersModule;
}

async function detectHardwareCapabilities() {
  if (typeof navigator !== 'undefined' && 'gpu' in navigator) {
    try {
      const adapter = await navigator.gpu.requestAdapter();
      if (adapter) {
        activeDevice = 'webgpu';
        supportsFp16 = adapter.features.has('shader-f16');
        return {
          device: 'webgpu',
          supportsFp16
        };
      }
    } catch {
      // Fallback to WASM
    }
  }
  activeDevice = 'wasm';
  supportsFp16 = false;
  return {
    device: 'wasm',
    supportsFp16: false
  };
}

function sendProgress(data) {
  self.postMessage({
    type: 'MODEL_PROGRESS',
    payload: data
  });
}

function formatTimestamp(seconds) {
  if (typeof seconds !== 'number' || Number.isNaN(seconds)) return '00:00';
  const mins = Math.floor(seconds / 60);
  const secs = Math.floor(seconds % 60);
  return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

async function ensureAsrPipeline(requestedModelId = 'onnx-community/whisper-tiny.en') {
  if (asrPipeline && asrModelId === requestedModelId) {
    return asrPipeline;
  }

  const { pipeline, env } = await getTransformers();
  if (env) env.allowRemoteModels = !airGapLocked;
  const hw = await detectHardwareCapabilities();

  self.postMessage({
    type: 'STATUS',
    payload: `Initializing Whisper (${requestedModelId}) on ${hw.device.toUpperCase()}...`
  });

  try {
    asrPipeline = await pipeline('automatic-speech-recognition', requestedModelId, {
      device: hw.device,
      dtype: hw.device === 'webgpu'
        ? {
            encoder_model: hw.supportsFp16 ? 'fp16' : 'fp32',
            decoder_model_merged: 'q4'
          }
        : 'q8',
      progress_callback: sendProgress
    });
  } catch {
    activeDevice = 'wasm';
    asrPipeline = await pipeline('automatic-speech-recognition', requestedModelId, {
      device: 'wasm',
      dtype: 'q8',
      progress_callback: sendProgress
    });
  }

  asrModelId = requestedModelId;
  self.postMessage({
    type: 'MODEL_READY',
    payload: { task: 'asr', modelId: requestedModelId, device: activeDevice }
  });

  return asrPipeline;
}

async function ensureLlmPipeline(requestedModelId = 'HuggingFaceTB/SmolLM2-360M-Instruct') {
  if (llmPipeline && llmModelId === requestedModelId) {
    return llmPipeline;
  }

  const { pipeline, env } = await getTransformers();
  if (env) env.allowRemoteModels = !airGapLocked;
  const hw = await detectHardwareCapabilities();

  self.postMessage({
    type: 'STATUS',
    payload: `Initializing SLM (${requestedModelId}) on ${hw.device.toUpperCase()}...`
  });

  const preferredDtype = hw.device === 'webgpu'
    ? (hw.supportsFp16 ? 'q4f16' : 'q4')
    : 'q8';

  try {
    llmPipeline = await pipeline('text-generation', requestedModelId, {
      device: hw.device,
      dtype: preferredDtype,
      progress_callback: sendProgress
    });
  } catch {
    activeDevice = 'wasm';
    llmPipeline = await pipeline('text-generation', requestedModelId, {
      device: 'wasm',
      dtype: 'q8',
      progress_callback: sendProgress
    });
  }

  llmModelId = requestedModelId;
  self.postMessage({
    type: 'MODEL_READY',
    payload: { task: 'llm', modelId: requestedModelId, device: activeDevice }
  });

  return llmPipeline;
}

self.addEventListener('message', async (event) => {
  const { type, payload, requestId } = event.data || {};

  try {
    if (type === 'PING_HARDWARE') {
      const hw = await detectHardwareCapabilities();
      self.postMessage({ type: 'HARDWARE_INFO', payload: hw, requestId });
      return;
    }

    if (type === 'SET_AIRGAP_MODE') {
      airGapLocked = Boolean(payload?.locked);
      if (transformersModule?.env) {
        transformersModule.env.allowRemoteModels = !airGapLocked;
      }
      self.postMessage({
        type: 'STATUS',
        payload: airGapLocked
          ? 'Worker Air-Gap Locked (Offline Cache Only)'
          : 'Worker Air-Gap Unlocked'
      });
      return;
    }

    if (type === 'ABORT_GENERATION') {
      if (stoppingCriteria) {
        stoppingCriteria.interrupt();
      }
      self.postMessage({
        type: 'STATUS',
        payload: 'Generation interrupted by user.'
      });
      return;
    }

    if (type === 'TRANSCRIBE_AUDIO') {
      const { audioData, modelId, includeTimestamps = true } = payload;
      const transcriber = await ensureAsrPipeline(modelId || 'onnx-community/whisper-tiny.en');
      const startTime = performance.now();

      const result = await transcriber(audioData, {
        chunk_length_s: 30,
        stride_length_s: 5,
        return_timestamps: includeTimestamps
      });

      const elapsedMs = Math.round(performance.now() - startTime);
      let formattedText = (result?.text || '').trim();

      if (includeTimestamps && Array.isArray(result?.chunks) && result.chunks.length > 0) {
        formattedText = result.chunks
          .map((c) => {
            const [start, end] = c.timestamp || [0, 0];
            return `[${formatTimestamp(start)} -> ${formatTimestamp(end ?? start)}] ${(c.text || '').trim()}`;
          })
          .join('\n');
      }

      self.postMessage({
        type: 'TRANSCRIBE_RESULT',
        requestId,
        payload: {
          text: formattedText,
          rawText: (result?.text || '').trim(),
          elapsedMs,
          device: activeDevice,
          modelId: asrModelId
        }
      });
      return;
    }

    if (type === 'GENERATE_TEXT') {
      const { messages, modelId, maxNewTokens = 512, temperature = 0.2, taskTag = 'structure' } = payload;
      const { TextStreamer } = await getTransformers();
      const generator = await ensureLlmPipeline(modelId || 'HuggingFaceTB/SmolLM2-360M-Instruct');

      if (stoppingCriteria) {
        stoppingCriteria.reset();
      }

      const startTime = performance.now();
      let streamedText = '';
      let tokenCount = 0;

      const streamer = new TextStreamer(generator.tokenizer, {
        skip_prompt: true,
        skip_special_tokens: true,
        callback_function: (tokenText) => {
          streamedText += tokenText;
          tokenCount += 1;
          const elapsedSec = Math.max(0.05, (performance.now() - startTime) / 1000);
          const tokensPerSec = Number((tokenCount / elapsedSec).toFixed(1));
          self.postMessage({
            type: 'LLM_STREAM_TOKEN',
            requestId,
            payload: {
              tokenText,
              accumulatedText: streamedText,
              tokensPerSec,
              taskTag
            }
          });
        }
      });

      const genConfig = {
        max_new_tokens: maxNewTokens,
        temperature,
        do_sample: temperature > 0,
        streamer
      };
      if (stoppingCriteria) {
        genConfig.stopping_criteria = [stoppingCriteria];
      }

      const output = await generator(messages, genConfig);

      const elapsedMs = Math.round(performance.now() - startTime);
      const tokensPerSec = Number((tokenCount / Math.max(0.1, elapsedMs / 1000)).toFixed(1));
      const finalGenerated =
        streamedText ||
        output?.[0]?.generated_text?.at?.(-1)?.content ||
        '';

      self.postMessage({
        type: 'LLM_COMPLETE',
        requestId,
        payload: {
          text: finalGenerated.trim(),
          elapsedMs,
          tokensPerSec,
          device: activeDevice,
          modelId: llmModelId,
          taskTag
        }
      });
    }
  } catch (error) {
    self.postMessage({
      type: 'ERROR',
      requestId,
      payload: {
        message: error?.message || 'Worker inference error'
      }
    });
  }
});
  
