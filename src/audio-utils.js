/**
 * LocalVault AI v2.0 — Client-Side 16kHz Audio Engine & Pure-JS WAV Synthesizer (src/audio-utils.js)
 * - Pure-JS 16kHz mono PCM WAV synthesizer for deterministic testing without a physical microphone
 * - Float32Array to 16-bit PCM WAV binary encoder & Blob exporter
 * - OfflineAudioContext 16kHz mono resampler & WebRTC microphone recorder helper
 */

export const WHISPER_SAMPLE_RATE = 16000;

/**
 * Synthesize a deterministic 16kHz mono Float32Array sine/harmonic test waveform in pure JS.
 * @param {object} [options]
 * @param {number} [options.durationSeconds=1.5]
 * @param {number} [options.sampleRate=16000]
 * @param {number} [options.frequencyHz=440]
 * @returns {Float32Array}
 */
export function synthesizeTestAudioSamples(options = {}) {
  const durationSeconds = Number(options.durationSeconds ?? 1.5);
  const sampleRate = Number(options.sampleRate ?? WHISPER_SAMPLE_RATE);
  const frequencyHz = Number(options.frequencyHz ?? 440);
  const totalSamples = Math.max(1, Math.floor(durationSeconds * sampleRate));
  const samples = new Float32Array(totalSamples);

  for (let i = 0; i < totalSamples; i++) {
    const t = i / sampleRate;
    // Envelope + fundamental + second harmonic simulating speech cadence
    const envelope = Math.sin(Math.PI * (i / totalSamples));
    const fundamental = 0.6 * Math.sin(2 * Math.PI * frequencyHz * t);
    const harmonic = 0.25 * Math.sin(2 * Math.PI * (frequencyHz * 1.5) * t);
    samples[i] = Number((envelope * (fundamental + harmonic)).toFixed(6));
  }
  return samples;
}

/**
 * Encode a mono Float32Array (-1.0 to 1.0) into a standard 44-byte RIFF/WAVE 16-bit PCM Uint8Array.
 * Works identically in Node.js and browser environments.
 * @param {Float32Array} samples
 * @param {number} [sampleRate=16000]
 * @returns {Uint8Array}
 */
export function encodeWavBytes(samples, sampleRate = WHISPER_SAMPLE_RATE) {
  if (!(samples instanceof Float32Array)) {
    throw new Error('encodeWavBytes expects a Float32Array of audio samples.');
  }
  const numChannels = 1;
  const bitsPerSample = 16;
  const bytesPerSample = bitsPerSample / 8;
  const dataByteLength = samples.length * bytesPerSample;
  const buffer = new ArrayBuffer(44 + dataByteLength);
  const view = new DataView(buffer);

  const writeAscii = (offset, text) => {
    for (let i = 0; i < text.length; i++) {
      view.setUint8(offset + i, text.charCodeAt(i));
    }
  };

  // RIFF identifier
  writeAscii(0, 'RIFF');
  view.setUint32(4, 36 + dataByteLength, true);
  writeAscii(8, 'WAVE');

  // fmt subchunk
  writeAscii(12, 'fmt ');
  view.setUint32(16, 16, true); // PCM chunk size
  view.setUint16(20, 1, true); // AudioFormat = 1 (PCM)
  view.setUint16(22, numChannels, true);
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, sampleRate * numChannels * bytesPerSample, true);
  view.setUint16(32, numChannels * bytesPerSample, true);
  view.setUint16(34, bitsPerSample, true);

  // data subchunk
  writeAscii(36, 'data');
  view.setUint32(40, dataByteLength, true);

  let offset = 44;
  for (let i = 0; i < samples.length; i++) {
    const clamped = Math.max(-1, Math.min(1, samples[i]));
    const int16 = clamped < 0 ? clamped * 0x8000 : clamped * 0x7fff;
    view.setInt16(offset, int16, true);
    offset += 2;
  }

  return new Uint8Array(buffer);
}

/**
 * Synthesize a complete 16kHz mono WAV file in pure JS (returns both raw bytes and Float32Array samples).
 * @param {object} [options]
 * @returns {{ samples: Float32Array, wavBytes: Uint8Array, sampleRate: number, durationSeconds: number }}
 */
export function synthesizeTestWav(options = {}) {
  const sampleRate = Number(options.sampleRate ?? WHISPER_SAMPLE_RATE);
  const durationSeconds = Number(options.durationSeconds ?? 1.5);
  const samples = synthesizeTestAudioSamples({ ...options, sampleRate, durationSeconds });
  const wavBytes = encodeWavBytes(samples, sampleRate);
  return {
    samples,
    wavBytes,
    sampleRate,
    durationSeconds
  };
}

/**
 * Create a browser Blob (audio/wav) from Float32Array samples.
 * @param {Float32Array} samples
 * @param {number} [sampleRate=16000]
 * @returns {Blob}
 */
export function exportWavBlob(samples, sampleRate = WHISPER_SAMPLE_RATE) {
  const wavBytes = encodeWavBytes(samples, sampleRate);
  return new Blob([wavBytes], { type: 'audio/wav' });
}

/**
 * Resample an AudioBuffer or Float32Array to 16kHz mono using OfflineAudioContext in the browser,
 * with a deterministic linear interpolation fallback in Node/non-WebAudio runtimes.
 * @param {Float32Array} inputSamples
 * @param {number} inputSampleRate
 * @param {number} [targetSampleRate=16000]
 * @returns {Promise<Float32Array>}
 */
export async function resampleTo16kHzMono(
  inputSamples,
  inputSampleRate,
  targetSampleRate = WHISPER_SAMPLE_RATE
) {
  if (inputSampleRate === targetSampleRate) {
    return new Float32Array(inputSamples);
  }
  const targetLength = Math.max(
    1,
    Math.round((inputSamples.length * targetSampleRate) / inputSampleRate)
  );

  if (typeof globalThis.OfflineAudioContext === 'function') {
    const offlineCtx = new globalThis.OfflineAudioContext(
      1,
      targetLength,
      targetSampleRate
    );
    const buffer = offlineCtx.createBuffer(1, inputSamples.length, inputSampleRate);
    buffer.copyToChannel(inputSamples, 0);
    const source = offlineCtx.createBufferSource();
    source.buffer = buffer;
    source.connect(offlineCtx.destination);
    source.start(0);
    const rendered = await offlineCtx.startRendering();
    return new Float32Array(rendered.getChannelData(0));
  }

  // Deterministic linear interpolation fallback for headless/Node environments
  const output = new Float32Array(targetLength);
  const ratio = (inputSamples.length - 1) / Math.max(1, targetLength - 1);
  for (let i = 0; i < targetLength; i++) {
    const pos = i * ratio;
    const idx = Math.floor(pos);
    const frac = pos - idx;
    const next = Math.min(inputSamples.length - 1, idx + 1);
    output[i] = inputSamples[idx] * (1 - frac) + inputSamples[next] * frac;
  }
  return output;
}

