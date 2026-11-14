
/**
 * LocalVault AI v2.0 — Client-Side Audio Utilities
 *
 * Features:
 * - Deterministic synthetic audio generation
 * - Mono 16-bit PCM WAV encoding
 * - Browser WAV Blob export
 * - Audio resampling to 16kHz mono
 *
 * Note:
 * These utilities do not themselves record microphone audio.
 */

export const WHISPER_SAMPLE_RATE = 16000;

const MIN_SAMPLE_RATE = 8000;
const MAX_SAMPLE_RATE = 192000;
const MAX_AUDIO_SAMPLES = 5000000;
const MAX_DURATION_SECONDS = 600;

/**
 * Validate a sample rate.
 */
function validateSampleRate(sampleRate) {
  if (
    !Number.isInteger(sampleRate) ||
    sampleRate < MIN_SAMPLE_RATE ||
    sampleRate > MAX_SAMPLE_RATE
  ) {
    throw new RangeError(
      `Sample rate must be an integer between ${MIN_SAMPLE_RATE} and ${MAX_SAMPLE_RATE}.`
    );
  }

  return sampleRate;
}

/**
 * Validate audio duration and calculate sample count.
 */
function getSampleCount(durationSeconds, sampleRate) {
  if (
    !Number.isFinite(durationSeconds) ||
    durationSeconds <= 0 ||
    durationSeconds > MAX_DURATION_SECONDS
  ) {
    throw new RangeError(
      `Audio duration must be greater than zero and no more than ${MAX_DURATION_SECONDS} seconds.`
    );
  }

  const count = Math.floor(durationSeconds * sampleRate);

  if (
    !Number.isSafeInteger(count) ||
    count < 1 ||
    count > MAX_AUDIO_SAMPLES
  ) {
    throw new RangeError(
      'Requested audio exceeds the supported sample limit.'
    );
  }

  return count;
}

/**
 * Generate a deterministic synthetic mono waveform.
 *
 * The result is a test tone, not recorded speech.
 *
 * @param {object} [options]
 * @param {number} [options.durationSeconds=1.5]
 * @param {number} [options.sampleRate=16000]
 * @param {number} [options.frequencyHz=440]
 * @returns {Float32Array}
 */
export function synthesizeTestAudioSamples(options = {}) {
  const sampleRate = validateSampleRate(
    Number(options.sampleRate ?? WHISPER_SAMPLE_RATE)
  );

  const durationSeconds = Number(
    options.durationSeconds ?? 1.5
  );

  const frequencyHz = Number(
    options.frequencyHz ?? 440
  );

  const totalSamples = getSampleCount(
    durationSeconds,
    sampleRate
  );

  if (
    !Number.isFinite(frequencyHz) ||
    frequencyHz <= 0 ||
    frequencyHz >= sampleRate / 2
  ) {
    throw new RangeError(
      'Frequency must be positive and below the Nyquist frequency.'
    );
  }

  const samples = new Float32Array(totalSamples);

  for (let i = 0; i < totalSamples; i++) {
    const time = i / sampleRate;

    const envelope = Math.sin(
      Math.PI * (i / totalSamples)
    );

    const fundamental =
      0.6 * Math.sin(2 * Math.PI * frequencyHz * time);

    const harmonic =
      0.25 * Math.sin(2 * Math.PI * frequencyHz * 1.5 * time);

    samples[i] = envelope * (fundamental + harmonic);
  }

  return samples;
}

/**
 * Encode mono Float32 audio into a standard 16-bit PCM WAV file.
 *
 * @param {Float32Array} samples
 * @param {number} [sampleRate=16000]
 * @returns {Uint8Array}
 */
export function encodeWavBytes(
  samples,
  sampleRate = WHISPER_SAMPLE_RATE
) {
  if (!(samples instanceof Float32Array)) {
    throw new TypeError(
      'encodeWavBytes expects a Float32Array.'
    );
  }

  validateSampleRate(sampleRate);

  const numChannels = 1;
  const bitsPerSample = 16;
  const bytesPerSample = bitsPerSample / 8;

  const dataByteLength = samples.length * bytesPerSample;

  if (
    !Number.isSafeInteger(dataByteLength) ||
    dataByteLength > 0xffffffff - 36
  ) {
    throw new RangeError(
      'Audio is too large for a standard WAV file.'
    );
  }

  const buffer = new ArrayBuffer(44 + dataByteLength);
  const view = new DataView(buffer);

  function writeAscii(offset, value) {
    for (let i = 0; i < value.length; i++) {
      view.setUint8(offset + i, value.charCodeAt(i));
    }
  }

  // RIFF header.
  writeAscii(0, 'RIFF');
  view.setUint32(4, 36 + dataByteLength, true);
  writeAscii(8, 'WAVE');

  // Format chunk.
  writeAscii(12, 'fmt ');
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true);
  view.setUint16(22, numChannels, true);
  view.setUint32(24, sampleRate, true);
  view.setUint32(
    28,
    sampleRate * numChannels * bytesPerSample,
    true
  );
  view.setUint16(32, numChannels * bytesPerSample, true);
  view.setUint16(34, bitsPerSample, true);

  // Data chunk.
  writeAscii(36, 'data');
  view.setUint32(40, dataByteLength, true);

  let offset = 44;

  for (let i = 0; i < samples.length; i++) {
    const sample = Number.isFinite(samples[i])
      ? Math.max(-1, Math.min(1, samples[i]))
      : 0;

    const pcmValue = sample < 0
      ? Math.round(sample * 0x8000)
      : Math.round(sample * 0x7fff);

    view.setInt16(offset, pcmValue, true);
    offset += bytesPerSample;
  }

  return new Uint8Array(buffer);
}

/**
 * Generate a synthetic WAV file and its original samples.
 *
 * @param {object} [options]
 * @returns {{
 *   samples: Float32Array,
 *   wavBytes: Uint8Array,
 *   sampleRate: number,
 *   durationSeconds: number
 * }}
 */
export function synthesizeTestWav(options = {}) {
  const sampleRate = validateSampleRate(
    Number(options.sampleRate ?? WHISPER_SAMPLE_RATE)
  );

  const durationSeconds = Number(
    options.durationSeconds ?? 1.5
  );

  const samples = synthesizeTestAudioSamples({
    ...options,
    sampleRate,
    durationSeconds
  });

  const wavBytes = encodeWavBytes(
    samples,
    sampleRate
  );

  return {
    samples,
    wavBytes,
    sampleRate,
    durationSeconds
  };
}

/**
 * Export Float32 audio as a browser WAV Blob.
 *
 * @param {Float32Array} samples
 * @param {number} [sampleRate=16000]
 * @returns {Blob}
 */
export function exportWavBlob(
  samples,
  sampleRate = WHISPER_SAMPLE_RATE
) {
  if (typeof Blob === 'undefined') {
    throw new Error(
      'Blob export is not supported in this environment.'
    );
  }

  const wavBytes = encodeWavBytes(samples, sampleRate);

  return new Blob(
    [wavBytes],
    { type: 'audio/wav' }
  );
}

/**
 * Resample mono Float32 audio.
 *
 * Uses OfflineAudioContext where available.
 * Uses deterministic linear interpolation as a fallback.
 *
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
  if (!(inputSamples instanceof Float32Array)) {
    throw new TypeError(
      'Input audio must be a Float32Array.'
    );
  }

  validateSampleRate(inputSampleRate);
  validateSampleRate(targetSampleRate);

  if (inputSamples.length === 0) {
    throw new RangeError('Input audio cannot be empty.');
  }

  if (inputSamples.length > MAX_AUDIO_SAMPLES) {
    throw new RangeError('Input audio exceeds the sample limit.');
  }

  for (let i = 0; i < inputSamples.length; i++) {
    if (!Number.isFinite(inputSamples[i])) {
      throw new TypeError(
        'Input audio contains non-finite samples.'
      );
    }
  }

  if (inputSampleRate === targetSampleRate) {
    return new Float32Array(inputSamples);
  }

  const targetLength = Math.max(
    1,
    Math.round(
      inputSamples.length * targetSampleRate / inputSampleRate
    )
  );

  if (targetLength > MAX_AUDIO_SAMPLES) {
    throw new RangeError('Resampled audio exceeds the sample limit.');
  }

  const OfflineContext =
    globalThis.OfflineAudioContext ||
    globalThis.webkitOfflineAudioContext;

  if (typeof OfflineContext === 'function') {
    try {
      const context = new OfflineContext(
        1,
        targetLength,
        targetSampleRate
      );

      const audioBuffer = context.createBuffer(
        1,
        inputSamples.length,
        inputSampleRate
      );

      audioBuffer.getChannelData(0).set(inputSamples);

      const source = context.createBufferSource();
      source.buffer = audioBuffer;
      source.connect(context.destination);
      source.start(0);

      const rendered = await context.startRendering();

      return new Float32Array(
        rendered.getChannelData(0)
      );
    } catch {
      // Use deterministic interpolation if browser resampling fails.
    }
  }

  // Linear interpolation fallback.
  const output = new Float32Array(targetLength);

  const ratio =
    (inputSamples.length - 1) /
    Math.max(1, targetLength - 1);

  for (let i = 0; i < targetLength; i++) {
    const position = i * ratio;
    const index = Math.floor(position);
    const fraction = position - index;

    const nextIndex = Math.min(
      inputSamples.length - 1,
      index + 1
    );

    output[i] =
      inputSamples[index] * (1 - fraction) +
      inputSamples[nextIndex] * fraction;
  }

  return output;
}
