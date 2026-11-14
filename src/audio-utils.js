/** Browser audio helpers. Whisper inputs are mono Float32 samples at 16 kHz. */
export const WHISPER_SAMPLE_RATE = 16000;
const MIN_RATE = 8000;
const MAX_RATE = 192000;
const MAX_SAMPLES = 30000000;
const MAX_SECONDS = 600;

function validateRate(rate) { if (!Number.isInteger(rate) || rate < MIN_RATE || rate > MAX_RATE) throw new RangeError(`Sample rate must be an integer between ${MIN_RATE} and ${MAX_RATE}.`); return rate; }
function validateSamples(samples) { if (!(samples instanceof Float32Array)) throw new TypeError('Audio samples must be a Float32Array.'); if (!samples.length) throw new RangeError('Audio input cannot be empty.'); if (samples.length > MAX_SAMPLES) throw new RangeError('Audio exceeds the sample limit.'); for (const value of samples) if (!Number.isFinite(value)) throw new TypeError('Audio contains non-finite samples.'); }

export function synthesizeTestAudioSamples(options = {}) {
  const sampleRate = validateRate(Number(options.sampleRate ?? WHISPER_SAMPLE_RATE));
  const durationSeconds = Number(options.durationSeconds ?? 1.5);
  const frequencyHz = Number(options.frequencyHz ?? 440);
  if (!Number.isFinite(durationSeconds) || durationSeconds <= 0 || durationSeconds > MAX_SECONDS) throw new RangeError(`Audio duration must be greater than zero and no more than ${MAX_SECONDS} seconds.`);
  if (!Number.isFinite(frequencyHz) || frequencyHz <= 0 || frequencyHz >= sampleRate / 2) throw new RangeError('Frequency must be positive and below the Nyquist frequency.');
  const count = Math.floor(durationSeconds * sampleRate);
  if (!count || count > MAX_SAMPLES) throw new RangeError('Requested audio exceeds the sample limit.');
  const samples = new Float32Array(count);
  for (let i = 0; i < count; i++) { const t = i / sampleRate; const envelope = Math.sin(Math.PI * i / count); samples[i] = envelope * (0.6 * Math.sin(2 * Math.PI * frequencyHz * t) + 0.2 * Math.sin(4 * Math.PI * frequencyHz * t)); }
  return samples;
}

export function encodeWavBytes(samples, sampleRate = WHISPER_SAMPLE_RATE) {
  if (!(samples instanceof Float32Array)) throw new TypeError('encodeWavBytes expects a Float32Array.');
  validateRate(sampleRate);
  const dataLength = samples.length * 2;
  if (!Number.isSafeInteger(dataLength) || dataLength > 0xffffffff - 36) throw new RangeError('Audio is too large for a WAV file.');
  const buffer = new ArrayBuffer(44 + dataLength);
  const view = new DataView(buffer);
  const ascii = (offset, value) => { for (let i = 0; i < value.length; i++) view.setUint8(offset + i, value.charCodeAt(i)); };
  ascii(0, 'RIFF'); view.setUint32(4, 36 + dataLength, true); ascii(8, 'WAVE');
  ascii(12, 'fmt '); view.setUint32(16, 16, true); view.setUint16(20, 1, true); view.setUint16(22, 1, true);
  view.setUint32(24, sampleRate, true); view.setUint32(28, sampleRate * 2, true); view.setUint16(32, 2, true); view.setUint16(34, 16, true);
  ascii(36, 'data'); view.setUint32(40, dataLength, true);
  for (let i = 0; i < samples.length; i++) { const sample = Math.max(-1, Math.min(1, samples[i])); view.setInt16(44 + i * 2, sample < 0 ? Math.round(sample * 32768) : Math.round(sample * 32767), true); }
  return new Uint8Array(buffer);
}
export function synthesizeTestWav(options = {}) { const sampleRate = validateRate(Number(options.sampleRate ?? WHISPER_SAMPLE_RATE)); const samples = synthesizeTestAudioSamples({ ...options, sampleRate }); return { samples, wavBytes: encodeWavBytes(samples, sampleRate), sampleRate, durationSeconds: samples.length / sampleRate }; }
export function exportWavBlob(samples, sampleRate = WHISPER_SAMPLE_RATE) { if (typeof Blob === 'undefined') throw new Error('Blob is not supported in this environment.'); return new Blob([encodeWavBytes(samples, sampleRate)], { type: 'audio/wav' }); }

export async function resampleTo16kHzMono(inputSamples, inputSampleRate, targetSampleRate = WHISPER_SAMPLE_RATE) {
  validateSamples(inputSamples); validateRate(inputSampleRate); validateRate(targetSampleRate);
  if (inputSampleRate === targetSampleRate) return new Float32Array(inputSamples);
  const outputLength = Math.max(1, Math.round(inputSamples.length * targetSampleRate / inputSampleRate));
  if (outputLength > MAX_SAMPLES) throw new RangeError('Resampled audio exceeds the sample limit.');
  const OfflineContext = globalThis.OfflineAudioContext || globalThis.webkitOfflineAudioContext;
  if (typeof OfflineContext === 'function') {
    try { const context = new OfflineContext(1, outputLength, targetSampleRate); const buffer = context.createBuffer(1, inputSamples.length, inputSampleRate); buffer.getChannelData(0).set(inputSamples); const source = context.createBufferSource(); source.buffer = buffer; source.connect(context.destination); source.start(0); const rendered = await context.startRendering(); return new Float32Array(rendered.getChannelData(0)); } catch { /* deterministic interpolation below */ }
  }
  const output = new Float32Array(outputLength); const ratio = (inputSamples.length - 1) / Math.max(1, outputLength - 1);
  for (let i = 0; i < outputLength; i++) { const pos = i * ratio; const index = Math.floor(pos); const fraction = pos - index; output[i] = inputSamples[index] * (1 - fraction) + inputSamples[Math.min(index + 1, inputSamples.length - 1)] * fraction; }
  return output;
}

export async function decodeAudioFile(file, audioContext = null) {
  if (!file || typeof file.arrayBuffer !== 'function') throw new TypeError('Choose a supported audio file.');
  if (file.size > 50 * 1024 * 1024) throw new RangeError('Audio file is larger than the 50 MB limit.');
  const AudioContextCtor = globalThis.AudioContext || globalThis.webkitAudioContext;
  if (!audioContext && typeof AudioContextCtor !== 'function') throw new Error('Web Audio is not supported in this browser.');
  const context = audioContext || new AudioContextCtor();
  try {
    const decoded = await context.decodeAudioData(await file.arrayBuffer());
    if (!decoded.numberOfChannels || !decoded.length) throw new Error('The selected audio file contains no audio samples.');
    if (decoded.duration > MAX_SECONDS) throw new RangeError(`Audio must be no longer than ${MAX_SECONDS} seconds.`);
    const mono = new Float32Array(decoded.length);
    for (let channel = 0; channel < decoded.numberOfChannels; channel++) { const data = decoded.getChannelData(channel); for (let i = 0; i < data.length; i++) mono[i] += data[i] / decoded.numberOfChannels; }
    const samples = await resampleTo16kHzMono(mono, decoded.sampleRate, WHISPER_SAMPLE_RATE);
    return { samples, sampleRate: WHISPER_SAMPLE_RATE, durationSeconds: samples.length / WHISPER_SAMPLE_RATE };
  } finally {
    if (!audioContext && context.state !== 'closed') await context.close().catch(() => {});
  }
}
