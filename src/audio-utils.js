/**
 * Browser Audio Capture, 16kHz Mono Resampler & Pure-JS WAV Synthesizer
 */

export const SAMPLE_RATE = 16000;

export const DEMO_TRANSCRIPTS = {
  lecture: `Welcome everyone to today's systems engineering lecture on Zero-Cloud Client-Side AI architectures. Traditionally, deploying speech recognition or language models required sending raw user audio and text over HTTPS to centralized cloud GPU clusters. That introduces three major problems: recurring API token expenses, network latency, and severe privacy risks when handling medical, legal, or proprietary source code. With the standardization of WebGPU in modern browsers and quantized ONNX weights via Transformers.js, we can now execute models like Whisper and Qwen 2.5 directly on the user's local GPU shader cores. For next Monday's lab assignment, every student must benchmark 4-bit quantized model inference latency on their laptop and submit their report by Friday at 5 PM. Are there any questions about how WebGPU compute shaders map matrix multiplications to local VRAM?`,
  meeting: `Thanks for joining the Q4 security incident sync. Let's review our action items before launch. First, Contact: Sarah Chen (sarah.chen@acmecorp.io) and Dr. Marcus Vance confirmed that no customer support transcripts or database URIs like postgres://admin:Sup3rS3cretP@ss99@db.internal:5432/prod can leave the browser unredacted. We must deploy the client-side PII firewall across all engineering workflows by Friday. Second, Alex will rotate the production OpenAI key sk-proj-98a7bc65def4321098a7bc65def43210 and migrate our transcription pipeline to Whisper WebGPU so we eliminate the $4,200 monthly cloud API bill. Will compliance sign off on the zero-telemetry audit before Wednesday?`
};

export function encodeFloat32ToWavBlob(samples, sampleRate = SAMPLE_RATE) {
  const numSamples = samples.length;
  const buffer = new ArrayBuffer(44 + numSamples * 2);
  const view = new DataView(buffer);

  function writeAscii(offset, str) {
    for (let i = 0; i < str.length; i++) {
      view.setUint8(offset + i, str.charCodeAt(i));
    }
  }

  writeAscii(0, 'RIFF');
  view.setUint32(4, 36 + numSamples * 2, true);
  writeAscii(8, 'WAVE');
  writeAscii(12, 'fmt ');
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true);
  view.setUint16(22, 1, true);
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, sampleRate * 2, true);
  view.setUint16(32, 2, true);
  view.setUint16(34, 16, true);
  writeAscii(36, 'data');
  view.setUint32(40, numSamples * 2, true);

  let offset = 44;
  for (let i = 0; i < numSamples; i++) {
    const s = Math.max(-1, Math.min(1, samples[i]));
    view.setInt16(offset, s < 0 ? s * 0x8000 : s * 0x7fff, true);
    offset += 2;
  }

  return new Blob([buffer], { type: 'audio/wav' });
}

export function generateSyntheticTestAudio(durationSeconds = 2.5) {
  const totalSamples = Math.floor(durationSeconds * SAMPLE_RATE);
  const audioData = new Float32Array(totalSamples);
  for (let i = 0; i < totalSamples; i++) {
    const t = i / SAMPLE_RATE;
    const envelope = Math.sin(Math.PI * (t / durationSeconds));
    audioData[i] =
      0.25 *
      envelope *
      (Math.sin(2 * Math.PI * 220 * t) +
        0.5 * Math.sin(2 * Math.PI * 440 * t) +
        0.25 * Math.sin(2 * Math.PI * 880 * t));
  }
  const wavBlob = encodeFloat32ToWavBlob(audioData, SAMPLE_RATE);
  return {
    audioData,
    durationSeconds,
    wavBlob
  };
}

export async function decodeAudioBlobTo16kHzMono(audioBlob) {
  const arrayBuffer = await audioBlob.arrayBuffer();
  const AudioCtx = window.AudioContext || window.webkitAudioContext;
  if (!AudioCtx) {
    throw new Error('Web Audio API is not supported in this browser.');
  }

  const tempCtx = new AudioCtx();
  let decodedBuffer;
  try {
    decodedBuffer = await tempCtx.decodeAudioData(arrayBuffer.slice(0));
  } finally {
    if (tempCtx.state !== 'closed') {
      await tempCtx.close().catch(() => {});
    }
  }

  const targetLength = Math.max(1, Math.ceil(decodedBuffer.duration * SAMPLE_RATE));
  const OfflineCtx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
  const offlineCtx = new OfflineCtx(1, targetLength, SAMPLE_RATE);

  const source = offlineCtx.createBufferSource();
  source.buffer = decodedBuffer;
  source.connect(offlineCtx.destination);
  source.start(0);

  const renderedBuffer = await offlineCtx.startRendering();
  const float32Data = new Float32Array(renderedBuffer.getChannelData(0));

  return {
    audioData: float32Data,
    durationSeconds: Number(decodedBuffer.duration.toFixed(2)),
    wavBlob: encodeFloat32ToWavBlob(float32Data, SAMPLE_RATE)
  };
}

export class MicrophoneRecorder {
  constructor() {
    this.mediaRecorder = null;
    this.stream = null;
    this.chunks = [];
    this.isRecording = false;
  }

  async start() {
    if (this.isRecording) return;
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      throw new Error('Microphone access requires HTTPS or localhost.');
    }

    this.stream = await navigator.mediaDevices.getUserMedia({
      audio: {
        channelCount: 1,
        sampleRate: SAMPLE_RATE,
        echoCancellation: true,
        noiseSuppression: true
      }
    });

    this.chunks = [];
    const mimeType =
      typeof MediaRecorder !== 'undefined' && MediaRecorder.isTypeSupported('audio/webm;codecs=opus')
        ? 'audio/webm;codecs=opus'
        : '';

    this.mediaRecorder = mimeType
      ? new MediaRecorder(this.stream, { mimeType })
      : new MediaRecorder(this.stream);

    this.mediaRecorder.ondataavailable = (event) => {
      if (event.data && event.data.size > 0) {
        this.chunks.push(event.data);
      }
    };

    this.mediaRecorder.start(250);
    this.isRecording = true;
  }

  async stop() {
    if (!this.isRecording || !this.mediaRecorder) return null;

    return new Promise((resolve, reject) => {
      this.mediaRecorder.onstop = async () => {
        try {
          const blob = new Blob(this.chunks, {
            type: this.mediaRecorder.mimeType || 'audio/webm'
          });
          this.cleanup();
          const decoded = await decodeAudioBlobTo16kHzMono(blob);
          resolve({ blob, ...decoded });
        } catch (err) {
          this.cleanup();
          reject(err);
        }
      };
      this.mediaRecorder.stop();
    });
  }

  cleanup() {
    this.isRecording = false;
    if (this.stream) {
      this.stream.getTracks().forEach((t) => t.stop());
      this.stream = null;
    }
  }
}
