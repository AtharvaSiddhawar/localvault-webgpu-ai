import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { PIIEngine, calculateShannonEntropy, isAllowlistedLoopback, isValidLuhn, rehydrateText } from '../src/pii-engine.js';
import { CryptoVault, decryptVault, encryptVault } from '../src/crypto-vault.js';
import { NetworkFirewall } from '../src/network-firewall.js';
import { SUPPORTED_NOTE_MODES, structureTranscript } from '../src/note-structurer.js';
import { encodeWavBytes, exportWavBlob, resampleTo16kHzMono, synthesizeTestWav } from '../src/audio-utils.js';
import { runCli } from '../bin/localvault-cli.mjs';

if (!globalThis.crypto?.subtle) Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
if (typeof globalThis.btoa !== 'function') globalThis.btoa = (value) => Buffer.from(value, 'binary').toString('base64');
if (typeof globalThis.atob !== 'function') globalThis.atob = (value) => Buffer.from(value, 'base64').toString('binary');

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log(`PASS ${name}`); }
  catch (error) { failed++; console.error(`FAIL ${name}\n${error?.stack || error}`); }
}
function captureConsole(fn) {
  const oldLog = console.log; const oldError = console.error; const lines = [];
  console.log = (...args) => lines.push(args.join(' ')); console.error = (...args) => lines.push(args.join(' '));
  try { return { result: fn(), output: lines.join('\n') }; }
  finally { console.log = oldLog; console.error = oldError; }
}

await test('1. Entropy and identifier validators', () => {
  assert.equal(calculateShannonEntropy('aaaa'), 0);
  assert.equal(calculateShannonEntropy('ab'), 1);
  assert.equal(isValidLuhn('4532015112830366'), true);
  assert.equal(isValidLuhn('4532015112830367'), false);
});

await test('2. Loopback allowlist is precise', () => {
  assert.equal(isAllowlistedLoopback('127.0.0.1'), true);
  assert.equal(isAllowlistedLoopback('127.255.255.255'), true);
  assert.equal(isAllowlistedLoopback('127.999.0.1'), false);
  assert.equal(isAllowlistedLoopback('192.168.1.1'), false);
});

await test('3. PII scanner redacts known patterns and preserves local host', () => {
  const engine = new PIIEngine();
  const result = engine.scrub('Email alex@example.org, host 127.0.0.1, external 198.51.100.42 and key sk-proj-123456789012345678901234567890.');
  assert.match(result.scrubbedText, /\[EMAIL_1\]/);
  assert.match(result.scrubbedText, /127\.0\.0\.1/);
  assert.doesNotMatch(result.scrubbedText, /alex@example\.org/);
  assert.doesNotMatch(result.scrubbedText, /198\.51\.100\.42/);
  assert.ok(result.stats.totalRedacted >= 3);
  const bearer = new PIIEngine().scrub('Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456');
  assert.match(bearer.scrubbedText, /Authorization: Bearer \[BEARER_TOKEN_1\]/);
});

await test('4. Custom blocklist, allowlist and run-unique placeholders', () => {
  const engine = new PIIEngine({ customAllowlist: ['safe@example.org'] });
  const first = engine.scrub('safe@example.org; blockedword; contact one@example.org', { customBlocklist: ['blockedword'] });
  const second = engine.scrub('contact two@example.org');
  assert.match(first.scrubbedText, /safe@example\.org/);
  assert.doesNotMatch(first.scrubbedText, /blockedword/);
  assert.match(second.scrubbedText, /EMAIL_R2_1/);
  assert.notEqual(first.vaultMap['[EMAIL_1]'], second.vaultMap['[EMAIL_R2_1]']);
});

await test('5. Rehydration restores exact placeholders', () => {
  const map = { '[EMAIL_1]': 'alex@example.org', '[ENV_SECRET_1]': 'sample-secret' };
  assert.equal(rehydrateText('Email [EMAIL_1], secret [ENV_SECRET_1].', map), 'Email alex@example.org, secret sample-secret.');
});

await test('6. Async optional entity detector and fallback', async () => {
  const engine = new PIIEngine({ slmNerDetector: async () => [{ text: 'Alice Smith', type: 'PERSON' }] });
  const result = await engine.scrubAsync('Please contact Alice Smith about the schedule.');
  assert.doesNotMatch(result.scrubbedText, /Alice Smith/);
  assert.equal(result.stats.byLayer[4], 1);
  const fallback = await new PIIEngine({ slmNerDetector: async () => { throw new Error('unavailable'); } }).scrubAsync('mail fallback@example.org');
  assert.doesNotMatch(fallback.scrubbedText, /fallback@example\.org/);
});

await test('7. Vault encryption, unlock, tamper rejection and clearing', async () => {
  const vault = new CryptoVault();
  const data = { '[EMAIL_1]': 'alex@example.org', '[TOKEN_1]': 'demo-token' };
  const envelope = await vault.lock(data, 'localvault-safe-passphrase');
  assert.equal(envelope.cipher, 'AES-256-GCM');
  assert.equal(envelope.iterations, 310000);
  assert.deepEqual(await vault.unlock(envelope, 'localvault-safe-passphrase'), data);
  await assert.rejects(() => decryptVault(envelope, 'incorrect-passphrase'), /authentication failed/i);
  const corrupted = { ...envelope, ciphertext: `${envelope.ciphertext.slice(0, -4)}AAAA` };
  await assert.rejects(() => decryptVault(corrupted, 'localvault-safe-passphrase'));
  vault.clear(); assert.equal(vault.locked, true); assert.equal(vault.unlockedData, null); assert.equal(vault.activeEnvelope, null);
});

await test('8. Vault schema rejects malformed values and weak new passphrases', async () => {
  await assert.rejects(() => encryptVault({ ok: true }, 'short'), /12 characters/i);
  await assert.rejects(() => decryptVault('{not-json', 'some-passphrase'), /valid JSON/i);
});

await test('9. Firewall decision policy and air-gap lockdown', () => {
  const firewall = new NetworkFirewall();
  assert.equal(firewall.inspectRequest('/asset.js', 'GET').allowed, true);
  assert.equal(firewall.inspectRequest('https://huggingface.co/model.bin', 'GET').allowed, true);
  assert.equal(firewall.inspectRequest('https://evil.example.org/data', 'GET').action, 'BLOCKED_UNAPPROVED_HOST');
  assert.equal(firewall.inspectRequest('https://huggingface.co/submit', 'POST', 'payload').allowed, false);
  firewall.setAirGapLockdown(true);
  assert.equal(firewall.inspectRequest('https://huggingface.co/model.bin', 'GET').action, 'BLOCKED_AIRGAP');
  assert.equal(firewall.inspectRequest('/local.js', 'GET').allowed, true);
  assert.equal(firewall.getStats().airGapLockdown, true);
});

await test('10. Runtime fetch, XHR, beacon interception and restoration', async () => {
  let fetchCalls = 0; const originalFetch = async (url) => { fetchCalls++; return { ok: true, url }; };
  let beaconCalls = 0; const originalBeacon = () => { beaconCalls++; return true; };
  class MockXHR { open(method, url) { this.method = method; this.url = url; } send(body) { this.body = body; } }
  const oldOpen = MockXHR.prototype.open; const oldSend = MockXHR.prototype.send;
  const fake = { location: { href: 'https://app.localvault.test/' }, fetch: originalFetch, XMLHttpRequest: MockXHR, navigator: { sendBeacon: originalBeacon } };
  const firewall = new NetworkFirewall(); firewall.install(fake);
  await fake.fetch('/health'); assert.equal(fetchCalls, 1);
  await fake.fetch('https://huggingface.co/model.bin'); assert.equal(fetchCalls, 2);
  await assert.rejects(() => fake.fetch('https://evil.example.org/data'), /LocalVault Firewall/);
  await assert.rejects(() => fake.fetch('https://huggingface.co/post', { method: 'POST', body: 'x' }), /LocalVault Firewall/);
  const xhr = new fake.XMLHttpRequest(); xhr.open('POST', 'https://evil.example.org/collect');
  assert.throws(() => xhr.send('secret'), /LocalVault Firewall/);
  assert.equal(fake.navigator.sendBeacon('https://evil.example.org/beacon', 'payload'), false);
  assert.equal(beaconCalls, 0);
  firewall.uninstall(fake); assert.equal(fake.fetch, originalFetch);
  assert.equal(fake.XMLHttpRequest.prototype.open, oldOpen); assert.equal(fake.XMLHttpRequest.prototype.send, oldSend);
  assert.equal(fake.navigator.sendBeacon, originalBeacon);
});

await test('11. WAV synthesis, PCM header, blob export and resampling', async () => {
  const wav = synthesizeTestWav({ durationSeconds: 0.5, sampleRate: 16000 });
  assert.equal(wav.samples.length, 8000); assert.equal(wav.wavBytes.byteLength, 16044);
  const header = Buffer.from(wav.wavBytes.slice(0, 44));
  assert.equal(header.toString('ascii', 0, 4), 'RIFF'); assert.equal(header.toString('ascii', 8, 12), 'WAVE');
  assert.equal(header.readUInt32LE(24), 16000); assert.equal(header.readUInt16LE(34), 16);
  const blob = exportWavBlob(new Float32Array([0, 0.5, -0.5]), 16000); assert.equal(blob.type, 'audio/wav'); assert.equal(blob.size, 50);
  assert.equal(encodeWavBytes(new Float32Array([0]), 16000).length, 46);
  const resampled = await resampleTo16kHzMono(new Float32Array(48000), 48000, 16000); assert.equal(resampled.length, 16000);
  await assert.rejects(() => resampleTo16kHzMono(new Float32Array(0), 16000, 16000), /empty/i);
  await assert.rejects(() => resampleTo16kHzMono(new Float32Array([0, 1]), 16000, 0), /sample rate/i);
});

await test('12. Note structurer supports all modes and auto-scrubs', () => {
  assert.deepEqual(SUPPORTED_NOTE_MODES, ['meeting', 'lecture', 'incident', 'executive']);
  const raw = 'Incident call with engineer dev@company.org. We decided to migrate to WebGPU. Todo: rotate token sk-proj-123456789012345678901234567890 immediately.';
  for (const mode of SUPPORTED_NOTE_MODES) {
    const result = structureTranscript(raw, { mode, autoScrub: true });
    assert.equal(result.mode, mode); assert.ok(result.markdown.length > 50);
    assert.doesNotMatch(result.markdown, /dev@company\.org|sk-proj-1234567890/);
  }
  const unfiltered = structureTranscript('Contact person@example.org.', { mode: 'meeting', autoScrub: false });
  assert.match(unfiltered.markdown, /person@example\.org/); assert.equal(unfiltered.piiStats.totalRedacted, 0);
  assert.equal(structureTranscript('', { mode: 'bad' }).mode, 'meeting');
});

await test('13. CLI supports scrub, structure, entropy and help', () => {
  const help = captureConsole(() => runCli(['--help'])); assert.equal(help.result.exitCode, 0); assert.match(help.output, /Commands:/);
  const scrub = captureConsole(() => runCli(['scrub', 'Email alex@example.org'])); assert.equal(scrub.result.exitCode, 0); assert.match(scrub.result.result.scrubbedText, /\[EMAIL_1\]/);
  const structure = captureConsole(() => runCli(['structure', 'Decided to proceed. Todo: run tests.', '--mode=incident'])); assert.equal(structure.result.exitCode, 0); assert.match(structure.result.output, /Incident Post-Mortem/);
  const entropy = captureConsole(() => runCli(['entropy', 'ab'])); assert.equal(entropy.result.exitCode, 0); assert.equal(entropy.result.entropy, 1);
  const invalid = captureConsole(() => runCli(['structure', 'notes', '--mode=invalid'])); assert.equal(invalid.result.exitCode, 1);
  const missing = captureConsole(() => runCli(['scrub'])); assert.equal(missing.result.exitCode, 1);
  const unknown = captureConsole(() => runCli(['other'])); assert.equal(unknown.result.exitCode, 1);
});

console.log('------------------------------------------------------------');
console.log(`LocalVault verification: ${passed} passed, ${failed} failed`);
console.log('------------------------------------------------------------');
if (failed) process.exitCode = 1;
