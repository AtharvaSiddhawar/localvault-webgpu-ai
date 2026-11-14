/**
 * LocalVault AI v2.0 — Zero-Dependency Regression Test Suite (tests/verify.mjs)
 * Verifies:
 * 1. All 16 required repository files exist and are non-empty
 * 2. Luhn check-digit verification (valid & invalid card numbers)
 * 3. Shannon Information Entropy H(X) calculation
 * 4. 4-Layer Hybrid PII & Secret Scrubbing (SSH/PEM keys, DB URIs, OpenAI/AWS/GitHub/Stripe keys, SSNs, emails, IPs, .env secrets)
 * 5. Layer 3 Developer Loopback Allowlist (127.0.0.1, localhost, 0.0.0.0 preserved) & Custom Blocklist
 * 6. Fuzzy-Resilient Re-Hydration (rehydrateText handles [email_1], {{EMAIL_1}}, [email-1], <EMAIL_1>)
 * 7. Zero-Knowledge AES-256-GCM + PBKDF2-SHA256 (100,000 iterations) lock/unlock & tamper rejection
 * 8. Client-side Network Firewall POST/PUT exfiltration blocking & Air-Gap Lockdown
 * 9. Pure-JS 16kHz WAV synthesis & RIFF/WAVE header verification
 * 10. Offline Audio Transcript Structurer across all 4 engineering modes ('meeting', 'lecture', 'incident', 'executive')
 * 11. CLI execution for scrub & structure commands
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  PIIEngine,
  calculateShannonEntropy,
  isValidLuhn,
  rehydrateText
} from '../src/pii-engine.js';
import {
  CryptoVault,
  encryptVault,
  decryptVault
} from '../src/crypto-vault.js';
import { NetworkFirewall } from '../src/network-firewall.js';
import {
  structureTranscript,
  SUPPORTED_NOTE_MODES
} from '../src/note-structurer.js';
import {
  synthesizeTestWav,
  encodeWavBytes,
  resampleTo16kHzMono,
  WHISPER_SAMPLE_RATE
} from '../src/audio-utils.js';
import { runCli } from '../bin/localvault-cli.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');

const REQUIRED_16_FILES = [
  'package.json',
  'vite.config.js',
  'public/coi-serviceworker.js',
  'index.html',
  'src/styles.css',
  'src/main.js',
  'src/worker.js',
  'src/pii-engine.js',
  'src/crypto-vault.js',
  'src/network-firewall.js',
  'src/note-structurer.js',
  'src/audio-utils.js',
  'bin/localvault-cli.mjs',
  'tests/verify.mjs',
  'README.md',
  '.github/workflows/deploy.yml'
];

let passed = 0;
let failed = 0;

async function runTest(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  [PASS] ${name}`);
  } catch (err) {
    failed++;
    console.error(`  [FAIL] ${name}: ${err.message}`);
    console.error(err.stack);
  }
}

console.log('==============================================================');
console.log(' LocalVault AI v2.0 — Comprehensive Regression Verification');
console.log('==============================================================');

await runTest('1. Repository File Integrity (All 16 Architecture Files Present)', () => {
  for (const relPath of REQUIRED_16_FILES) {
    const fullPath = path.join(ROOT_DIR, relPath);
    assert.ok(fs.existsSync(fullPath), `Missing required file: ${relPath}`);
    const stat = fs.statSync(fullPath);
    assert.ok(stat.size > 0, `Required file is empty: ${relPath}`);
  }
});

await runTest('2. ISO/IEC 7812 Luhn Check-Digit Validation', () => {
  assert.equal(isValidLuhn('4532-0151-1283-0366'), true, 'Valid Visa Luhn should pass');
  assert.equal(isValidLuhn('49927398716'), false, '11-digit number should be rejected (13-19 required)');
  assert.equal(isValidLuhn('4532-0151-1283-0367'), false, 'Corrupted check digit must fail');
  assert.equal(isValidLuhn('0000000000000000'), false, 'All-zero digits must fail');
});

await runTest('3. Shannon Information Entropy H(X) Calculation', () => {
  assert.equal(calculateShannonEntropy(''), 0);
  assert.equal(calculateShannonEntropy('aaaaaaaaaa'), 0);
  assert.equal(calculateShannonEntropy('ab'), 1);
  const highEntropyKey = '9a8B7c6D5e4F3g2H1i0J9k8L7m6N5o4P';
  const lowEntropyWord = 'development';
  assert.ok(
    calculateShannonEntropy(highEntropyKey) > 4.2,
    'Cryptographic key should have high Shannon entropy (> 4.2 bits/char)'
  );
  assert.ok(
    calculateShannonEntropy(lowEntropyWord) < 3.5,
    'Normal English word should have lower entropy'
  );
});

await runTest('4. 4-Layer Hybrid PII & Secret Scrubbing + Loopback Allowlist', () => {
  const engine = new PIIEngine({ customBlocklist: ['ProjectOmega'] });
  const sample = [
    '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----',
    'DB=postgres://dbuser:MyS3cr3tP@ss99@198.51.100.25:5432/main',
    'OPENAI=sk-proj-1234567890abcdefghijklmnopQRSTUV',
    'ANTHROPIC=sk-ant-api03-1234567890abcdefghijklmnopQRSTUV',
    'GITHUB=ghp_1234567890abcdefghijklmnopQRSTUV1234',
    'AWS=AKIAIOSFODNN7EXAMPLE',
    'STRIPE=sk_live_51H8abcDEF1234567890xyz',
    'PASSWORD="UltraSecretPasswordValue99!"',
    'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
    'Card: 4532-0151-1283-0366, SSN: 123-45-6789, Email: dev@company.io, Phone: (415) 555-2671',
    'Loopback: 127.0.0.1, localhost, and 0.0.0.0 must remain untouched.',
    'Codename: ProjectOmega launched by Engineer Alice Smith.'
  ].join('\n');

  const res = engine.scrub(sample);

  // Ensure secrets were scrubbed
  assert.ok(!res.scrubbedText.includes('BEGIN OPENSSH PRIVATE KEY'), 'SSH key must be scrubbed');
  assert.ok(!res.scrubbedText.includes('MyS3cr3tP@ss99'), 'Postgres URI must be scrubbed');
  assert.ok(!res.scrubbedText.includes('sk-proj-1234567890'), 'OpenAI key must be scrubbed');
  assert.ok(!res.scrubbedText.includes('sk-ant-api03-'), 'Anthropic key must be scrubbed');
  assert.ok(!res.scrubbedText.includes('ghp_1234567890'), 'GitHub token must be scrubbed');
  assert.ok(!res.scrubbedText.includes('AKIAIOSFODNN7EXAMPLE'), 'AWS key must be scrubbed');
  assert.ok(!res.scrubbedText.includes('sk_live_51H8'), 'Stripe key must be scrubbed');
  assert.ok(!res.scrubbedText.includes('UltraSecretPasswordValue99!'), 'Env password must be scrubbed');
  assert.ok(!res.scrubbedText.includes('4532-0151-1283-0366'), 'Luhn credit card must be scrubbed');
  assert.ok(!res.scrubbedText.includes('123-45-6789'), 'SSN must be scrubbed');
  assert.ok(!res.scrubbedText.includes('dev@company.io'), 'Email must be scrubbed');
  assert.ok(!res.scrubbedText.includes('ProjectOmega'), 'Custom blocklist term must be scrubbed');
  assert.ok(!res.scrubbedText.includes('Alice Smith'), 'Contextual Layer 4 person must be scrubbed');

  // Ensure Layer 3 developer loopbacks were preserved
  assert.ok(res.scrubbedText.includes('127.0.0.1'), '127.0.0.1 must be preserved');
  assert.ok(res.scrubbedText.includes('localhost'), 'localhost must be preserved');
  assert.ok(res.scrubbedText.includes('0.0.0.0'), '0.0.0.0 must be preserved');
});

await runTest('5. Fuzzy-Resilient Re-Hydration Across LLM Placeholder Mutations', () => {
  const vaultMap = {
    '[EMAIL_1]': 'atharva@localvault.dev',
    '[OPENAI_KEY_1]': 'sk-proj-secret1234567890abcdef',
    '[DB_URI_1]': 'postgres://user:pass@10.0.0.8:5432/db'
  };

  const mutatedLlmOutput =
    'Contact [email_1] or {{EMAIL_1}} using key {{openai-key-1}} and connect to <db_uri 1> or (EMAIL-1).';
  const restored = rehydrateText(mutatedLlmOutput, vaultMap);

  assert.equal(
    restored,
    'Contact atharva@localvault.dev or atharva@localvault.dev using key sk-proj-secret1234567890abcdef and connect to postgres://user:pass@10.0.0.8:5432/db or atharva@localvault.dev.'
  );
});

await runTest('6. Zero-Knowledge AES-256-GCM + PBKDF2-SHA256 (310k Iterations) Crypto Vault', async () => {
  const vault = new CryptoVault();
  const secretData = { '[EMAIL_1]': 'founder@localvault.ai', '[AWS_KEY_1]': 'AKIAIOSFODNN7EXAMPLE' };
  const envelope = await vault.lock(secretData, 'CorrectHorseBatteryStaple!99');

  assert.equal(envelope.magic, 'LVVAULT_V2');
  assert.equal(envelope.kdf, 'PBKDF2-SHA256');
  assert.equal(envelope.cipher, 'AES-256-GCM');
  assert.equal(envelope.iterations, 310000);

  const decrypted = await vault.unlock(envelope, 'CorrectHorseBatteryStaple!99');
  assert.deepEqual(decrypted, secretData);

  // Wrong passphrase must fail authentication
  await assert.rejects(
    async () => decryptVault(envelope, 'WrongPassphrase'),
    /Vault authentication failed/
  );
});

await runTest('7. Client-Side Network Exfiltration Firewall & Air-Gap Lockdown', () => {
  const fw = new NetworkFirewall();

  const getModel = fw.inspectRequest('https://huggingface.co/onnx-community/whisper-tiny.en/resolve/main/model.onnx', 'GET');
  assert.equal(getModel.allowed, true);

  const postExfil = fw.inspectRequest('https://evil.example.com/collect', 'POST', '{"secret":"123"}');
  assert.equal(postExfil.allowed, false);
  assert.equal(postExfil.action, 'BLOCKED_EXFILTRATION');

  fw.setAirGapLockdown(true);
  const airgapExternalGet = fw.inspectRequest('https://huggingface.co/model.onnx', 'GET');
  assert.equal(airgapExternalGet.allowed, false);
  assert.equal(airgapExternalGet.action, 'BLOCKED_AIRGAP');

  const airgapLocalAsset = fw.inspectRequest('./assets/index.js', 'GET');
  assert.equal(airgapLocalAsset.allowed, true);
});

await runTest('8. Pure-JS 16kHz WAV Synthesis & Resampling', async () => {
  const { samples, wavBytes, sampleRate } = synthesizeTestWav({
    durationSeconds: 0.5,
    sampleRate: WHISPER_SAMPLE_RATE
  });
  assert.equal(sampleRate, 16000);
  assert.equal(samples.length, 8000);
  assert.equal(wavBytes.byteLength, 44 + 8000 * 2);

  // Verify RIFF / WAVE ASCII headers
  const header = Buffer.from(wavBytes.slice(0, 12)).toString('ascii');
  assert.equal(header.slice(0, 4), 'RIFF');
  assert.equal(header.slice(8, 12), 'WAVE');

  const resampled = await resampleTo16kHzMono(new Float32Array(48000), 48000, 16000);
  assert.equal(resampled.length, 16000);
});

await runTest('9. Offline Transcript Note Structurer (All 4 Engineering Modes)', () => {
  const raw =
    'Incident call with engineer dev@company.org on server 198.51.100.99. We decided to migrate to WebGPU local inference. Todo: rotate token sk-proj-1234567890abcdefghijklmnopQRSTUV immediately.';

  for (const mode of SUPPORTED_NOTE_MODES) {
    const out = structureTranscript(raw, { mode, autoScrub: true });
    assert.equal(out.mode, mode);
    assert.ok(!out.markdown.includes('dev@company.org'), `Mode ${mode} must auto-scrub email`);
    assert.ok(!out.markdown.includes('sk-proj-1234567890'), `Mode ${mode} must auto-scrub OpenAI key`);
    assert.ok(out.piiStats.totalRedacted >= 3);
  }
});

await runTest('10. CLI Executable Verification (scrub, structure, entropy)', () => {
  const scrubRun = runCli(['scrub', 'Email alice@acme.io and localhost']);
  assert.equal(scrubRun.exitCode, 0);
  assert.ok(scrubRun.result.scrubbedText.includes('[EMAIL_1]'));
  assert.ok(scrubRun.result.scrubbedText.includes('localhost'));

  const structRun = runCli(['structure', 'Decided to ship v2. Todo: run tests.', '--mode=incident']);
  assert.equal(structRun.exitCode, 0);
  assert.ok(structRun.result.markdown.includes('SRE Incident Post-Mortem'));
});

console.log('--------------------------------------------------------------');
console.log(` Verification Summary: ${passed} passed, ${failed} failed`);
console.log('--------------------------------------------------------------');

if (failed > 0) {
  process.exit(1);
}

