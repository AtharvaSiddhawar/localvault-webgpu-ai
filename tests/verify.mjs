/**
 * LocalVault AI v2.0 — Comprehensive Verification & Regression Suite
 * Run via: npm test (or node tests/verify.mjs)
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  scrubText,
  rehydrateText,
  isValidLuhn,
  calculateShannonEntropy
} from '../src/pii-engine.js';
import {
  encryptVaultMap,
  decryptVaultMap
} from '../src/crypto-vault.js';
import {
  structureTranscriptInstant,
  buildNoteStructuringMessages
} from '../src/note-structurer.js';
import {
  generateSyntheticTestAudio
} from '../src/audio-utils.js';

console.log('=== Running LocalVault AI v2.0 Verification Suite ===');

const requiredFiles = [
  'package.json',
  'vite.config.js',
  'index.html',
  'README.md',
  'LICENSE',
  '.gitignore',
  '.github/workflows/deploy.yml',
  'public/coi-serviceworker.js',
  'bin/localvault-cli.mjs',
  'src/main.js',
  'src/worker.js',
  'src/pii-engine.js',
  'src/crypto-vault.js',
  'src/network-firewall.js',
  'src/note-structurer.js',
  'src/audio-utils.js',
  'src/styles.css'
];

for (const relPath of requiredFiles) {
  const fullPath = path.resolve(process.cwd(), relPath);
  assert.equal(fs.existsSync(fullPath), true, `Missing required file: ${relPath}`);
}
console.log(`[PASS] File integrity verified (${requiredFiles.length} files present).`);

const highEntropy = calculateShannonEntropy('whsec_K9mP4xR2vL8nQ5wZ1jF7yB3cT6hN0dG');
const lowEntropy = calculateShannonEntropy('aaaaaaaaaa');
assert.equal(highEntropy > 4.0, true, 'High-entropy secret must exceed 4.0 bits/char');
assert.equal(lowEntropy, 0, 'Constant string has 0 entropy');
assert.equal(isValidLuhn('4532 0151 1283 0366'), true);
assert.equal(isValidLuhn('4532 0151 1283 0367'), false);
assert.equal(isValidLuhn('0000 0000 0000 0000'), false, 'Repeated zero digits must be rejected');
console.log('[PASS] Shannon entropy calculator & strict Luhn validator verified.');

const complexInput = `
Contact: Dr. Evelyn Vance (evelyn@acme.io)
DB_URI=postgres://admin:9vK!x82QpLm@prod.db.internal:5432/main
WEBHOOK_SECRET = "whsec_98a7bc65def4321098a7bc65def43210"
Localhost: 127.0.0.1
Prod IP: 192.168.42.118
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmU=
-----END OPENSSH PRIVATE KEY-----
`;

const scrubRes = scrubText(complexInput, {
  customTerms: ['Project Titan'],
  preserveLocalhost: true
});

assert.equal(scrubRes.scrubbedText.includes('evelyn@acme.io'), false, 'Email must be redacted');
assert.equal(scrubRes.scrubbedText.includes('9vK!x82QpLm'), false, 'Postgres URI password must be redacted');
assert.equal(scrubRes.scrubbedText.includes('whsec_98a7bc65def4321098a7bc65def43210'), false, 'High-entropy secret assignment must be redacted');
assert.equal(scrubRes.scrubbedText.includes('BEGIN OPENSSH PRIVATE KEY'), false, 'Multi-line private key must be redacted');
assert.equal(scrubRes.scrubbedText.includes('192.168.42.118'), false, 'Private prod IP must be redacted');
assert.equal(scrubRes.scrubbedText.includes('127.0.0.1'), true, 'Loopback 127.0.0.1 must be preserved for developers');
assert.equal(scrubRes.stats.risk.level, 'CRITICAL', 'Risk score should be CRITICAL');
console.log('[PASS] 4-Layer PII & Secret Firewall verified (including localhost preservation).');

const mutatedLlmResponse = 'Updated [email_1] and rotated {{CONN_URI_1}} and <PRIV_KEY-1>.';
const rehydrated = rehydrateText(mutatedLlmResponse, scrubRes.tokenToOriginal);
assert.equal(rehydrated.includes('evelyn@acme.io'), true, 'Lowercase [email_1] must rehydrate');
assert.equal(rehydrated.includes('postgres://admin:9vK!x82QpLm@prod.db.internal:5432/main'), true, 'Curly brace {{CONN_URI_1}} must rehydrate');
assert.equal(rehydrated.includes('-----BEGIN OPENSSH PRIVATE KEY-----'), true, 'Hyphenated <PRIV_KEY-1> must rehydrate');
console.log('[PASS] Fuzzy-resilient token re-hydration verified.');

const encryptedVault = await encryptVaultMap(scrubRes.tokenToOriginal, 'super-secret-passphrase');
assert.equal(encryptedVault.includes('evelyn@acme.io'), false, 'Ciphertext must not leak plaintext');
const decryptedVault = await decryptVaultMap(encryptedVault, 'super-secret-passphrase');
assert.deepEqual(decryptedVault, scrubRes.tokenToOriginal, 'Decrypted map must match original exactly');
console.log('[PASS] AES-256-GCM + PBKDF2 cryptographic vault verified.');

const synthAudio = generateSyntheticTestAudio(1.0);
assert.equal(synthAudio.audioData.length, 16000, '1s audio at 16kHz must have 16000 samples');
assert.equal(synthAudio.wavBlob.size, 44 + 16000 * 2, '16-bit mono WAV header + PCM size must be exact');

const incidentNotes = structureTranscriptInstant(
  'We must rotate the staging keys by Friday. What caused the timeout?',
  'incident',
  { piiRedactedCount: 3 }
);
assert.equal(incidentNotes.includes('# Engineering Incident Post-Mortem'), true);
assert.equal(incidentNotes.includes('Auto-Scrubbed PII: 3 entities'), true);
assert.equal(buildNoteStructuringMessages('test', 'incident').length, 2);
console.log('[PASS] 16kHz WAV synthesizer & Incident Note Structurer verified.');

console.log('=== ALL v2.0 VERIFICATION CHECKS PASSED WITH ZERO ERRORS ===');
  
