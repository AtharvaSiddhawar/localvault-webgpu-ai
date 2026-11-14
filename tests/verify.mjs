
/**
 * LocalVault AI — Comprehensive Regression Test Suite
 *
 * Covers:
 * 1. Repository file integrity
 * 2. Luhn validation
 * 3. Shannon entropy
 * 4. PII and secret detection
 * 5. Placeholder rehydration
 * 6. AES-256-GCM encrypted vault
 * 7. Network firewall policy
 * 8. Firewall runtime interceptors
 * 9. WAV encoding and audio resampling
 * 10. Transcript structuring
 * 11. CLI execution
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

const REQUIRED_FILES = [
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
  } catch (error) {
    failed++;
    console.error(`  [FAIL] ${name}: ${error.message}`);
    console.error(error.stack);
  }
}

console.log('==============================================================');
console.log(' LocalVault AI — Regression Verification');
console.log('==============================================================');

// --------------------------------------------------------------
// 1. Repository integrity
// --------------------------------------------------------------

await runTest(
  '1. Repository Integrity — All 16 Required Files',
  () => {
    for (const relativePath of REQUIRED_FILES) {
      const fullPath = path.join(ROOT_DIR, relativePath);

      assert.ok(
        fs.existsSync(fullPath),
        `Missing required file: ${relativePath}`
      );

      const stat = fs.statSync(fullPath);

      assert.ok(
        stat.isFile() && stat.size > 0,
        `Required file is empty or invalid: ${relativePath}`
      );
    }
  }
);

// --------------------------------------------------------------
// 2. Luhn validation
// --------------------------------------------------------------

await runTest(
  '2. ISO/IEC 7812 Luhn Check-Digit Validation',
  () => {
    assert.equal(
      isValidLuhn('4532-0151-1283-0366'),
      true
    );

    assert.equal(
      isValidLuhn('49927398716'),
      false
    );

    assert.equal(
      isValidLuhn('4532-0151-1283-0367'),
      false
    );

    assert.equal(
      isValidLuhn('0000000000000000'),
      false
    );

    assert.equal(
      isValidLuhn('not-a-card-number'),
      false
    );
  }
);

// --------------------------------------------------------------
// 3. Shannon entropy
// --------------------------------------------------------------

await runTest(
  '3. Shannon Information Entropy Calculation',
  () => {
    assert.equal(calculateShannonEntropy(''), 0);
    assert.equal(calculateShannonEntropy('aaaaaaaaaa'), 0);
    assert.equal(calculateShannonEntropy('ab'), 1);

    const highEntropyKey =
      '9a8B7c6D5e4F3g2H1i0J9k8L7m6N5o4P';

    const lowEntropyWord = 'development';

    assert.ok(
      calculateShannonEntropy(highEntropyKey) > 4.2
    );

    assert.ok(
      calculateShannonEntropy(lowEntropyWord) < 3.5
    );
  }
);

// --------------------------------------------------------------
// 4. PII and secret scrubbing
// --------------------------------------------------------------

await runTest(
  '4. PII and Secret Scrubbing + Loopback Allowlist',
  () => {
    const engine = new PIIEngine({
      customBlocklist: ['ProjectOmega']
    });

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

    const result = engine.scrub(sample);
    const clean = result.scrubbedText;

    const secrets = [
      'BEGIN OPENSSH PRIVATE KEY',
      'MyS3cr3tP@ss99',
      'sk-proj-1234567890',
      'sk-ant-api03-',
      'ghp_1234567890',
      'AKIAIOSFODNN7EXAMPLE',
      'sk_live_51H8',
      'UltraSecretPasswordValue99!',
      '4532-0151-1283-0366',
      '123-45-6789',
      'dev@company.io',
      'ProjectOmega',
      'Alice Smith'
    ];

    for (const secret of secrets) {
      assert.ok(
        !clean.includes(secret),
        `Secret was not scrubbed: ${secret}`
      );
    }

    assert.ok(clean.includes('127.0.0.1'));
    assert.ok(clean.includes('localhost'));
    assert.ok(clean.includes('0.0.0.0'));

    assert.ok(result.stats.totalRedacted > 0);
    assert.ok(Object.keys(result.vaultMap).length > 0);
  }
);

// --------------------------------------------------------------
// 5. Placeholder rehydration
// --------------------------------------------------------------

await runTest(
  '5. Fuzzy Placeholder Rehydration',
  () => {
    const vaultMap = {
      '[EMAIL_1]': 'atharva@localvault.dev',
      '[OPENAI_KEY_1]': 'sk-proj-secret1234567890abcdef',
      '[DB_URI_1]': 'postgres://user:pass@10.0.0.8:5432/db'
    };

    const mutatedOutput =
      'Contact [email_1] or {{EMAIL_1}} using key {{openai-key-1}} and connect to <db_uri 1> or (EMAIL-1).';

    const restored = rehydrateText(
      mutatedOutput,
      vaultMap
    );

    assert.equal(
      restored,
      'Contact atharva@localvault.dev or atharva@localvault.dev using key sk-proj-secret1234567890abcdef and connect to postgres://user:pass@10.0.0.8:5432/db or atharva@localvault.dev.'
    );
  }
);

// --------------------------------------------------------------
// 6. Cryptographic vault
// --------------------------------------------------------------

await runTest(
  '6. AES-256-GCM + PBKDF2-SHA256 Encrypted Vault',
  async () => {
    const vault = new CryptoVault();

    const secretData = {
      '[EMAIL_1]': 'founder@localvault.ai',
      '[AWS_KEY_1]': 'AKIAIOSFODNN7EXAMPLE'
    };

    const passphrase =
      'CorrectHorseBatteryStaple!99';

    const envelope = await vault.lock(
      secretData,
      passphrase
    );

    assert.equal(envelope.magic, 'LVVAULT_V2');
    assert.equal(envelope.version, '2.1.0');
    assert.equal(envelope.kdf, 'PBKDF2-SHA256');
    assert.equal(envelope.cipher, 'AES-256-GCM');

    assert.equal(envelope.iterations, 310000);

    assert.equal(vault.locked, true);

    const decrypted = await vault.unlock(
      envelope,
      passphrase
    );

    assert.deepEqual(decrypted, secretData);
    assert.equal(vault.locked, false);

    // Wrong passphrase must fail authentication.
    await assert.rejects(
      () => decryptVault(envelope, 'WrongPassphrase'),
      /Vault authentication failed/
    );

    // New vaults must reject weak passphrases.
    await assert.rejects(
      () => encryptVault(secretData, 'short'),
      /at least 12 characters/
    );

    // Tampered ciphertext must fail authentication.
    const tamperedEnvelope = { ...envelope };
    const ciphertextBytes = Buffer.from(
      envelope.ciphertext,
      'base64'
    );

    ciphertextBytes[0] ^= 1;

    tamperedEnvelope.ciphertext =
      ciphertextBytes.toString('base64');

    await assert.rejects(
      () => decryptVault(tamperedEnvelope, passphrase),
      /Vault authentication failed/
    );

    // Missing passphrases must be rejected.
    await assert.rejects(
      () => decryptVault(envelope, ''),
      /passphrase/i
    );

    vault.clear();
    assert.equal(vault.locked, true);
    assert.equal(vault.unlockedData, null);
  }
);

// --------------------------------------------------------------
// 7. Network firewall policy
// --------------------------------------------------------------

await runTest(
  '7. Network Firewall Host, Protocol and Payload Policies',
  () => {
    const firewall = new NetworkFirewall();

    // Approved model/library hosts.
    const approvedModel = firewall.inspectRequest(
      'https://huggingface.co/onnx-community/whisper-tiny.en/resolve/main/model.onnx',
      'GET'
    );

    assert.equal(approvedModel.allowed, true);
    assert.equal(approvedModel.action, 'ALLOWED_READONLY');

    const approvedCdn = firewall.inspectRequest(
      'https://cdn.jsdelivr.net/npm/example/package.js',
      'GET'
    );

    assert.equal(approvedCdn.allowed, true);

    // Unapproved external GET must be blocked.
    const unapprovedGet = firewall.inspectRequest(
      'https://evil.example.com/collect',
      'GET'
    );

    assert.equal(unapprovedGet.allowed, false);
    assert.equal(
      unapprovedGet.action,
      'BLOCKED_UNAPPROVED_HOST'
    );

    // Hostname suffix spoofing must be blocked.
    const spoofedHost = firewall.inspectRequest(
      'https://huggingface.co.evil.example/model.onnx',
      'GET'
    );

    assert.equal(spoofedHost.allowed, false);

    // External HTTP must be blocked.
    const insecureProtocol = firewall.inspectRequest(
      'http://evil.example.com/model.onnx',
      'GET'
    );

    assert.equal(insecureProtocol.allowed, false);
    assert.equal(
      insecureProtocol.action,
      'BLOCKED_PROTOCOL'
    );

    // Embedded credentials must be rejected.
    const credentialUrl = firewall.inspectRequest(
      'https://user:password@huggingface.co/model.onnx',
      'GET'
    );

    assert.equal(credentialUrl.allowed, false);
    assert.equal(
      credentialUrl.action,
      'BLOCKED_CREDENTIAL_URL'
    );

    // Payload-carrying read-only requests must be blocked.
    const getWithBody = firewall.inspectRequest(
      'https://huggingface.co/model.onnx',
      'GET',
      '{"secret":"test"}'
    );

    assert.equal(getWithBody.allowed, false);
    assert.equal(
      getWithBody.action,
      'BLOCKED_PAYLOAD'
    );

    // POST and other mutating methods must be blocked.
    const post = firewall.inspectRequest(
      'https://evil.example.com/collect',
      'POST',
      '{"secret":"test"}'
    );

    assert.equal(post.allowed, false);
    assert.equal(post.action, 'BLOCKED_METHOD');

    const patch = firewall.inspectRequest(
      'https://huggingface.co/model',
      'PATCH',
      '{"value":1}'
    );

    assert.equal(patch.allowed, false);

    // Same-origin local resources are permitted.
    const localAsset = firewall.inspectRequest(
      './assets/index.js',
      'GET'
    );

    assert.equal(localAsset.allowed, true);
    assert.equal(
      localAsset.action,
      'ALLOWED_SAME_ORIGIN'
    );

    // Local generated data resources are permitted.
    const localData = firewall.inspectRequest(
      'data:text/plain,LocalVault',
      'GET'
    );

    assert.equal(localData.allowed, true);
    assert.equal(localData.action, 'ALLOWED_LOCAL');

    // Sensitive URL parameters must not appear in logs.
    const sensitiveUrl = firewall.inspectRequest(
      'https://huggingface.co/model?token=secret-value',
      'GET'
    );

    assert.equal(sensitiveUrl.allowed, true);
    assert.ok(!sensitiveUrl.url.includes('secret-value'));

    // Strict Air-Gap Lockdown.
    firewall.setAirGapLockdown(true);

    const blockedExternal = firewall.inspectRequest(
      'https://huggingface.co/model.onnx',
      'GET'
    );

    assert.equal(blockedExternal.allowed, false);
    assert.equal(
      blockedExternal.action,
      'BLOCKED_AIRGAP'
    );

    const allowedLocal = firewall.inspectRequest(
      './assets/index.js',
      'GET'
    );

    assert.equal(allowedLocal.allowed, true);

    const stats = firewall.getStats();

    assert.ok(stats.totalEvents >= 10);
    assert.ok(stats.blocked >= 5);
    assert.equal(stats.airGapLockdown, true);
    assert.ok(stats.allowedHosts.includes('huggingface.co'));
  }
);

// --------------------------------------------------------------
// 8. Runtime fetch interceptor
// --------------------------------------------------------------

await runTest(
  '8. Runtime Fetch Interceptor and Restoration',
  async () => {
    let originalFetchCalls = 0;

    const originalFetch = async (input) => {
      originalFetchCalls++;

      return {
        ok: true,
        requested: String(input)
      };
    };

    const mockGlobal = {
      location: {
        href: 'https://app.localvault.test/'
      },
      fetch: originalFetch
    };

    const firewall = new NetworkFirewall();
    firewall.install(mockGlobal);

    assert.equal(firewall.installed, true);

    // Same-origin request reaches the original fetch.
    const localResponse = await mockGlobal.fetch('/health');

    assert.equal(localResponse.ok, true);
    assert.equal(originalFetchCalls, 1);

    // Approved external host reaches the original fetch.
    await mockGlobal.fetch(
      'https://huggingface.co/model.onnx'
    );

    assert.equal(originalFetchCalls, 2);

    // Unapproved external host must never reach original fetch.
    await assert.rejects(
      () => mockGlobal.fetch('https://evil.example.com/data'),
      /LocalVault Firewall/
    );

    assert.equal(originalFetchCalls, 2);

    // Mutating requests must never reach original fetch.
    await assert.rejects(
      () => mockGlobal.fetch(
        'https://huggingface.co/model',
        {
          method: 'POST',
          body: '{"data":"test"}'
        }
      ),
      /LocalVault Firewall/
    );

    assert.equal(originalFetchCalls, 2);

    firewall.uninstall(mockGlobal);

    assert.equal(firewall.installed, false);
    assert.equal(mockGlobal.fetch, originalFetch);
  }
);

// --------------------------------------------------------------
// 9. WAV encoding and resampling
// --------------------------------------------------------------

await runTest(
  '9. 16kHz WAV Synthesis, Encoding and Resampling',
  async () => {
    const {
      samples,
      wavBytes,
      sampleRate
    } = synthesizeTestWav({
      durationSeconds: 0.5,
      sampleRate: WHISPER_SAMPLE_RATE
    });

    assert.equal(sampleRate, 16000);
    assert.equal(samples.length, 8000);
    assert.equal(wavBytes.byteLength, 44 + 8000 * 2);

    const header = Buffer.from(
      wavBytes.slice(0, 12)
    ).toString('ascii');

    assert.equal(header.slice(0, 4), 'RIFF');
    assert.equal(header.slice(8, 12), 'WAVE');

    const encoded = encodeWavBytes(
      new Float32Array([0, 0.5, -0.5]),
      16000
    );

    assert.equal(encoded.length, 50);

    const resampled = await resampleTo16kHzMono(
      new Float32Array(48000),
      48000,
      16000
    );

    assert.equal(resampled.length, 16000);
  }
);

// --------------------------------------------------------------
// 10. Transcript structuring
// --------------------------------------------------------------

await runTest(
  '10. Transcript Structurer — All Four Engineering Modes',
  () => {
    const raw =
      'Incident call with engineer dev@company.org on server 198.51.100.99. ' +
      'We decided to migrate to WebGPU local inference. ' +
      'Todo: rotate token sk-proj-1234567890abcdefghijklmnopQRSTUV immediately.';

    for (const mode of SUPPORTED_NOTE_MODES) {
      const output = structureTranscript(raw, {
        mode,
        autoScrub: true
      });

      assert.equal(output.mode, mode);

      assert.ok(
        !output.markdown.includes('dev@company.org'),
        `Mode ${mode} did not scrub the email`
      );

      assert.ok(
        !output.markdown.includes('sk-proj-1234567890'),
        `Mode ${mode} did not scrub the API key`
      );

      assert.ok(
        output.piiStats.totalRedacted >= 3,
        `Mode ${mode} did not report expected detections`
      );
    }
  }
);

// --------------------------------------------------------------
// 11. CLI execution
// --------------------------------------------------------------

await runTest(
  '11. CLI Commands — Scrub, Structure and Entropy',
  () => {
    const scrubRun = runCli([
      'scrub',
      'Email alice@acme.io and localhost'
    ]);

    assert.equal(scrubRun.exitCode, 0);

    assert.ok(
      scrubRun.result.scrubbedText.includes('[EMAIL_1]')
    );

    assert.ok(
      scrubRun.result.scrubbedText.includes('localhost')
    );

    const structureRun = runCli([
      'structure',
      'Decided to ship v2. Todo: run tests.',
      '--mode=incident'
    ]);

    assert.equal(structureRun.exitCode, 0);

    assert.ok(
      structureRun.result.markdown.includes(
        'SRE Incident Post-Mortem'
      )
    );
  }
);

// --------------------------------------------------------------
// Final report
// --------------------------------------------------------------

console.log('--------------------------------------------------------------');
console.log(`Verification Summary: ${passed} passed, ${failed} failed`);
console.log('--------------------------------------------------------------');

if (failed > 0) {
  process.exitCode = 1;
}
