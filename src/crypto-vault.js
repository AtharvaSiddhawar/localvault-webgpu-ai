/**
 * LocalVault AI v2.0 — Zero-Knowledge Cryptographic Vault (src/crypto-vault.js)
 * Uses native Web Crypto API (PBKDF2-SHA256 with 100,000 iterations + AES-256-GCM)
 * Compatible with Browser (window.crypto.subtle) and Node.js 18–24+ (globalThis.crypto.subtle / node:crypto.webcrypto).
 */

const VAULT_MAGIC = 'LVVAULT_V2';
const PBKDF2_ITERATIONS = 100000;
const SALT_BYTES = 16;
const IV_BYTES = 12;

let cachedWebCrypto = null;

async function getWebCrypto() {
  if (cachedWebCrypto) return cachedWebCrypto;
  if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
    cachedWebCrypto = globalThis.crypto;
    return cachedWebCrypto;
  }
  try {
    const nodeCryptoSpec = 'node:' + 'crypto';
    const mod = await import(/* @vite-ignore */ nodeCryptoSpec);
    if (mod?.webcrypto?.subtle) {
      cachedWebCrypto = mod.webcrypto;
      return cachedWebCrypto;
    }
  } catch {
    // Ignore in pure browser environments
  }
  throw new Error('Web Crypto API (crypto.subtle) is not available in this runtime.');
}

function bytesToBase64(bytes) {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(base64) {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(base64, 'base64'));
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Derive a 256-bit AES-GCM CryptoKey from a passphrase using PBKDF2-SHA256 (100,000 iterations).
 * @param {string} passphrase
 * @param {Uint8Array} salt
 * @param {number} [iterations=100000]
 * @returns {Promise<CryptoKey>}
 */
export async function deriveVaultKey(passphrase, salt, iterations = PBKDF2_ITERATIONS) {
  if (!passphrase || typeof passphrase !== 'string') {
    throw new Error('A non-empty passphrase is required for PBKDF2 key derivation.');
  }
  const webCrypto = await getWebCrypto();
  const encoder = new TextEncoder();
  const keyMaterial = await webCrypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return webCrypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt arbitrary JSON-serializable vault data into an authenticated .lvvault envelope.
 * @param {object|string} payload
 * @param {string} passphrase
 * @returns {Promise<object>} Encrypted .lvvault envelope
 */
export async function encryptVault(payload, passphrase) {
  const webCrypto = await getWebCrypto();
  const salt = webCrypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = webCrypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await deriveVaultKey(passphrase, salt, PBKDF2_ITERATIONS);

  const encoder = new TextEncoder();
  const serialized = JSON.stringify({
    data: payload,
    timestamp: new Date().toISOString()
  });

  const ciphertextBuffer = await webCrypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoder.encode(serialized)
  );

  return {
    magic: VAULT_MAGIC,
    version: '2.0.0',
    kdf: 'PBKDF2-SHA256',
    cipher: 'AES-256-GCM',
    iterations: PBKDF2_ITERATIONS,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertextBuffer)),
    createdAt: new Date().toISOString()
  };
}

/**
 * Decrypt and authenticate a .lvvault envelope using the provided passphrase.
 * Throws if passphrase is wrong or ciphertext/IV/salt has been tampered with.
 * @param {object|string} envelopeInput
 * @param {string} passphrase
 * @returns {Promise<any>} Original decrypted payload
 */
export async function decryptVault(envelopeInput, passphrase) {
  const webCrypto = await getWebCrypto();
  const envelope =
    typeof envelopeInput === 'string' ? JSON.parse(envelopeInput) : envelopeInput;

  if (!envelope || envelope.magic !== VAULT_MAGIC) {
    throw new Error('Invalid .lvvault file format or unsupported vault header.');
  }

  const salt = base64ToBytes(envelope.salt);
  const iv = base64ToBytes(envelope.iv);
  const ciphertext = base64ToBytes(envelope.ciphertext);
  const iterations = Number(envelope.iterations) || PBKDF2_ITERATIONS;

  const key = await deriveVaultKey(passphrase, salt, iterations);

  let decryptedBuffer;
  try {
    decryptedBuffer = await webCrypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext
    );
  } catch {
    throw new Error('Vault decryption failed: invalid passphrase or tampered ciphertext.');
  }

  const decoder = new TextDecoder();
  const parsed = JSON.parse(decoder.decode(decryptedBuffer));
  return parsed.data;
}

/**
 * Serialize an encrypted vault envelope to a formatted .lvvault JSON string.
 * @param {object} envelope
 * @returns {string}
 */
export function serializeVaultFile(envelope) {
  return JSON.stringify(envelope, null, 2);
}

export class CryptoVault {
  constructor() {
    this.locked = true;
    this.activeEnvelope = null;
    this.unlockedData = null;
  }

  async lock(data, passphrase) {
    this.activeEnvelope = await encryptVault(data, passphrase);
    this.unlockedData = null;
    this.locked = true;
    return this.activeEnvelope;
  }

  async unlock(envelope, passphrase) {
    const data = await decryptVault(envelope || this.activeEnvelope, passphrase);
    this.unlockedData = data;
    this.locked = false;
    return data;
  }

  exportLvVault(envelope = this.activeEnvelope) {
    if (!envelope) {
      throw new Error('No encrypted vault envelope available to export.');
    }
    return serializeVaultFile(envelope);
  }
}
