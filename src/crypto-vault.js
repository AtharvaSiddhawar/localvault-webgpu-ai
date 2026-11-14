
/**
 * LocalVault AI — Secure Cryptographic Vault
 *
 * New vaults:
 * - PBKDF2-SHA256 with 310,000 iterations
 * - AES-256-GCM authenticated encryption
 * - 16-byte random salt
 * - 12-byte random initialization vector
 *
 * No default passphrase is supplied or stored.
 */

const VAULT_MAGIC = 'LVVAULT_V2';
const VAULT_VERSION = '2.1.0';

const PBKDF2_ITERATIONS = 310000;
const MIN_ACCEPTED_ITERATIONS = 100000;
const MAX_ACCEPTED_ITERATIONS = 2000000;

const SALT_BYTES = 16;
const IV_BYTES = 12;
const AUTH_TAG_BITS = 128;

const MAX_PASSPHRASE_LENGTH = 1024;
const MAX_CIPHERTEXT_BYTES = 50 * 1024 * 1024;

let cachedWebCrypto = null;

async function getWebCrypto() {
  if (cachedWebCrypto?.subtle) {
    return cachedWebCrypto;
  }

  if (globalThis.crypto?.subtle) {
    cachedWebCrypto = globalThis.crypto;
    return cachedWebCrypto;
  }

  throw new Error(
    'Secure Web Crypto is unavailable. Use HTTPS or a supported modern browser.'
  );
}

/**
 * Decryption accepts existing non-empty passphrases for compatibility.
 * New encryption applies the stronger minimum-length requirement.
 */
function validatePassphrase(passphrase) {
  if (typeof passphrase !== 'string' || !passphrase.length) {
    throw new Error('Enter a master passphrase.');
  }

  if (passphrase.trim().length === 0) {
    throw new Error('The master passphrase cannot contain only whitespace.');
  }

  if (passphrase.length > MAX_PASSPHRASE_LENGTH) {
    throw new Error('Passphrase is too long.');
  }
}

function validateNewPassphrase(passphrase) {
  validatePassphrase(passphrase);

  if (passphrase.length < 12) {
    throw new Error(
      'Use a passphrase with at least 12 characters.'
    );
  }
}

function bytesToBase64(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError('Expected byte data.');
  }

  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }

  let binary = '';
  const chunkSize = 0x8000;

  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    const chunk = bytes.subarray(
      offset,
      Math.min(offset + chunkSize, bytes.length)
    );

    binary += String.fromCharCode(...chunk);
  }

  return btoa(binary);
}

function base64ToBytes(value, fieldName) {
  if (typeof value !== 'string' || !value.length) {
    throw new Error(`Vault file is missing ${fieldName}.`);
  }

  // Accept canonical standard Base64 only.
  const validBase64 =
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

  if (
    value.length % 4 !== 0 ||
    !validBase64.test(value)
  ) {
    throw new Error(`Vault file contains invalid ${fieldName}.`);
  }

  let bytes;

  try {
    if (typeof Buffer !== 'undefined') {
      bytes = new Uint8Array(
        Buffer.from(value, 'base64')
      );
    } else {
      const binary = atob(value);
      bytes = new Uint8Array(binary.length);

      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
    }
  } catch {
    throw new Error(`Vault file contains invalid ${fieldName}.`);
  }

  if (bytesToBase64(bytes) !== value) {
    throw new Error(`Vault file contains non-canonical ${fieldName}.`);
  }

  return bytes;
}

export async function deriveVaultKey(
  passphrase,
  salt,
  iterations = PBKDF2_ITERATIONS
) {
  validatePassphrase(passphrase);

  if (!(salt instanceof Uint8Array) || salt.length !== SALT_BYTES) {
    throw new Error('Invalid vault salt.');
  }

  if (
    !Number.isSafeInteger(iterations) ||
    iterations < MIN_ACCEPTED_ITERATIONS ||
    iterations > MAX_ACCEPTED_ITERATIONS
  ) {
    throw new Error('Unsupported or unsafe PBKDF2 iteration count.');
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
    {
      name: 'AES-GCM',
      length: 256
    },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptVault(payload, passphrase) {
  validateNewPassphrase(passphrase);

  if (payload === undefined) {
    throw new Error('There is no data to encrypt.');
  }

  let serialized;

  try {
    serialized = JSON.stringify({
      data: payload,
      timestamp: new Date().toISOString()
    });
  } catch {
    throw new Error('Vault data could not be serialized.');
  }

  if (typeof serialized !== 'string') {
    throw new Error('Vault data could not be serialized.');
  }

  const plaintext = new TextEncoder().encode(serialized);

  if (plaintext.byteLength > MAX_CIPHERTEXT_BYTES) {
    throw new Error('Vault payload exceeds the supported size limit.');
  }

  const webCrypto = await getWebCrypto();

  const salt = webCrypto.getRandomValues(
    new Uint8Array(SALT_BYTES)
  );

  const iv = webCrypto.getRandomValues(
    new Uint8Array(IV_BYTES)
  );

  const key = await deriveVaultKey(
    passphrase,
    salt,
    PBKDF2_ITERATIONS
  );

  const ciphertextBuffer = await webCrypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      tagLength: AUTH_TAG_BITS
    },
    key,
    plaintext
  );

  return {
    magic: VAULT_MAGIC,
    version: VAULT_VERSION,
    kdf: 'PBKDF2-SHA256',
    cipher: 'AES-256-GCM',
    iterations: PBKDF2_ITERATIONS,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(
      new Uint8Array(ciphertextBuffer)
    ),
    createdAt: new Date().toISOString()
  };
}

function validateEnvelope(envelope) {
  if (
    !envelope ||
    typeof envelope !== 'object' ||
    Array.isArray(envelope)
  ) {
    throw new Error('Invalid vault file.');
  }

  if (envelope.magic !== VAULT_MAGIC) {
    throw new Error('Unsupported vault file format.');
  }

  // Permit compatible v2 minor versions.
  if (
    typeof envelope.version !== 'string' ||
    !/^2\.\d+\.\d+$/.test(envelope.version)
  ) {
    throw new Error('Unsupported vault version.');
  }

  if (envelope.kdf !== 'PBKDF2-SHA256') {
    throw new Error('Unsupported vault key-derivation algorithm.');
  }

  if (envelope.cipher !== 'AES-256-GCM') {
    throw new Error('Unsupported vault encryption algorithm.');
  }

  if (
    !Number.isSafeInteger(envelope.iterations) ||
    envelope.iterations < MIN_ACCEPTED_ITERATIONS ||
    envelope.iterations > MAX_ACCEPTED_ITERATIONS
  ) {
    throw new Error('Invalid or unsafe PBKDF2 iteration count.');
  }

  const salt = base64ToBytes(envelope.salt, 'salt');
  const iv = base64ToBytes(envelope.iv, 'initialization vector');
  const ciphertext = base64ToBytes(
    envelope.ciphertext,
    'ciphertext'
  );

  if (salt.length !== SALT_BYTES) {
    throw new Error('Vault file has an invalid salt length.');
  }

  if (iv.length !== IV_BYTES) {
    throw new Error('Vault file has an invalid initialization vector length.');
  }

  if (
    ciphertext.length < 16 ||
    ciphertext.length > MAX_CIPHERTEXT_BYTES + 16
  ) {
    throw new Error('Vault ciphertext is incomplete or oversized.');
  }

  return {
    salt,
    iv,
    ciphertext,
    iterations: envelope.iterations
  };
}

export async function decryptVault(envelopeInput, passphrase) {
  validatePassphrase(passphrase);

  let envelope;

  try {
    envelope = typeof envelopeInput === 'string'
      ? JSON.parse(envelopeInput)
      : envelopeInput;
  } catch {
    throw new Error('Vault file is not valid JSON.');
  }

  const validated = validateEnvelope(envelope);
  const webCrypto = await getWebCrypto();

  const key = await deriveVaultKey(
    passphrase,
    validated.salt,
    validated.iterations
  );

  let decryptedBuffer;

  try {
    decryptedBuffer = await webCrypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: validated.iv,
        tagLength: AUTH_TAG_BITS
      },
      key,
      validated.ciphertext
    );
  } catch {
    throw new Error(
      'Vault authentication failed. Check the passphrase or file integrity.'
    );
  }

  try {
    const decoder = new TextDecoder('utf-8', { fatal: true });
    const parsed = JSON.parse(
      decoder.decode(decryptedBuffer)
    );

    if (
      !parsed ||
      typeof parsed !== 'object' ||
      !Object.prototype.hasOwnProperty.call(parsed, 'data')
    ) {
      throw new Error('Missing vault payload.');
    }

    return parsed.data;
  } catch {
    throw new Error('Decrypted vault payload is invalid.');
  }
}

export function serializeVaultFile(envelope) {
  validateEnvelope(envelope);
  return JSON.stringify(envelope, null, 2);
}

export class CryptoVault {
  constructor() {
    this.locked = true;
    this.activeEnvelope = null;
    this.unlockedData = null;
  }

  async lock(data, passphrase) {
    const envelope = await encryptVault(data, passphrase);

    this.activeEnvelope = envelope;
    this.unlockedData = null;
    this.locked = true;

    return envelope;
  }

  async unlock(envelope, passphrase) {
    const source = envelope || this.activeEnvelope;

    if (!source) {
      throw new Error('No vault file is available to unlock.');
    }

    const data = await decryptVault(source, passphrase);

    this.activeEnvelope = typeof source === 'string'
      ? JSON.parse(source)
      : source;

    this.unlockedData = data;
    this.locked = false;

    return data;
  }

  exportLvVault(envelope = this.activeEnvelope) {
    if (!envelope) {
      throw new Error('No encrypted vault is available to export.');
    }

    return serializeVaultFile(envelope);
  }

  clear() {
    this.unlockedData = null;
    this.activeEnvelope = null;
    this.locked = true;
  }
}
