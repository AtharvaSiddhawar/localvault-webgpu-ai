/** Versioned authenticated-encryption vault using the Web Crypto API. */
const MAGIC = 'LVVAULT_V2';
const VERSION = '2.1.0';
const ITERATIONS = 310000;
const MIN_ITERATIONS = 100000;
const MAX_ITERATIONS = 2000000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const MAX_DATA_BYTES = 50 * 1024 * 1024;

function getCrypto() {
  if (globalThis.crypto?.subtle && globalThis.crypto?.getRandomValues) return globalThis.crypto;
  throw new Error('Web Crypto is unavailable. Use HTTPS or a supported modern browser.');
}
function validatePassphrase(value, creating = false) {
  if (typeof value !== 'string' || !value.trim()) throw new Error('Enter a master passphrase.');
  if (value.length > 1024) throw new Error('Passphrase is too long.');
  if (creating && value.length < 12) throw new Error('Use a passphrase with at least 12 characters.');
}
function toBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}
function fromBase64(value, field, maxDecodedBytes = MAX_DATA_BYTES + 16) {
  if (typeof value !== 'string' || !value || value.length > Math.ceil(maxDecodedBytes / 3) * 4 + 4 || value.length % 4 !== 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error(`Vault file contains invalid ${field}.`);
  let bytes;
  try { const binary = atob(value); bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0)); } catch { throw new Error(`Vault file contains invalid ${field}.`); }
  if (toBase64(bytes) !== value) throw new Error(`Vault file contains non-canonical ${field}.`);
  return bytes;
}
function validateEnvelope(input) {
  const envelope = typeof input === 'string' ? (() => { try { return JSON.parse(input); } catch { throw new Error('Vault file is not valid JSON.'); } })() : input;
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) throw new Error('Invalid vault file.');
  if (envelope.magic !== MAGIC || !/^2\.\d+\.\d+$/.test(String(envelope.version || ''))) throw new Error('Unsupported vault file format or version.');
  if (envelope.kdf !== 'PBKDF2-SHA256' || envelope.cipher !== 'AES-256-GCM') throw new Error('Unsupported vault algorithms.');
  if (!Number.isSafeInteger(envelope.iterations) || envelope.iterations < MIN_ITERATIONS || envelope.iterations > MAX_ITERATIONS) throw new Error('Invalid or unsafe PBKDF2 iteration count.');
  const salt = fromBase64(envelope.salt, 'salt', SALT_LENGTH);
  const iv = fromBase64(envelope.iv, 'initialization vector', IV_LENGTH);
  const ciphertext = fromBase64(envelope.ciphertext, 'ciphertext', MAX_DATA_BYTES + 16);
  if (salt.length !== SALT_LENGTH || iv.length !== IV_LENGTH || ciphertext.length < 16 || ciphertext.length > MAX_DATA_BYTES + 16) throw new Error('Vault file contains invalid or oversized cryptographic data.');
  return { envelope, salt, iv, ciphertext };
}

export async function deriveVaultKey(passphrase, salt, iterations = ITERATIONS) {
  validatePassphrase(passphrase);
  if (!(salt instanceof Uint8Array) || salt.length !== SALT_LENGTH) throw new Error('Invalid vault salt.');
  if (!Number.isSafeInteger(iterations) || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) throw new Error('Unsupported or unsafe PBKDF2 iteration count.');
  const crypto = getCrypto();
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export async function encryptVault(payload, passphrase) {
  validatePassphrase(passphrase, true);
  if (payload === undefined) throw new Error('There is no data to encrypt.');
  let serialized;
  try {
    if (JSON.stringify(payload) === undefined) throw new Error('unsupported payload');
    serialized = JSON.stringify({ data: payload, createdAt: new Date().toISOString() });
  } catch { throw new Error('Vault data could not be serialized.'); }
  if (typeof serialized !== 'string') throw new Error('Vault data could not be serialized.');
  const plaintext = new TextEncoder().encode(serialized);
  if (plaintext.byteLength > MAX_DATA_BYTES) throw new Error('Vault payload exceeds the supported size limit.');
  const crypto = getCrypto();
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const key = await deriveVaultKey(passphrase, salt, ITERATIONS);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, plaintext);
  return { magic: MAGIC, version: VERSION, kdf: 'PBKDF2-SHA256', cipher: 'AES-256-GCM', iterations: ITERATIONS, salt: toBase64(salt), iv: toBase64(iv), ciphertext: toBase64(new Uint8Array(encrypted)), createdAt: new Date().toISOString() };
}

export async function decryptVault(envelopeInput, passphrase) {
  validatePassphrase(passphrase);
  const { envelope, salt, iv, ciphertext } = validateEnvelope(envelopeInput);
  const key = await deriveVaultKey(passphrase, salt, envelope.iterations);
  let plaintext;
  try { plaintext = await getCrypto().subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, ciphertext); }
  catch { throw new Error('Vault authentication failed. Check the passphrase or file integrity.'); }
  try {
    const decoded = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext));
    if (!decoded || typeof decoded !== 'object' || !Object.hasOwn(decoded, 'data')) throw new Error('Missing data payload.');
    return decoded.data;
  } catch { throw new Error('Decrypted vault payload is invalid.'); }
}

export function serializeVaultFile(envelope) {
  validateEnvelope(envelope);
  return JSON.stringify(envelope, null, 2);
}

export class CryptoVault {
  constructor() { this.locked = true; this.activeEnvelope = null; this.unlockedData = null; }
  async lock(data, passphrase) { const envelope = await encryptVault(data, passphrase); this.activeEnvelope = envelope; this.unlockedData = null; this.locked = true; return envelope; }
  async unlock(envelope, passphrase) { const source = envelope || this.activeEnvelope; if (!source) throw new Error('No vault file is available to unlock.'); const data = await decryptVault(source, passphrase); this.activeEnvelope = typeof source === 'string' ? JSON.parse(source) : source; this.unlockedData = data; this.locked = false; return data; }
  exportLvVault(envelope = this.activeEnvelope) { if (!envelope) throw new Error('No encrypted vault is available to export.'); return serializeVaultFile(envelope); }
  clear() { this.unlockedData = null; this.activeEnvelope = null; this.locked = true; }
}
