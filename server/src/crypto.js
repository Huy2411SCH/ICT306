// All cryptography uses Node's built-in, OpenSSL-backed `crypto` module. Nothing is hand-rolled.
import {
  pbkdf2,
  randomBytes,
  createCipheriv,
  createDecipheriv,
  timingSafeEqual,
} from 'node:crypto';
import { promisify } from 'node:util';

const pbkdf2Async = promisify(pbkdf2);

// OWASP Password Storage Cheat Sheet (2023+) recommends 600,000 iterations for PBKDF2-HMAC-SHA256.
export const PBKDF2_ITERATIONS = 600_000;
const KEY_LENGTH = 32; // 256-bit keys
const IV_LENGTH = 12; // 96-bit nonce, recommended for GCM
const TAG_LENGTH = 16;

export const newSalt = () => randomBytes(16);
export const newVaultKey = () => randomBytes(KEY_LENGTH);

/** Derive a 256-bit key from the master password. Async so it doesn't block the event loop. */
export function deriveKey(password, salt) {
  return pbkdf2Async(password.normalize('NFKC'), salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256');
}

/**
 * AES-256-GCM encrypt. Output layout: iv(12) | tag(16) | ciphertext.
 * `aad` binds the ciphertext to its context (e.g. owner + entry id) so blobs can't be swapped.
 */
export function encrypt(key, plaintext, aad) {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_LENGTH });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]);
}

/** AES-256-GCM decrypt. Throws if the data, tag or AAD were tampered with. */
export function decrypt(key, blob, aad) {
  const buf = Buffer.from(blob);
  const iv = buf.subarray(0, IV_LENGTH);
  const tag = buf.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const ciphertext = buf.subarray(IV_LENGTH + TAG_LENGTH);
  const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_LENGTH });
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function encryptJson(key, value, aad) {
  const plaintext = Buffer.from(JSON.stringify(value), 'utf8');
  try {
    return encrypt(key, plaintext, aad);
  } finally {
    wipe(plaintext);
  }
}

export function decryptJson(key, blob, aad) {
  const plaintext = decrypt(key, blob, aad);
  try {
    return JSON.parse(plaintext.toString('utf8'));
  } finally {
    wipe(plaintext);
  }
}

/** Constant-time comparison (prevents timing attacks on hash checks). */
export function safeEqual(a, b) {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

/**
 * Overwrite sensitive buffers with zeros. Best effort: JavaScript strings are immutable and
 * garbage-collected, so only Buffer-held secrets (keys, decrypted plaintext) can be wiped.
 */
export function wipe(...buffers) {
  for (const buf of buffers) if (buf) buf.fill(0);
}
