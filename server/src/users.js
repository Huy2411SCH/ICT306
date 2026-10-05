// User account service: key hierarchy, password verification and lockout.
//
//   master password --PBKDF2(auth_salt)--> auth hash (stored, used only to verify logins)
//   master password --PBKDF2(kek_salt)---> KEK --AES-GCM unwrap--> vault key --> entries
//
// Changing the master password only re-wraps the vault key; entries are never re-encrypted.
import { randomBytes } from 'node:crypto';
import { db } from './db.js';
import { config } from './config.js';
import {
  deriveKey, newSalt, newVaultKey, encrypt, decrypt, safeEqual, wipe,
} from './crypto.js';
import { audit } from './audit.js';

export const USERNAME_RE = /^[a-zA-Z0-9_.-]{3,32}$/;

export const findUserByName = db.prepare('SELECT * FROM users WHERE username = ?');
export const findUserById = db.prepare('SELECT * FROM users WHERE id = ?');

const vaultKeyAad = (username) => `vault-key:${username}`;
const DUMMY_SALT = randomBytes(16);

async function wrapNewCredentials(username, password, vaultKey) {
  const authSalt = newSalt();
  const kekSalt = newSalt();
  const authHash = await deriveKey(password, authSalt);
  const kek = await deriveKey(password, kekSalt);
  try {
    return { authSalt, authHash, kekSalt, wrappedKey: encrypt(kek, vaultKey, vaultKeyAad(username)) };
  } finally {
    wipe(kek);
  }
}

export async function createUser(username, password, role) {
  const vaultKey = newVaultKey();
  try {
    const c = await wrapNewCredentials(username, password, vaultKey);
    db.prepare(`
      INSERT INTO users (username, role, auth_salt, auth_hash, kek_salt, wrapped_key, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run(username, role, c.authSalt, c.authHash, c.kekSalt, c.wrappedKey, Date.now());
  } finally {
    wipe(vaultKey);
  }
}

/** Constant-work password check: unknown users still cost one PBKDF2 run (no timing oracle). */
export async function verifyPassword(user, password) {
  if (!user) {
    await deriveKey(password, DUMMY_SALT);
    return false;
  }
  const candidate = await deriveKey(password, user.auth_salt);
  try {
    return safeEqual(candidate, user.auth_hash);
  } finally {
    wipe(candidate);
  }
}

export async function unwrapVaultKey(user, password) {
  const kek = await deriveKey(password, user.kek_salt);
  try {
    return decrypt(kek, user.wrapped_key, vaultKeyAad(user.username));
  } finally {
    wipe(kek);
  }
}

export async function changeMasterPassword(user, newPassword, vaultKey) {
  const c = await wrapNewCredentials(user.username, newPassword, vaultKey);
  db.prepare(`
    UPDATE users SET auth_salt = ?, auth_hash = ?, kek_salt = ?, wrapped_key = ? WHERE id = ?`)
    .run(c.authSalt, c.authHash, c.kekSalt, c.wrappedKey, user.id);
}

export const isLocked = (user) => Boolean(user.locked_until && user.locked_until > Date.now());

/** Record a failed attempt; lock the account after maxFailedLogins. Returns true if now locked. */
export function registerFailure(req, user, reason) {
  audit(req, 'login_failed', { userId: user.id, username: user.username, details: { reason } });
  const attempts = user.failed_attempts + 1;
  if (attempts >= config.maxFailedLogins) {
    const until = Date.now() + config.lockoutMinutes * 60_000;
    db.prepare('UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?').run(until, user.id);
    audit(req, 'account_locked', { userId: user.id, username: user.username, details: { attempts } });
    return true;
  }
  db.prepare('UPDATE users SET failed_attempts = ? WHERE id = ?').run(attempts, user.id);
  return false;
}

export function clearFailures(userId) {
  db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?').run(userId);
}
