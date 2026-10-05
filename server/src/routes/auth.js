import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import QRCode from 'qrcode';
import { generateSecret, generateURI, verify as verifyTotp } from 'otplib';
import { db } from '../db.js';
import { config } from '../config.js';
import { audit } from '../audit.js';
import { encrypt, decrypt, wipe } from '../crypto.js';
import { putKey, dropKey, hasKey } from '../keystore.js';
import { HttpError, str, requireStage, requireUnlocked } from '../middleware.js';
import { analyseStrength, breachCount } from '../strength.js';
import {
  USERNAME_RE, findUserByName, findUserById, createUser, verifyPassword, unwrapVaultKey,
  changeMasterPassword, isLocked, registerFailure, clearFailures,
} from '../users.js';

export const router = Router();

// Brute-force protection per IP (account lockout below adds per-account protection).
const authLimiter = rateLimit({
  windowMs: 15 * 60_000,
  limit: config.authRateLimit,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many attempts. Try again later.' },
  handler: (req, res, _next, options) => {
    audit(req, 'rate_limited', { details: { path: req.originalUrl } });
    res.status(options.statusCode).json(options.message);
  },
});

const regenerate = (req) =>
  new Promise((resolve, reject) => req.session.regenerate((err) => (err ? reject(err) : resolve())));

const totpAad = (username) => `totp:${username}`;
const GENERIC_LOGIN_ERROR = 'Invalid username or password';

/** NIST SP 800-63B style policy: length + blocklist + strength estimate, no composition rules. */
async function assertStrongMasterPassword(password, username) {
  const strength = analyseStrength(password, [username]);
  if (strength.score < 3) {
    throw new HttpError(400, `Master password is too weak. ${strength.warning || strength.suggestions[0] || 'Make it longer.'}`);
  }
  const breach = await breachCount(password);
  if (breach.count > 0) {
    throw new HttpError(400, 'This password has appeared in a known data breach. Choose another.');
  }
}

router.post('/register', authLimiter, async (req, res) => {
  const username = str(req.body.username, {
    name: 'Username', min: 3, max: 32, pattern: USERNAME_RE,
    patternMessage: 'Username may contain letters, numbers, dot, dash and underscore only',
  });
  const password = str(req.body.password, { name: 'Master password', min: 12, max: 128 });
  await assertStrongMasterPassword(password, username);
  if (findUserByName.get(username)) throw new HttpError(409, 'Username is not available');
  await createUser(username, password, 'user');
  audit(req, 'register', { username });
  res.status(201).json({ ok: true });
});

router.post('/login', authLimiter, async (req, res) => {
  const username = str(req.body.username, { name: 'Username', min: 1, max: 32 });
  const password = str(req.body.password, { name: 'Password', min: 1, max: 128 });
  const user = findUserByName.get(username);

  if (user && isLocked(user)) {
    audit(req, 'login_blocked', { userId: user.id, username, details: { reason: 'account_locked' } });
    throw new HttpError(403, 'Account temporarily locked after too many failed attempts. Try again later.');
  }
  if (!(await verifyPassword(user, password))) {
    if (user) registerFailure(req, user, 'bad_password');
    else audit(req, 'login_failed', { username, details: { reason: 'unknown_user' } });
    throw new HttpError(401, GENERIC_LOGIN_ERROR);
  }

  const vaultKey = await unwrapVaultKey(user, password);
  await regenerate(req); // prevent session fixation
  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.role = user.role;
  req.session.keyRef = putKey(vaultKey, user.id);
  req.session.stage = user.totp_enabled ? 'totp' : 'totp-setup';
  audit(req, 'login_password_ok');
  res.json({ next: req.session.stage });
});

router.post('/totp/setup', requireStage('totp-setup'), async (req, res) => {
  req.session.pendingTotp ??= generateSecret();
  const uri = generateURI({ issuer: 'SecureVault', label: req.session.username, secret: req.session.pendingTotp });
  const qr = await QRCode.toDataURL(uri, {
    width: 320, // large enough for phone cameras to read from a monitor
    margin: 4, // quiet zone required by the QR spec
    errorCorrectionLevel: 'M',
    color: { dark: '#000000', light: '#ffffff' },
  });
  res.json({ qr, secret: req.session.pendingTotp });
});

router.post('/totp/verify', authLimiter, requireStage('totp', 'totp-setup'), async (req, res) => {
  const code = str(req.body.code, { name: 'Code', min: 6, max: 6, pattern: /^\d{6}$/ });
  const user = findUserById.get(req.session.userId);
  const settingUp = req.session.stage === 'totp-setup';

  let secret = req.session.pendingTotp;
  if (!settingUp) {
    const plain = decrypt(config.serverKey, user.totp_secret_enc, totpAad(user.username));
    secret = plain.toString('utf8');
    wipe(plain);
  }
  if (!secret) throw new HttpError(400, 'Start 2FA setup first');

  // Accept the previous/current 30s window, and never accept the same window twice (replay).
  const result = await verifyTotp({ secret, token: code, epochTolerance: [30, 0] });
  const step = Math.floor(Date.now() / 30_000) + (result.delta ?? 0);
  if (!result.valid || step <= user.totp_last_step) {
    const locked = registerFailure(req, user, 'bad_totp');
    if (locked) {
      dropKey(req.session.keyRef);
      req.session.destroy(() => {});
      throw new HttpError(403, 'Account temporarily locked after too many failed attempts.');
    }
    throw new HttpError(401, 'Invalid or expired code');
  }

  if (settingUp) {
    const enc = encrypt(config.serverKey, Buffer.from(secret, 'utf8'), totpAad(user.username));
    db.prepare('UPDATE users SET totp_secret_enc = ?, totp_enabled = 1 WHERE id = ?').run(enc, user.id);
    audit(req, 'totp_enabled');
  }
  db.prepare('UPDATE users SET totp_last_step = ? WHERE id = ?').run(step, user.id);
  clearFailures(user.id);

  const { userId, username, role, keyRef } = req.session;
  await regenerate(req); // new session ID on privilege change
  Object.assign(req.session, { userId, username, role, keyRef, stage: 'full' });
  audit(req, 'login_success');
  res.json({ ok: true });
});

router.get('/me', (req, res) => {
  let { stage } = req.session;
  if (stage === 'full' && !hasKey(req.session.keyRef)) stage = req.session.stage = 'locked';
  const user = stage && findUserById.get(req.session.userId);
  if (!user) return res.json({ stage: null });
  res.json({
    stage,
    username: user.username,
    role: user.role,
    lockMinutes: config.lockMinutes,
  });
});

router.post('/lock', requireStage('full', 'locked'), (req, res) => {
  dropKey(req.session.keyRef);
  req.session.stage = 'locked';
  audit(req, 'vault_locked');
  res.json({ ok: true });
});

router.post('/unlock', authLimiter, requireStage('full', 'locked'), async (req, res) => {
  const password = str(req.body.password, { name: 'Password', min: 1, max: 128 });
  const user = findUserById.get(req.session.userId);
  if (!(await verifyPassword(user, password))) {
    if (registerFailure(req, user, 'bad_unlock_password')) {
      dropKey(req.session.keyRef);
      req.session.destroy(() => {});
      throw new HttpError(403, 'Account temporarily locked after too many failed attempts.');
    }
    throw new HttpError(401, 'Incorrect master password');
  }
  clearFailures(user.id);
  dropKey(req.session.keyRef);
  req.session.keyRef = putKey(await unwrapVaultKey(user, password), user.id);
  req.session.role = user.role;
  req.session.stage = 'full';
  audit(req, 'vault_unlocked');
  res.json({ ok: true });
});

router.post('/change-password', authLimiter, requireUnlocked, async (req, res) => {
  const current = str(req.body.currentPassword, { name: 'Current password', min: 1, max: 128 });
  const next = str(req.body.newPassword, { name: 'New master password', min: 12, max: 128 });
  const user = findUserById.get(req.session.userId);
  if (!(await verifyPassword(user, current))) {
    registerFailure(req, user, 'bad_password_change');
    throw new HttpError(401, 'Current password is incorrect');
  }
  await assertStrongMasterPassword(next, user.username);
  await changeMasterPassword(user, next, req.vaultKey);
  audit(req, 'master_password_changed');
  res.json({ ok: true });
});

router.post('/logout', (req, res) => {
  dropKey(req.session.keyRef);
  if (req.session.userId) audit(req, 'logout');
  req.session.destroy(() => {
    res.clearCookie('vault.sid');
    res.json({ ok: true });
  });
});
