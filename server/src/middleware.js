import { config } from './config.js';
import { getKey } from './keystore.js';
import { audit } from './audit.js';
import { findUserById } from './users.js';

export class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/** Allow-list validation for string inputs. Rejects wrong types, lengths and formats. */
export function str(value, { name, min = 0, max, pattern, patternMessage }) {
  if (typeof value !== 'string') throw new HttpError(400, `${name} must be text`);
  if (value.length < min || value.length > max) {
    throw new HttpError(400, `${name} must be ${min}-${max} characters`);
  }
  if (pattern && !pattern.test(value)) {
    throw new HttpError(400, patternMessage ?? `${name} has an invalid format`);
  }
  return value;
}

/**
 * Session stages: 'totp-setup' | 'totp' (password ok, 2FA pending) -> 'full' -> 'locked'.
 * Nothing in the vault is reachable until the 'full' stage.
 */
export const requireStage = (...stages) => (req, res, next) => {
  if (!stages.includes(req.session.stage)) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
};

/** Fully authenticated AND the vault key is still in memory (not auto-locked). */
export function requireUnlocked(req, res, next) {
  if (req.session.stage !== 'full' && req.session.stage !== 'locked') {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const key = getKey(req.session.keyRef);
  if (!key) {
    req.session.stage = 'locked';
    return res.status(423).json({ error: 'Vault is locked' });
  }
  req.vaultKey = key;
  next();
}

/** RBAC. Always used after requireUnlocked. The role is read from the DB, never trusted from the session. */
export const requireRole = (role) => (req, res, next) => {
  const user = findUserById.get(req.session.userId);
  if (!user || user.role !== role) {
    audit(req, 'access_denied', { details: { path: req.originalUrl, requiredRole: role } });
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
};

/**
 * CSRF defence (in addition to SameSite=Strict cookies): state-changing requests must come
 * from an allow-listed Origin and be JSON, which a cross-site HTML form cannot send.
 */
export function originCheck(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const origin = req.get('origin');
  if (!origin || !config.allowedOrigins.includes(origin)) {
    audit(req, 'csrf_blocked', { details: { origin: origin ?? null, path: req.originalUrl } });
    return res.status(403).json({ error: 'Forbidden' });
  }
  if (!req.is('application/json')) {
    return res.status(415).json({ error: 'Content-Type must be application/json' });
  }
  next();
}

/** Fail securely: expected errors get their message, everything else a generic one. */
export function errorHandler(err, req, res, _next) {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON' });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Request too large' });
  console.error(err); // details stay server-side
  res.status(500).json({ error: 'Internal error' });
}
