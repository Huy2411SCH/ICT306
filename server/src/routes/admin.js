// Admin area. Admins manage accounts and review security events, but there is deliberately
// NO endpoint that can read another user's vault: separation of duties + least privilege.
import { Router } from 'express';
import { db } from '../db.js';
import { audit, verifyChain } from '../audit.js';
import { HttpError, requireUnlocked, requireRole } from '../middleware.js';
import { analyseBehaviour } from '../behaviour.js';
import { dropUserKeys } from '../keystore.js';

export const router = Router();
router.use(requireUnlocked, requireRole('admin'));

const parseId = (value) => {
  const id = Number(value);
  if (!Number.isInteger(id) || id < 1) throw new HttpError(400, 'Invalid user id');
  return id;
};

router.get('/users', (req, res) => {
  const users = db.prepare(`
    SELECT u.id, u.username, u.role, u.totp_enabled, u.failed_attempts, u.locked_until, u.created_at,
           (SELECT COUNT(*) FROM entries e WHERE e.user_id = u.id) AS entry_count
    FROM users u ORDER BY u.id`).all();
  res.json({
    users: users.map((u) => ({
      ...u,
      totp_enabled: Boolean(u.totp_enabled),
      locked: Boolean(u.locked_until && u.locked_until > Date.now()),
    })),
  });
});

router.post('/users/:id/unlock', (req, res) => {
  const id = parseId(req.params.id);
  const result = db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?').run(id);
  if (result.changes === 0) throw new HttpError(404, 'User not found');
  audit(req, 'admin_unlocked_account', { details: { targetUserId: id } });
  res.json({ ok: true });
});

router.put('/users/:id/role', (req, res) => {
  const id = parseId(req.params.id);
  const { role } = req.body;
  if (!['admin', 'user'].includes(role)) throw new HttpError(400, 'Role must be admin or user');
  if (id === req.session.userId) throw new HttpError(400, 'You cannot change your own role');
  const result = db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, id);
  if (result.changes === 0) throw new HttpError(404, 'User not found');
  dropUserKeys(id); // force the user to log in again so the new role takes effect
  audit(req, 'admin_changed_role', { details: { targetUserId: id, role } });
  res.json({ ok: true });
});

router.get('/audit', (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 200, 1), 1000);
  const events = db
    .prepare('SELECT id, ts, username, event, ip, user_agent, details FROM audit_log ORDER BY id DESC LIMIT ?')
    .all(limit);
  res.json({ events });
});

router.get('/audit/verify', (req, res) => {
  const result = verifyChain();
  audit(req, 'audit_chain_verified', { details: result });
  res.json(result);
});

router.get('/alerts', (req, res) => {
  res.json(analyseBehaviour());
});
