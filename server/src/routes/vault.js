import { Router } from 'express';
import { randomUUID } from 'node:crypto';
import { db } from '../db.js';
import { audit } from '../audit.js';
import { encryptJson, decryptJson } from '../crypto.js';
import { HttpError, str, requireUnlocked } from '../middleware.js';
import { analyseStrength, breachCount } from '../strength.js';

export const router = Router();
router.use(requireUnlocked);

const DAY = 24 * 60 * 60_000;
const entryAad = (userId, id) => `entry:${userId}:${id}`;

// Every query is scoped by user_id, so one user can never read another's entry by guessing its id (IDOR).
const listRows = db.prepare('SELECT * FROM entries WHERE user_id = ? ORDER BY updated_at DESC');
const getRow = db.prepare('SELECT * FROM entries WHERE id = ? AND user_id = ?');

function validateEntry(body) {
  return {
    title: str(body.title, { name: 'Title', min: 1, max: 100 }),
    username: str(body.username ?? '', { name: 'Username', max: 200 }),
    password: str(body.password, { name: 'Password', min: 1, max: 256 }),
    // Only http(s) URLs: blocks javascript: / data: links (stored XSS through the URL field).
    url: str(body.url ?? '', {
      name: 'URL', max: 500, pattern: /^(https?:\/\/[^\s<>"]+)?$/i,
      patternMessage: 'URL must start with http:// or https://',
    }),
    notes: str(body.notes ?? '', { name: 'Notes', max: 2000 }),
  };
}

function loadEntry(req, id) {
  const row = getRow.get(id, req.session.userId);
  if (!row) throw new HttpError(404, 'Entry not found');
  return { row, data: decryptJson(req.vaultKey, row.data, entryAad(req.session.userId, row.id)) };
}

function decryptAll(req) {
  return listRows.all(req.session.userId).map((row) => ({
    row,
    data: decryptJson(req.vaultKey, row.data, entryAad(req.session.userId, row.id)),
  }));
}

router.get('/', (req, res) => {
  // Passwords are not included in the list; they are fetched one at a time via /reveal.
  const entries = decryptAll(req).map(({ row, data }) => ({
    id: row.id,
    title: data.title,
    username: data.username,
    url: data.url,
    notes: data.notes,
    updatedAt: row.updated_at,
  }));
  res.json({ entries });
});

router.post('/', (req, res) => {
  const data = validateEntry(req.body);
  const id = randomUUID();
  const now = Date.now();
  db.prepare('INSERT INTO entries (id, user_id, data, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
    .run(id, req.session.userId, encryptJson(req.vaultKey, data, entryAad(req.session.userId, id)), now, now);
  audit(req, 'entry_created', { details: { entryId: id } });
  res.status(201).json({ id });
});

router.put('/:id', (req, res) => {
  const { row } = loadEntry(req, req.params.id);
  const data = validateEntry(req.body);
  db.prepare('UPDATE entries SET data = ?, updated_at = ? WHERE id = ? AND user_id = ?')
    .run(encryptJson(req.vaultKey, data, entryAad(req.session.userId, row.id)), Date.now(), row.id, req.session.userId);
  audit(req, 'entry_updated', { details: { entryId: row.id } });
  res.json({ ok: true });
});

router.delete('/:id', (req, res) => {
  const result = db.prepare('DELETE FROM entries WHERE id = ? AND user_id = ?').run(req.params.id, req.session.userId);
  if (result.changes === 0) throw new HttpError(404, 'Entry not found');
  audit(req, 'entry_deleted', { details: { entryId: req.params.id } });
  res.json({ ok: true });
});

// POST (not GET) so the password is never cached and the request is CSRF-checked.
router.post('/:id/reveal', (req, res) => {
  const { row, data } = loadEntry(req, req.params.id);
  audit(req, 'password_revealed', { details: { entryId: row.id } });
  res.json({ password: data.password });
});

/** Vault hygiene report: reused, weak, old and (optionally) breached passwords. */
router.get('/health', async (req, res) => {
  const all = decryptAll(req);
  const byPassword = new Map();
  for (const { data } of all) {
    byPassword.set(data.password, [...(byPassword.get(data.password) ?? []), data.title]);
  }
  const reused = [...byPassword.values()].filter((titles) => titles.length > 1);
  const weak = all
    .filter(({ data }) => analyseStrength(data.password).score < 3)
    .map(({ data }) => data.title);
  const old = all
    .filter(({ row }) => Date.now() - row.updated_at > 90 * DAY)
    .map(({ data }) => data.title);

  let breached = null;
  if (req.query.breach === '1') {
    breached = [];
    for (const [password, titles] of byPassword) {
      const { count } = await breachCount(password);
      if (count > 0) breached.push(...titles);
    }
  }

  const issues = reused.flat().length + weak.length + old.length + (breached?.length ?? 0);
  const score = all.length === 0 ? 100 : Math.max(0, Math.round(100 - (issues / all.length) * 50));
  res.json({ total: all.length, score, reused, weak, old, breached });
});
