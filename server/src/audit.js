// Tamper-evident security log. Each row stores HMAC(SERVER_KEY, previous hash + row contents),
// so editing or deleting a row in the middle breaks the chain (STRIDE: Repudiation).
import { createHmac } from 'node:crypto';
import { db } from './db.js';
import { config } from './config.js';

const insert = db.prepare(`
  INSERT INTO audit_log (ts, user_id, username, event, ip, user_agent, details, prev_hash, hash)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
const lastHash = db.prepare('SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1');

function rowHash(prevHash, row) {
  const payload = JSON.stringify([
    prevHash, row.ts, row.user_id, row.username, row.event, row.ip, row.user_agent, row.details,
  ]);
  return createHmac('sha256', config.serverKey).update(payload).digest('hex');
}

export function audit(req, event, { userId, username, details } = {}) {
  const row = {
    ts: Date.now(),
    user_id: userId ?? req?.session?.userId ?? null,
    username: username ?? req?.session?.username ?? null,
    event,
    ip: req?.ip ?? null,
    user_agent: req?.get?.('user-agent')?.slice(0, 200) ?? null,
    details: details ? JSON.stringify(details) : null,
  };
  const prevHash = lastHash.get()?.hash ?? 'GENESIS';
  insert.run(
    row.ts, row.user_id, row.username, row.event, row.ip, row.user_agent, row.details,
    prevHash, rowHash(prevHash, row),
  );
}

export function verifyChain() {
  let prevHash = 'GENESIS';
  let checked = 0;
  for (const row of db.prepare('SELECT * FROM audit_log ORDER BY id').iterate()) {
    if (row.prev_hash !== prevHash || row.hash !== rowHash(prevHash, row)) {
      return { valid: false, checked, brokenAtId: row.id };
    }
    prevHash = row.hash;
    checked++;
  }
  return { valid: true, checked };
}
