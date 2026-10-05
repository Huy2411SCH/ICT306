// User behaviour analysis: rule-based anomaly detection over the audit log.
// Each rule maps to an attack it detects (see report, Threat Model section).
import { db } from './db.js';

const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;
const WEIGHT = { high: 3, medium: 2, low: 1 };

export const RULES = {
  bruteForce: '3+ failed logins for one account within 10 minutes',
  passwordSpraying: 'Failed logins for 5+ different accounts from one IP within 10 minutes',
  accountLocked: 'Account locked after repeated failures',
  newIp: 'Successful login from an IP address never used by this account before',
  unusualHour: 'Login more than 3 hours away from any of the user\'s usual login times',
  massReveal: '10+ passwords revealed within 5 minutes (possible vault exfiltration)',
  accessDenied: 'Attempt to reach a page the user\'s role does not allow',
};

/** Events within `windowMs` before `ts` (rows are sorted by ts). */
function windowed(rows, index, windowMs) {
  const end = rows[index].ts;
  const out = [];
  for (let i = index; i >= 0 && end - rows[i].ts <= windowMs; i--) out.push(rows[i]);
  return out;
}

const hourDistance = (a, b) => Math.min(Math.abs(a - b), 24 - Math.abs(a - b));

export function analyseBehaviour(now = Date.now()) {
  const rows = db
    .prepare('SELECT id, ts, user_id, username, event, ip FROM audit_log WHERE ts >= ? ORDER BY ts, id')
    .all(now - 30 * DAY);
  const alerts = [];
  const add = (rule, severity, row, message) =>
    alerts.push({ rule, severity, ts: row.ts, username: row.username, ip: row.ip, message, description: RULES[rule] });

  const fails = rows.filter((r) => r.event === 'login_failed');
  fails.forEach((row, i) => {
    const recent = windowed(fails, i, 10 * MINUTE);
    const sameUser = recent.filter((r) => r.username === row.username).length;
    if (sameUser === 3) add('bruteForce', 'high', row, `${sameUser} failed logins for "${row.username}" in 10 min`);
    const accounts = new Set(recent.filter((r) => r.ip === row.ip).map((r) => r.username));
    const prior = new Set(recent.slice(1).filter((r) => r.ip === row.ip).map((r) => r.username));
    if (accounts.size === 5 && prior.size === 4) {
      add('passwordSpraying', 'high', row, `IP ${row.ip} tried ${accounts.size} different accounts in 10 min`);
    }
  });

  const reveals = rows.filter((r) => r.event === 'password_revealed');
  reveals.forEach((row, i) => {
    const count = windowed(reveals, i, 5 * MINUTE).filter((r) => r.user_id === row.user_id).length;
    if (count === 10) add('massReveal', 'high', row, `"${row.username}" revealed ${count} passwords in 5 min`);
  });

  const history = new Map(); // user_id -> { ips:Set, hours:[] }
  for (const row of rows) {
    if (row.event === 'account_locked') add('accountLocked', 'high', row, `Account "${row.username}" was locked`);
    if (row.event === 'access_denied') add('accessDenied', 'medium', row, `"${row.username}" tried to access an admin-only resource`);
    if (row.event !== 'login_success') continue;

    const h = history.get(row.user_id) ?? { ips: new Set(), hours: [] };
    const hour = new Date(row.ts).getHours();
    if (h.ips.size > 0 && !h.ips.has(row.ip)) {
      add('newIp', 'medium', row, `"${row.username}" logged in from new IP ${row.ip}`);
    }
    if (h.hours.length >= 5 && h.hours.every((x) => hourDistance(x, hour) > 3)) {
      add('unusualHour', 'medium', row, `"${row.username}" logged in at an unusual time (${hour}:00)`);
    }
    h.ips.add(row.ip);
    h.hours.push(hour);
    history.set(row.user_id, h);
  }

  const riskByUser = {};
  for (const a of alerts) {
    if (!a.username) continue;
    riskByUser[a.username] = (riskByUser[a.username] ?? 0) + WEIGHT[a.severity];
  }
  alerts.sort((a, b) => b.ts - a.ts);
  return { alerts, riskByUser, rules: RULES };
}
