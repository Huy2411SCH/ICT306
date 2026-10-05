// In-memory store for unlocked vault keys. Keys never touch the database, cookies or logs.
// Each entry is wiped (zero-filled) on logout, manual lock, or after LOCK_MINUTES of inactivity.
import { randomUUID } from 'node:crypto';
import { wipe } from './crypto.js';
import { config } from './config.js';

const store = new Map();
const idleMs = () => config.lockMinutes * 60_000;

export function putKey(key, userId) {
  const ref = randomUUID();
  store.set(ref, { key, userId, lastActive: Date.now() });
  return ref;
}

/** Return the key and refresh its idle timer, or null if missing/expired. */
export function getKey(ref) {
  if (!hasKey(ref)) return null;
  const entry = store.get(ref);
  entry.lastActive = Date.now();
  return entry.key;
}

/** Check for a live key without refreshing the idle timer. */
export function hasKey(ref) {
  const entry = ref && store.get(ref);
  if (!entry) return false;
  if (Date.now() - entry.lastActive > idleMs()) {
    dropKey(ref);
    return false;
  }
  return true;
}

export function dropKey(ref) {
  const entry = ref && store.get(ref);
  if (entry) {
    wipe(entry.key);
    store.delete(ref);
  }
}

export function dropUserKeys(userId) {
  for (const [ref, entry] of store) if (entry.userId === userId) dropKey(ref);
}

// Auto-lock sweeper: wipes idle keys even if the user never sends another request.
setInterval(() => {
  for (const ref of store.keys()) hasKey(ref);
}, 30_000).unref();
