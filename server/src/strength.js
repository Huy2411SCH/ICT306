// Password strength analysis (zxcvbn) and compromised-password checks (HIBP k-anonymity).
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import zxcvbn from 'zxcvbn';
import { config } from './config.js';

const COMMON = new Set(
  readFileSync(new URL('../data/common-passwords.txt', import.meta.url), 'utf8')
    .split(/\r?\n/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean),
);

/**
 * Returns zxcvbn's verdict plus `features`: derived statistics that describe the password's
 * weaknesses WITHOUT containing any part of it. Only `features` is ever sent to the AI model.
 */
export function analyseStrength(password, userInputs = []) {
  const r = zxcvbn(password, userInputs);
  const features = {
    length: [...password].length,
    hasLower: /[a-z]/.test(password),
    hasUpper: /[A-Z]/.test(password),
    hasDigit: /\d/.test(password),
    hasSymbol: /[^A-Za-z0-9]/.test(password),
    score: r.score,
    guessesLog10: Math.round(r.guesses_log10 * 10) / 10,
    crackTimeOfflineSlowHash: r.crack_times_display.offline_slow_hashing_1e4_per_second,
    crackTimeOnline: r.crack_times_display.online_no_throttling_10_per_second,
    patterns: [...new Set(r.sequence.map((m) => m.pattern))],
    dictionaries: [...new Set(r.sequence.map((m) => m.dictionary_name).filter(Boolean))],
    usesLeetSpeak: r.sequence.some((m) => m.l33t),
    reversedWord: r.sequence.some((m) => m.reversed),
    containsUserInfo: r.sequence.some((m) => m.dictionary_name === 'user_inputs'),
  };
  return {
    score: r.score,
    crackTime: features.crackTimeOfflineSlowHash,
    warning: r.feedback.warning,
    suggestions: r.feedback.suggestions,
    features,
  };
}

/**
 * Has this password appeared in a data breach?
 * Uses the Have I Been Pwned range API: only the first 5 hex chars of the SHA-1 hash leave the
 * server, and the match happens locally (k-anonymity). Falls back to a bundled common-password
 * list when offline.
 */
export async function breachCount(password) {
  const localHit = COMMON.has(password.toLowerCase());
  if (!config.hibpEnabled) return { count: localHit ? 1 : 0, source: 'local' };

  const sha1 = createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);
  try {
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'Add-Padding': 'true', 'User-Agent': 'SecureVault-student-project' },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) throw new Error(`HIBP status ${res.status}`);
    for (const line of (await res.text()).split('\n')) {
      const [hashSuffix, count] = line.trim().split(':');
      if (hashSuffix === suffix) return { count: Number(count), source: 'hibp' };
    }
    return { count: localHit ? 1 : 0, source: 'hibp' };
  } catch {
    return { count: localHit ? 1 : 0, source: 'local' };
  }
}

/** Rule-based advice used when AI feedback is disabled or unavailable. */
export function localAdvice(f, breaches = 0) {
  const tips = [];
  if (breaches > 0) tips.push(`This password appears in ${breaches.toLocaleString()} breach records. Never use it.`);
  if (f.length < 12) tips.push(`It is only ${f.length} characters. Aim for 14+ (a 4-5 word passphrase is easy to remember).`);
  if (f.dictionaries.includes('passwords')) tips.push('It is built on a commonly used password, which attackers try first.');
  if (f.dictionaries.some((d) => d !== 'passwords' && d !== 'user_inputs')) tips.push('It contains dictionary words or names. Combine several unrelated words instead of one.');
  if (f.usesLeetSpeak) tips.push('Swapping letters for symbols (p@ssw0rd) is well known to cracking tools and adds little strength.');
  if (f.patterns.includes('date')) tips.push('Dates (birthdays, years) are easy to guess. Remove them.');
  if (f.patterns.includes('spatial')) tips.push('Keyboard patterns like "qwerty" or "asdf" are among the first guesses.');
  if (f.patterns.includes('repeat') || f.patterns.includes('sequence')) tips.push('Repeated or sequential characters (aaa, 123, abc) add almost no strength.');
  if (f.containsUserInfo) tips.push('It contains your username. Avoid personal information.');
  if (tips.length === 0 && f.score < 4) tips.push('Make it longer. Length matters more than complexity.');
  if (tips.length === 0) tips.push('Strong password. Make sure it is unique to this account.');
  return tips;
}
