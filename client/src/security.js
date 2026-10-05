// Client-side security helpers: clipboard auto-clear, password generator, idle auto-lock.
import { useEffect } from 'react';

export const CLIPBOARD_CLEAR_SECONDS = 15;
let clipboardTimer;

/** Copy a secret, then overwrite the clipboard after CLIPBOARD_CLEAR_SECONDS. */
export async function copySecret(text, onCleared) {
  await navigator.clipboard.writeText(text);
  clearTimeout(clipboardTimer);
  clipboardTimer = setTimeout(async () => {
    await clearClipboard();
    onCleared?.();
  }, CLIPBOARD_CLEAR_SECONDS * 1000);
}

export async function clearClipboard() {
  clearTimeout(clipboardTimer);
  try {
    await navigator.clipboard.writeText('');
  } catch {
    // Browsers only allow clipboard writes while the page is focused.
  }
}

const CHARSETS = {
  lower: 'abcdefghijkmnopqrstuvwxyz',
  upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
  digits: '23456789',
  symbols: '!@#$%^&*-_=+?',
};

/** Cryptographically secure generator (Web Crypto) with rejection sampling to avoid modulo bias. */
export function generatePassword(length = 20, sets = ['lower', 'upper', 'digits', 'symbols']) {
  const chars = sets.map((s) => CHARSETS[s]).join('');
  const limit = 256 - (256 % chars.length);
  const out = [];
  while (out.length < length) {
    for (const byte of crypto.getRandomValues(new Uint8Array(length * 2))) {
      if (byte < limit && out.length < length) out.push(chars[byte % chars.length]);
    }
  }
  return out.join('');
}

/** Calls onIdle after `minutes` without mouse/keyboard/touch activity. */
export function useIdleLock(enabled, minutes, onIdle) {
  useEffect(() => {
    if (!enabled) return undefined;
    let timer;
    const reset = () => {
      clearTimeout(timer);
      timer = setTimeout(onIdle, minutes * 60_000);
    };
    const events = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll'];
    events.forEach((e) => window.addEventListener(e, reset, { passive: true }));
    reset();
    return () => {
      clearTimeout(timer);
      events.forEach((e) => window.removeEventListener(e, reset));
    };
  }, [enabled, minutes, onIdle]);
}

/** Only http(s) links are rendered as clickable (defence in depth against javascript: URLs). */
export const safeHref = (url) => (/^https?:\/\//i.test(url ?? '') ? url : undefined);
