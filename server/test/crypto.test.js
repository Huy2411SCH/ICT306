import './setup-env.js';
import { test } from 'node:test';
import assert from 'node:assert/strict';

const { encrypt, decrypt, encryptJson, decryptJson, deriveKey, newSalt, newVaultKey, wipe } =
  await import('../src/crypto.js');

test('AES-256-GCM round trip', () => {
  const key = newVaultKey();
  const blob = encryptJson(key, { password: 'hunter2' }, 'entry:1:abc');
  assert.deepEqual(decryptJson(key, blob, 'entry:1:abc'), { password: 'hunter2' });
});

test('same plaintext encrypts differently each time (random IV)', () => {
  const key = newVaultKey();
  const a = encrypt(key, Buffer.from('secret'), 'x');
  const b = encrypt(key, Buffer.from('secret'), 'x');
  assert.notDeepEqual(a, b);
});

test('tampered ciphertext is rejected (integrity)', () => {
  const key = newVaultKey();
  const blob = encrypt(key, Buffer.from('secret'), 'x');
  blob[blob.length - 1] ^= 0x01;
  assert.throws(() => decrypt(key, blob, 'x'));
});

test('ciphertext moved to another entry is rejected (AAD binding)', () => {
  const key = newVaultKey();
  const blob = encrypt(key, Buffer.from('secret'), 'entry:1:aaa');
  assert.throws(() => decrypt(key, blob, 'entry:2:aaa'));
});

test('wrong key is rejected', () => {
  const blob = encrypt(newVaultKey(), Buffer.from('secret'), 'x');
  assert.throws(() => decrypt(newVaultKey(), blob, 'x'));
});

test('PBKDF2 is deterministic per salt and differs across salts', async () => {
  const salt = newSalt();
  const a = await deriveKey('correct horse battery staple', salt);
  const b = await deriveKey('correct horse battery staple', salt);
  const c = await deriveKey('correct horse battery staple', newSalt());
  assert.deepEqual(a, b);
  assert.notDeepEqual(a, c);
  assert.equal(a.length, 32);
});

test('wipe zero-fills key material', () => {
  const key = newVaultKey();
  wipe(key);
  assert.ok(key.every((byte) => byte === 0));
});
