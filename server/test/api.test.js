// Security tests for the HTTP API (authentication, 2FA, RBAC, CSRF, injection, IDOR, lockout).
import './setup-env.js';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { generate as totpCode } from 'otplib';

const { createApp } = await import('../src/app.js');
const { createUser } = await import('../src/users.js');
const { db } = await import('../src/db.js');
const { verifyChain } = await import('../src/audit.js');

const STRONG = 'violet-tractor-moonlight-42';
let server;
let base;

before(async () => {
  server = createApp().listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  base = `http://localhost:${server.address().port}`;
});
after(() => server.close());

/** Minimal cookie-keeping HTTP client that behaves like the browser app. */
function client({ origin = 'http://test.local' } = {}) {
  let cookie = '';
  return async (method, path, body) => {
    const headers = {};
    if (cookie) headers.cookie = cookie;
    if (method !== 'GET') {
      headers['content-type'] = 'application/json';
      if (origin) headers.origin = origin;
    }
    const res = await fetch(base + path, {
      method, headers, body: method === 'GET' ? undefined : JSON.stringify(body ?? {}),
    });
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) cookie = setCookie.split(';')[0];
    return { status: res.status, body: await res.json().catch(() => null) };
  };
}

/** Register + log in + complete 2FA. Returns the http client and TOTP secret. */
async function fullLogin(username, role = 'user') {
  if (role === 'admin') await createUser(username, STRONG, 'admin');
  else assert.equal((await client()('POST', '/api/auth/register', { username, password: STRONG })).status, 201);
  const http = client();
  const login = await http('POST', '/api/auth/login', { username, password: STRONG });
  assert.equal(login.body.next, 'totp-setup');
  const { body: { secret } } = await http('POST', '/api/auth/totp/setup');
  const code = await totpCode({ secret });
  const verify = await http('POST', '/api/auth/totp/verify', { code });
  assert.equal(verify.status, 200);
  return { http, secret, code };
}

test('vault requires authentication', async () => {
  const { status } = await client()('GET', '/api/vault');
  assert.equal(status, 401);
});

test('weak or breached master passwords are rejected at registration', async () => {
  const http = client();
  assert.equal((await http('POST', '/api/auth/register', { username: 'weak1', password: 'password1234' })).status, 400);
  assert.equal((await http('POST', '/api/auth/register', { username: 'weak2', password: 'short' })).status, 400);
});

test('CSRF: state-changing request without allowed Origin is blocked', async () => {
  const noOrigin = await client({ origin: null })('POST', '/api/auth/login', { username: 'x', password: 'y' });
  const evil = await client({ origin: 'https://evil.example' })('POST', '/api/auth/login', { username: 'x', password: 'y' });
  assert.equal(noOrigin.status, 403);
  assert.equal(evil.status, 403);
});

test('SQL injection in login is treated as plain data', async () => {
  const { status, body } = await client()('POST', '/api/auth/login', { username: "' OR 1=1 --", password: "' OR '1'='1" });
  assert.equal(status, 401);
  assert.equal(body.error, 'Invalid username or password');
});

test('password alone does not grant vault access (2FA enforced)', async () => {
  await client()('POST', '/api/auth/register', { username: 'twofa', password: STRONG });
  const http = client();
  await http('POST', '/api/auth/login', { username: 'twofa', password: STRONG });
  assert.equal((await http('GET', '/api/vault')).status, 401);
  await http('POST', '/api/auth/totp/setup');
  assert.equal((await http('POST', '/api/auth/totp/verify', { code: '000000' })).status, 401);
  assert.equal((await http('GET', '/api/vault')).status, 401);
});

test('full flow: entries are stored encrypted, never in plaintext', async () => {
  const { http } = await fullLogin('alice');
  const secretPw = 'Unique-Gmail-Pa55phrase!';
  const created = await http('POST', '/api/vault', { title: 'Gmail', username: 'alice@example.com', password: secretPw, url: 'https://mail.google.com' });
  assert.equal(created.status, 201);

  const list = await http('GET', '/api/vault');
  assert.equal(list.body.entries[0].title, 'Gmail');
  assert.equal(list.body.entries[0].password, undefined, 'list must not include passwords');

  const reveal = await http('POST', `/api/vault/${created.body.id}/reveal`);
  assert.equal(reveal.body.password, secretPw);

  const raw = db.prepare('SELECT data FROM entries WHERE id = ?').get(created.body.id);
  assert.ok(!Buffer.from(raw.data).toString('latin1').includes(secretPw), 'plaintext found in DB');
  assert.ok(!Buffer.from(raw.data).toString('latin1').includes('Gmail'), 'title found in DB');
});

test('javascript: URLs are rejected (stored XSS)', async () => {
  const { http } = await fullLogin('xss');
  const res = await http('POST', '/api/vault', { title: 't', password: 'p', url: 'javascript:alert(1)' });
  assert.equal(res.status, 400);
});

test('IDOR: a user cannot read or delete another user\'s entry', async () => {
  const { http: bob } = await fullLogin('bob');
  const { body } = await bob('POST', '/api/vault', { title: 'Bank', password: 'bob-secret' });
  const { http: mallory } = await fullLogin('mallory');
  assert.equal((await mallory('POST', `/api/vault/${body.id}/reveal`)).status, 404);
  assert.equal((await mallory('DELETE', `/api/vault/${body.id}`)).status, 404);
});

test('RBAC: normal users cannot reach admin endpoints, admins can', async () => {
  const { http: user } = await fullLogin('carol');
  assert.equal((await user('GET', '/api/admin/users')).status, 403);
  const { http: admin } = await fullLogin('root', 'admin');
  const users = await admin('GET', '/api/admin/users');
  assert.equal(users.status, 200);
  assert.ok(users.body.users.every((u) => !('auth_hash' in u) && !('wrapped_key' in u)));
});

test('TOTP codes cannot be replayed', async () => {
  const { code } = await fullLogin('replay');
  const http = client();
  await http('POST', '/api/auth/login', { username: 'replay', password: STRONG });
  const res = await http('POST', '/api/auth/totp/verify', { code });
  assert.equal(res.status, 401);
});

test('account locks after 5 failed logins', async () => {
  await client()('POST', '/api/auth/register', { username: 'victim', password: STRONG });
  const http = client();
  for (let i = 0; i < 5; i++) await http('POST', '/api/auth/login', { username: 'victim', password: 'wrong' });
  const res = await http('POST', '/api/auth/login', { username: 'victim', password: STRONG });
  assert.equal(res.status, 403);
});

test('manual lock wipes the key and blocks the vault until unlock', async () => {
  const { http } = await fullLogin('locker');
  await http('POST', '/api/auth/lock');
  assert.equal((await http('GET', '/api/vault')).status, 423);
  assert.equal((await http('POST', '/api/auth/unlock', { password: 'wrong' })).status, 401);
  assert.equal((await http('POST', '/api/auth/unlock', { password: STRONG })).status, 200);
  assert.equal((await http('GET', '/api/vault')).status, 200);
});

test('audit log hash chain verifies, and detects tampering', () => {
  assert.equal(verifyChain().valid, true);
  db.prepare("UPDATE audit_log SET event = 'nothing_to_see' WHERE id = 3").run();
  const result = verifyChain();
  assert.equal(result.valid, false);
  assert.equal(result.brokenAtId, 3);
});
