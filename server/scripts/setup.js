// One-time setup: generates random secrets (.env) and a self-signed TLS certificate.
// Never overwrites existing files: changing SERVER_KEY would make stored TOTP secrets unreadable.
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { generate } from 'selfsigned';

const envPath = new URL('../.env', import.meta.url);
const certDir = new URL('../certs/', import.meta.url);

if (existsSync(envPath)) {
  console.log('.env already exists, keeping it.');
} else {
  writeFileSync(
    envPath,
    [
      'PORT=3443',
      `SESSION_SECRET=${randomBytes(32).toString('hex')}`,
      `SERVER_KEY=${randomBytes(32).toString('hex')}`,
      'LOCK_MINUTES=5',
      'ALLOWED_ORIGINS=https://localhost:3443,http://localhost:5173',
      'DB_PATH=data/vault.db',
      '# AI password feedback (Google Gemini). Get a free key at https://aistudio.google.com',
      '# and copy a current model name from AI Studio (a "Flash" model is fast and cheap).',
      'AI_FEEDBACK=off',
      'GEMINI_API_KEY=',
      'GEMINI_MODEL=',
      '',
    ].join('\n'),
    { mode: 0o600 },
  );
  console.log('Created .env with fresh random secrets.');
}

if (existsSync(new URL('cert.pem', certDir))) {
  console.log('TLS certificate already exists, keeping it.');
} else {
  mkdirSync(certDir, { recursive: true });
  const pems = await generate([{ name: 'commonName', value: 'localhost' }], {
    keySize: 2048,
    algorithm: 'sha256',
    extensions: [
      { name: 'subjectAltName', altNames: [{ type: 2, value: 'localhost' }, { type: 7, ip: '127.0.0.1' }] },
    ],
  });
  writeFileSync(new URL('key.pem', certDir), pems.private, { mode: 0o600 });
  writeFileSync(new URL('cert.pem', certDir), pems.cert);
  console.log('Created self-signed TLS certificate in certs/.');
}

console.log('\nNext: npm run create-admin -- <username>');
