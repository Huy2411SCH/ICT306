import https from 'node:https';
import { readFileSync } from 'node:fs';
import { config } from './config.js';
import { createApp } from './app.js';

const certDir = new URL('../certs/', import.meta.url);
let tls;
try {
  tls = {
    key: readFileSync(new URL('key.pem', certDir)),
    cert: readFileSync(new URL('cert.pem', certDir)),
  };
} catch {
  console.error('TLS certificate not found. Run "npm run setup" first.');
  process.exit(1);
}

https
  .createServer({ ...tls, minVersion: 'TLSv1.2' }, createApp())
  .listen(config.port, () => {
    console.log(`SecureVault running at https://localhost:${config.port}`);
    console.log(`Auto-lock after ${config.lockMinutes} min idle. AI feedback: ${config.aiFeedback ? 'on' : 'off'}.`);
  });
