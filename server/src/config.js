// Central configuration. Secrets come from the environment (.env created by `npm run setup`),
// never from source code.

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}. Run "npm run setup" first.`);
  return value;
}

export const config = {
  port: Number(process.env.PORT ?? 3443),
  sessionSecret: required('SESSION_SECRET'),
  // 256-bit server key: encrypts TOTP secrets at rest and signs the audit-log hash chain.
  serverKey: Buffer.from(required('SERVER_KEY'), 'hex'),
  lockMinutes: Number(process.env.LOCK_MINUTES ?? 5),
  allowedOrigins: (process.env.ALLOWED_ORIGINS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),
  dbPath: process.env.DB_PATH ?? 'data/vault.db',
  cookieSecure: process.env.COOKIE_SECURE !== 'false',
  hibpEnabled: process.env.HIBP_DISABLED !== 'true',
  aiFeedback: process.env.AI_FEEDBACK === 'on',
  geminiApiKey: process.env.GEMINI_API_KEY,
  geminiModel: process.env.GEMINI_MODEL,
  authRateLimit: Number(process.env.AUTH_RATE_LIMIT ?? 20),
  maxFailedLogins: 5,
  lockoutMinutes: 15,
};

if (config.serverKey.length !== 32) {
  throw new Error('SERVER_KEY must be 32 bytes (64 hex characters).');
}
