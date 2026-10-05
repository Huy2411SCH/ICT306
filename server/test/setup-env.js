// Test environment: in-memory DB, throwaway secrets, no network calls.
import { randomBytes } from 'node:crypto';

process.env.SESSION_SECRET = randomBytes(32).toString('hex');
process.env.SERVER_KEY = randomBytes(32).toString('hex');
process.env.DB_PATH = ':memory:';
process.env.COOKIE_SECURE = 'false';
process.env.HIBP_DISABLED = 'true';
process.env.ALLOWED_ORIGINS = 'http://test.local';
process.env.AI_FEEDBACK = 'off';
process.env.AUTH_RATE_LIMIT = '1000';
