import express from 'express';
import session from 'express-session';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { config } from './config.js';
import { originCheck, errorHandler } from './middleware.js';
import { router as authRouter } from './routes/auth.js';
import { router as vaultRouter } from './routes/vault.js';
import { router as toolsRouter } from './routes/tools.js';
import { router as adminRouter } from './routes/admin.js';

const clientDist = fileURLToPath(new URL('../../client/dist', import.meta.url));

export function createApp() {
  const app = express();

  // Security headers: strict CSP (no inline scripts), HSTS, no framing, no MIME sniffing, etc.
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"],
          imgSrc: ["'self'", 'data:'],
          fontSrc: ["'self'"], // helmet's default also allows any https: host (flagged by ZAP)
          connectSrc: ["'self'"],
          objectSrc: ["'none'"],
          frameAncestors: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
        },
      },
      crossOriginEmbedderPolicy: true, // require-corp: only same-origin or opted-in resources
      referrerPolicy: { policy: 'no-referrer' },
    }),
  );

  // Deny browser features the app never uses (clipboard-write stays allowed for copy).
  app.use((req, res, next) => {
    res.set(
      'Permissions-Policy',
      'camera=(), microphone=(), geolocation=(), payment=(), usb=(), clipboard-read=(), interest-cohort=()',
    );
    next();
  });

  app.use(express.json({ limit: '10kb' }));

  app.use(
    session({
      name: 'vault.sid',
      secret: config.sessionSecret,
      resave: false,
      saveUninitialized: false,
      rolling: true,
      cookie: {
        httpOnly: true, // not readable by JavaScript (limits XSS impact)
        secure: config.cookieSecure, // HTTPS only
        sameSite: 'strict', // not sent on cross-site requests (CSRF)
        maxAge: 30 * 60_000,
      },
    }),
  );

  // General API rate limit (DoS protection); auth routes have a stricter one.
  app.use(
    '/api',
    rateLimit({ windowMs: 15 * 60_000, limit: 500, standardHeaders: 'draft-8', legacyHeaders: false }),
    (req, res, next) => {
      res.set('Cache-Control', 'no-store');
      next();
    },
    originCheck,
  );

  app.use('/api/auth', authRouter);
  app.use('/api/vault', vaultRouter);
  app.use('/api/tools', toolsRouter);
  app.use('/api/admin', adminRouter);
  app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

  // Serve the built React app (production mode).
  if (existsSync(clientDist)) {
    app.use(express.static(clientDist));
    app.get('/{*splat}', (req, res) => res.sendFile('index.html', { root: clientDist }));
  }

  app.use(errorHandler);
  return app;
}
