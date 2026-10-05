import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { db } from '../db.js';
import { str, requireUnlocked } from '../middleware.js';
import { analyseStrength, breachCount, localAdvice } from '../strength.js';
import { aiFeedback } from '../ai.js';

export const router = Router();

const limiter = (limit) =>
  rateLimit({ windowMs: 60_000, limit, standardHeaders: 'draft-8', legacyHeaders: false,
    message: { error: 'Too many requests. Slow down.' } });

// Public (used on the registration screen), so it is rate limited.
router.post('/analyze', limiter(30), async (req, res) => {
  const password = str(req.body.password, { name: 'Password', min: 1, max: 256 });
  const userInputs = typeof req.body.username === 'string' ? [req.body.username.slice(0, 32)] : [];
  const strength = analyseStrength(password, userInputs);
  const breach = await breachCount(password);
  res.json({
    score: strength.score,
    crackTime: strength.crackTime,
    warning: strength.warning,
    suggestions: strength.suggestions,
    breachCount: breach.count,
    breachSource: breach.source,
  });
});

router.post('/ai-feedback', requireUnlocked, limiter(10), async (req, res) => {
  const password = str(req.body.password, { name: 'Password', min: 1, max: 256 });
  const { features } = analyseStrength(password, [req.session.username]);
  const { count } = await breachCount(password);
  const tips = await aiFeedback(features, count); // receives features only, never the password
  res.json({
    source: tips ? 'ai' : 'rules',
    tips: tips ?? localAdvice(features, count),
    sharedWithAi: tips ? features : null, // shown in the UI for transparency
  });
});

router.get('/activity', requireUnlocked, (req, res) => {
  const events = db
    .prepare('SELECT ts, event, ip, user_agent FROM audit_log WHERE user_id = ? ORDER BY id DESC LIMIT 100')
    .all(req.session.userId);
  res.json({ events });
});
