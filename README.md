# SecureVault: Secure Password Manager

A local password manager built following the Secure Software Development Lifecycle (SSDLC).
Node.js (Express) backend + React (Vite) frontend, served over HTTPS.

## Quick start

Requires Node.js 22.13+ (built with Node 24).

```bash
npm run install:all          # install root, server and client dependencies
npm run setup                # generate .env secrets + self-signed TLS certificate
npm run create-admin -- admin   # create an admin; prints a one-time master password
npm run build                # build the React app
npm start                    # https://localhost:3443
```

Your browser will warn about the self-signed certificate. Click "Advanced → Proceed" (expected for local HTTPS).

**Development mode** (hot reload): `npm run dev`, then open http://localhost:5173.

**Tests:** `npm test` (20 automated security tests).

**AI feedback (optional):** get a free API key from Google AI Studio (https://aistudio.google.com), then in
`server/.env` set `AI_FEEDBACK=on`, `GEMINI_API_KEY=...` and `GEMINI_MODEL=...` (copy a current model name from AI Studio).
Without it, the app falls back to rule-based feedback.

## Feature → code map

| Requirement | Implementation | File |
|---|---|---|
| Secure login | PBKDF2 auth hash, constant-time compare, generic errors, dummy hashing for unknown users | `server/src/users.js`, `server/src/routes/auth.js` |
| 2FA | TOTP (RFC 6238), QR enrolment, replay protection, mandatory for every user | `server/src/routes/auth.js` |
| RBAC | `admin` / `user` roles, role read from DB on each request, admins cannot decrypt vaults | `server/src/middleware.js`, `server/src/routes/admin.js` |
| Master password derivation | PBKDF2-HMAC-SHA256, 600,000 iterations, separate salts for auth hash and KEK | `server/src/crypto.js` |
| AES-256 encryption | AES-256-GCM, random 96-bit IV, AAD binds each ciphertext to owner + entry | `server/src/crypto.js`, `server/src/routes/vault.js` |
| Key hierarchy | Master password → KEK → wraps random vault key; password change re-wraps only | `server/src/users.js` |
| Secure memory | Keys held in Buffers, zero-filled on lock/logout/idle; never in DB, cookies or logs | `server/src/keystore.js` |
| Auto-lock | Server wipes key after 5 min idle; client idle timer shows lock screen | `server/src/keystore.js`, `client/src/security.js` |
| Clipboard clearing | Clipboard overwritten 15 s after copy, and on lock/logout | `client/src/security.js` |
| AI weak-password feedback | Gemini API receives only derived features (never the password); rule-based fallback | `server/src/ai.js`, `server/src/strength.js` |
| Compromised password check | Have I Been Pwned k-anonymity range API + offline list | `server/src/strength.js` |
| User behaviour analysis | 7 detection rules over the audit log, risk score per user | `server/src/behaviour.js` |
| Tamper-evident audit log | HMAC hash chain, integrity verification in admin UI | `server/src/audit.js` |
| SQL injection | Parameterised queries everywhere | all `db.prepare(...)` calls |
| XSS | React auto-escaping, strict CSP (no inline scripts), `javascript:` URLs rejected | `server/src/app.js`, `server/src/routes/vault.js` |
| CSRF | SameSite=Strict cookies + Origin allow-list + JSON-only | `server/src/middleware.js` |
| IDOR | Every query scoped by `user_id`, random UUID entry IDs | `server/src/routes/vault.js` |
| Brute force / DoS | Rate limiting (global + auth), account lockout after 5 failures | `server/src/routes/auth.js`, `server/src/app.js` |
| Session security | HttpOnly/Secure/SameSite cookies, ID regenerated at login and after 2FA, 30 min expiry | `server/src/app.js` |
| TLS | HTTPS only, TLS 1.2+, HSTS | `server/src/index.js` |
| Secure errors | Generic messages to clients; details logged server-side only | `server/src/middleware.js` |
| DevSecOps | CI: tests, Semgrep (SAST), npm audit (SCA), Gitleaks (secrets); Dependabot | `.github/` |

## Known limitations (discuss these in the report)

- JavaScript strings are immutable, so the master password itself can't be wiped from memory, only key Buffers.
- The session store is in-memory (single-process local app); a restart logs everyone out.
- Clipboard clearing only works while the tab has focus (browser restriction).
- Deleting the most recent audit rows isn't detected by the hash chain alone (would need external anchoring).
- Registration reveals whether a username exists (accepted trade-off for usability).
