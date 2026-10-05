import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { config } from './config.js';

if (config.dbPath !== ':memory:') mkdirSync(dirname(config.dbPath), { recursive: true });

export const db = new DatabaseSync(config.dbPath);

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    role            TEXT    NOT NULL CHECK (role IN ('admin', 'user')),
    auth_salt       BLOB    NOT NULL,
    auth_hash       BLOB    NOT NULL,   -- PBKDF2(master password, auth_salt): login verifier
    kek_salt        BLOB    NOT NULL,   -- PBKDF2(master password, kek_salt): key-encryption key
    wrapped_key     BLOB    NOT NULL,   -- AES-256-GCM(KEK, vault key)
    totp_secret_enc BLOB,               -- AES-256-GCM(SERVER_KEY, TOTP secret)
    totp_enabled    INTEGER NOT NULL DEFAULT 0,
    totp_last_step  INTEGER NOT NULL DEFAULT -1,  -- replay protection for TOTP codes
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    INTEGER,
    created_at      INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS entries (
    id         TEXT    PRIMARY KEY,     -- random UUID (not guessable)
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    data       BLOB    NOT NULL,        -- AES-256-GCM(vault key, JSON entry); nothing stored in plaintext
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_entries_user ON entries(user_id);

  CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    user_id    INTEGER,
    username   TEXT,
    event      TEXT    NOT NULL,
    ip         TEXT,
    user_agent TEXT,
    details    TEXT,
    prev_hash  TEXT    NOT NULL,
    hash       TEXT    NOT NULL         -- HMAC chain: tampering with any row breaks every later hash
  );
  CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
`);
