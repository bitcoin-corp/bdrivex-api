// Metadata in SQLite beside the blobs (node:sqlite, no native build). Blobs themselves are files named by hash.
import { DatabaseSync } from 'node:sqlite';

export function openDb(file) {
  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS nonces (
      nonce TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS uploads (
      id TEXT PRIMARY KEY, owner TEXT NOT NULL, size INTEGER NOT NULL, received INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS uploads_owner ON uploads(owner);
    CREATE TABLE IF NOT EXISTS files (
      owner TEXT NOT NULL, hash TEXT NOT NULL, size INTEGER NOT NULL, meta TEXT, created_at INTEGER NOT NULL,
      PRIMARY KEY (owner, hash));
    CREATE INDEX IF NOT EXISTS files_hash ON files(hash);
    CREATE TABLE IF NOT EXISTS links (
      id TEXT PRIMARY KEY, owner TEXT NOT NULL, hash TEXT NOT NULL, created_at INTEGER NOT NULL,
      expires_at INTEGER, revoked_at INTEGER, downloads INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY (owner, hash) REFERENCES files(owner, hash) ON DELETE CASCADE);
    CREATE INDEX IF NOT EXISTS links_file ON links(owner, hash);
  `);
  const q = (sql) => db.prepare(sql);
  return {
    db,
    nonces: {
      put: q('INSERT OR REPLACE INTO nonces (nonce, data, expires_at) VALUES (?, ?, ?)'),
      get: q('SELECT data, expires_at FROM nonces WHERE nonce = ?'),
      del: q('DELETE FROM nonces WHERE nonce = ?'),
      prune: q('DELETE FROM nonces WHERE expires_at < ?'),
    },
    uploads: {
      add: q('INSERT INTO uploads (id, owner, size, received, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?)'),
      get: q('SELECT * FROM uploads WHERE id = ?'),
      advance: q('UPDATE uploads SET received = ?, updated_at = ? WHERE id = ?'),
      del: q('DELETE FROM uploads WHERE id = ?'),
      stale: q('SELECT id FROM uploads WHERE updated_at < ?'),
    },
    files: {
      add: q('INSERT OR IGNORE INTO files (owner, hash, size, meta, created_at) VALUES (?, ?, ?, ?, ?)'),
      get: q('SELECT * FROM files WHERE owner = ? AND hash = ?'),
      mine: q('SELECT * FROM files WHERE owner = ? ORDER BY created_at DESC'),
      del: q('DELETE FROM files WHERE owner = ? AND hash = ?'),
      refs: q('SELECT COUNT(*) AS n FROM files WHERE hash = ?'),
    },
    links: {
      add: q('INSERT INTO links (id, owner, hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)'),
      get: q('SELECT * FROM links WHERE id = ?'),
      forFile: q('SELECT * FROM links WHERE owner = ? AND hash = ? ORDER BY created_at DESC'),
      revoke: q('UPDATE links SET revoked_at = ? WHERE id = ? AND owner = ? AND revoked_at IS NULL'),
      hit: q('UPDATE links SET downloads = downloads + 1 WHERE id = ?'),
    },
    usage: q(`SELECT
      (SELECT COALESCE(SUM(size), 0) FROM files WHERE owner = ?1) AS stored,
      (SELECT COUNT(*) FROM files WHERE owner = ?1) AS files,
      (SELECT COALESCE(SUM(size), 0) FROM uploads WHERE owner = ?1) AS pending`),
  };
}
