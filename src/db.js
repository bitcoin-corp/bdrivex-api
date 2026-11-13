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
    CREATE TABLE IF NOT EXISTS revoked (sid TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS generations (owner TEXT PRIMARY KEY, gen INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS reports (
      link_id TEXT PRIMARY KEY, at INTEGER NOT NULL, reason TEXT, ip TEXT);
    -- Blobs whose last file row went but whose delete from the store failed: retried by the server, and shown by
    -- scripts/orphan-blobs.mjs. A row here never means the blob is wanted; the retry checks nobody holds it again.
    CREATE TABLE IF NOT EXISTS blob_deletes (
      hash TEXT PRIMARY KEY, first_failed_at INTEGER NOT NULL, last_failed_at INTEGER NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 1, error TEXT);
  `);
  // v1.1: the file key wrapped by the owner's wallet (BRC-2, counterparty self). Only that wallet can open it.
  if (!db.prepare('PRAGMA table_info(files)').all().some((c) => c.name === 'key_wrap')) db.exec('ALTER TABLE files ADD COLUMN key_wrap TEXT');
  // v1.2: a link can be sent to one person. recipient = their identity key; recipient_wrap = the file key wrapped by
  // the sender's wallet for that key (BRC-2, protocol [2,'bdrivex share'], key ID '<hash>.<link id>'); recipient_label =
  // the $handle or paymail the sender typed, shown only to the sender. The sender is always the link's owner.
  const linkCols = new Set(db.prepare('PRAGMA table_info(links)').all().map((c) => c.name));
  for (const c of ['recipient', 'recipient_wrap', 'recipient_label']) if (!linkCols.has(c)) db.exec(`ALTER TABLE links ADD COLUMN ${c} TEXT`);
  db.exec('CREATE INDEX IF NOT EXISTS links_recipient ON links(recipient)');
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
      wrap: q('UPDATE files SET key_wrap = ? WHERE owner = ? AND hash = ?'),
    },
    links: {
      add: q('INSERT INTO links (id, owner, hash, created_at, expires_at, recipient, recipient_wrap, recipient_label) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'),
      bind: q('UPDATE links SET recipient = ?, recipient_wrap = ?, recipient_label = ? WHERE id = ? AND owner = ?'),
      // Is there a live link addressed to this key? (lets a wallet that isn't invited sign in to open it)
      liveFor: q(`SELECT 1 AS n FROM links l WHERE l.recipient = ? AND l.revoked_at IS NULL AND (l.expires_at IS NULL OR l.expires_at > ?)
        AND NOT EXISTS (SELECT 1 FROM reports r WHERE r.link_id = l.id) LIMIT 1`),
      get: q('SELECT * FROM links WHERE id = ?'),
      forFile: q('SELECT * FROM links WHERE owner = ? AND hash = ? ORDER BY created_at DESC'),
      revoke: q('UPDATE links SET revoked_at = ? WHERE id = ? AND owner = ? AND revoked_at IS NULL'),
      hit: q('UPDATE links SET downloads = downloads + 1 WHERE id = ?'),
    },
    blobDeletes: {
      failed: q(`INSERT INTO blob_deletes (hash, first_failed_at, last_failed_at, attempts, error) VALUES (?1, ?2, ?2, 1, ?3)
        ON CONFLICT(hash) DO UPDATE SET last_failed_at = ?2, attempts = attempts + 1, error = ?3`),
      done: q('DELETE FROM blob_deletes WHERE hash = ?'),
      all: q('SELECT hash, attempts FROM blob_deletes ORDER BY last_failed_at LIMIT 500'),
    },
    reports: {
      add: q('INSERT OR IGNORE INTO reports (link_id, at, reason, ip) VALUES (?, ?, ?, ?)'),
      get: q('SELECT at, reason FROM reports WHERE link_id = ?'),
    },
    sessions: {
      revoke: q('INSERT OR IGNORE INTO revoked (sid, expires_at) VALUES (?, ?)'),
      isRevoked: q('SELECT 1 AS r FROM revoked WHERE sid = ?'),
      prune: q('DELETE FROM revoked WHERE expires_at < ?'),
      gen: q('SELECT gen FROM generations WHERE owner = ?'),
      bump: q('INSERT INTO generations (owner, gen) VALUES (?, 1) ON CONFLICT(owner) DO UPDATE SET gen = gen + 1'),
    },
    usage: q(`SELECT
      (SELECT COALESCE(SUM(size), 0) FROM files WHERE owner = ?1) AS stored,
      (SELECT COUNT(*) FROM files WHERE owner = ?1) AS files,
      (SELECT COALESCE(SUM(size), 0) FROM uploads WHERE owner = ?1) AS pending`),
  };
}
