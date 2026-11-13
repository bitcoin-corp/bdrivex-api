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
    -- The deletion log: blobs deliberately removed (the last file row went by a user's delete), written by the server
    -- in the same step as the store delete (or its recorded retry). It is the ONLY thing scripts/mirror-to-b2.mjs
    -- --prune deletes from the B2 backup by, so a blob lost from the primary any other way is never pruned from B2.
    -- Uploading the same bytes again removes the row. b2_pruned_at: when the mirror removed it from B2 (audit).
    CREATE TABLE IF NOT EXISTS erased_blobs (
      hash TEXT PRIMARY KEY, erased_at INTEGER NOT NULL, reason TEXT NOT NULL, b2_pruned_at INTEGER);
    -- Legal holds: a reported file (owner, hash) can't be deleted by its owner, or by scripts/close-account.mjs, until
    -- an admin releases the hold with scripts/legal-hold.mjs. A report places one; an admin can place one by hand.
    -- Released holds are kept for the report retention period (3 years after release), then deleted.
    CREATE TABLE IF NOT EXISTS holds (
      id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, hash TEXT NOT NULL, link_id TEXT,
      placed_at INTEGER NOT NULL, reason TEXT, released_at INTEGER, released_note TEXT);
    CREATE INDEX IF NOT EXISTS holds_file ON holds(owner, hash);
    -- Accounts closed by scripts/close-account.mjs: sha256 of the identity key (never the key itself), so tokens
    -- issued before closing stop working. Deleted once every such token has expired (purge_after).
    CREATE TABLE IF NOT EXISTS closed_accounts (
      key_hash TEXT PRIMARY KEY, closed_at INTEGER NOT NULL, purge_after INTEGER NOT NULL);
  `);
  // v1.1: the file key wrapped by the owner's wallet (BRC-2, counterparty self). Only that wallet can open it.
  if (!db.prepare('PRAGMA table_info(files)').all().some((c) => c.name === 'key_wrap')) db.exec('ALTER TABLE files ADD COLUMN key_wrap TEXT');
  // v1.2: a link can be sent to one person. recipient = their identity key; recipient_wrap = the file key wrapped by
  // the sender's wallet for that key (BRC-2, protocol [2,'bdrivex share'], key ID '<hash>.<link id>'); recipient_label =
  // the $handle or paymail the sender typed, shown only to the sender. The sender is always the link's owner.
  const linkCols = new Set(db.prepare('PRAGMA table_info(links)').all().map((c) => c.name));
  for (const c of ['recipient', 'recipient_wrap', 'recipient_label']) if (!linkCols.has(c)) db.exec(`ALTER TABLE links ADD COLUMN ${c} TEXT`);
  db.exec('CREATE INDEX IF NOT EXISTS links_recipient ON links(recipient)');
  // Revoked or expired links lose recipient, recipient_wrap and recipient_label after a grace period (the terms promise
  // it); recipient_scrubbed_at says when, so the owner's list still shows it was sent to one person.
  if (!linkCols.has('recipient_scrubbed_at')) db.exec('ALTER TABLE links ADD COLUMN recipient_scrubbed_at INTEGER');
  // Reports keep what was reported (owner, hash) so the record outlives the link and the file (a deleted file takes its
  // links with it). Reports made before this column existed are filled in from their links, and their files held.
  const reportCols = new Set(db.prepare('PRAGMA table_info(reports)').all().map((c) => c.name));
  if (!reportCols.has('owner')) {
    db.exec(`ALTER TABLE reports ADD COLUMN owner TEXT; ALTER TABLE reports ADD COLUMN hash TEXT;
      UPDATE reports SET owner = (SELECT owner FROM links WHERE id = reports.link_id), hash = (SELECT hash FROM links WHERE id = reports.link_id);
      INSERT INTO holds (owner, hash, link_id, placed_at, reason)
        SELECT r.owner, r.hash, r.link_id, r.at, 'report (from before holds existed)' FROM reports r
        WHERE r.owner IS NOT NULL AND EXISTS (SELECT 1 FROM files f WHERE f.owner = r.owner AND f.hash = r.hash)
          AND NOT EXISTS (SELECT 1 FROM holds h WHERE h.link_id = r.link_id);`);
  }
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
      // Revoked or expired before ?2: drop who it was for. Not while the file is on legal hold (the report is about
      // what was sent to whom); once the hold is released, the next run scrubs it.
      scrub: q(`UPDATE links SET recipient = NULL, recipient_wrap = NULL, recipient_label = NULL, recipient_scrubbed_at = ?1
        WHERE (recipient IS NOT NULL OR recipient_wrap IS NOT NULL OR recipient_label IS NOT NULL)
          AND ((revoked_at IS NOT NULL AND revoked_at < ?2) OR (expires_at IS NOT NULL AND expires_at < ?2))
          AND NOT EXISTS (SELECT 1 FROM holds h WHERE h.owner = links.owner AND h.hash = links.hash AND h.released_at IS NULL)`),
    },
    blobDeletes: {
      failed: q(`INSERT INTO blob_deletes (hash, first_failed_at, last_failed_at, attempts, error) VALUES (?1, ?2, ?2, 1, ?3)
        ON CONFLICT(hash) DO UPDATE SET last_failed_at = ?2, attempts = attempts + 1, error = ?3`),
      done: q('DELETE FROM blob_deletes WHERE hash = ?'),
      all: q('SELECT hash, attempts FROM blob_deletes ORDER BY last_failed_at LIMIT 500'),
    },
    erased: {
      // A fresh erasure: (re)start the row, so a blob erased, uploaded again and erased again is pruned again.
      add: q(`INSERT INTO erased_blobs (hash, erased_at, reason, b2_pruned_at) VALUES (?, ?, ?, NULL)
        ON CONFLICT(hash) DO UPDATE SET erased_at = excluded.erased_at, reason = excluded.reason, b2_pruned_at = NULL`),
      // The blob is live again (uploaded again): it must not be pruned from B2.
      clear: q('DELETE FROM erased_blobs WHERE hash = ?'),
    },
    reports: {
      add: q('INSERT OR IGNORE INTO reports (link_id, at, reason, ip, owner, hash) VALUES (?, ?, ?, ?, ?, ?)'),
      get: q('SELECT at, reason FROM reports WHERE link_id = ?'),
      // Retention: records older than the cut-off go; reporter IPs older than the other cut-off are replaced by a keyed
      // hash ('h:<hex>'), so repeat reporters can still be matched but the address itself is gone.
      expire: q('DELETE FROM reports WHERE at < ?'),
      rawIps: q("SELECT link_id, ip FROM reports WHERE at < ? AND ip IS NOT NULL AND ip NOT LIKE 'h:%'"),
      setIp: q('UPDATE reports SET ip = ? WHERE link_id = ?'),
    },
    holds: {
      place: q('INSERT INTO holds (owner, hash, link_id, placed_at, reason) VALUES (?, ?, ?, ?, ?)'),
      active: q('SELECT id, link_id, placed_at, reason FROM holds WHERE owner = ? AND hash = ? AND released_at IS NULL LIMIT 1'),
      expire: q('DELETE FROM holds WHERE released_at IS NOT NULL AND released_at < ?'),
    },
    closed: {
      get: q('SELECT closed_at FROM closed_accounts WHERE key_hash = ?'),
      purge: q('DELETE FROM closed_accounts WHERE purge_after < ?'),
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
