// Admin operations shared by the server and the scripts: closing an account, and legal holds.
// The scripts run beside the live server on the same SQLite database (WAL, busy_timeout), so every write here is a
// short statement or transaction, and blob deletes re-check that nobody holds the blob, like the server does.
import { createHash, createHmac } from 'node:crypto';
import { rm } from 'node:fs/promises';
import { join } from 'node:path';

export const KEY = /^0[23][0-9a-f]{64}$/; // compressed secp256k1 public key, lowercase hex
export const HASH = /^[0-9a-f]{64}$/;
/** What closed_accounts stores instead of the identity key. */
export const keyHash = (identityKey) => createHash('sha256').update(`bdrivex closed account|${identityKey}`).digest('hex');
/** A reporter IP after REPORT_IP_HASH_DAYS: keyed with SESSION_SECRET, so it can't be reversed by trying every address. */
export const hashIp = (secret, ip) => 'h:' + createHmac('sha256', secret).update(`bdrivex report ip|${ip}`).digest('hex').slice(0, 32);
/** How long a closed account's key hash is kept: past the longest session (7 days), so every old token is dead. */
export const CLOSED_KEEP_MS = 8 * 86400_000;

const tablesOf = (db) => new Set(db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((t) => t.name));

/**
 * What closing this account would do, read-only (works on a read-only database handle).
 * Returns counts and lists; nothing is changed.
 */
export function closePlan(db, key) {
  const t = tablesOf(db);
  const files = db.prepare('SELECT hash, size, key_wrap FROM files WHERE owner = ?').all(key);
  const heldSet = new Set(t.has('holds') ? db.prepare('SELECT DISTINCT hash FROM holds WHERE owner = ? AND released_at IS NULL').all(key).map((r) => r.hash) : []);
  const held = files.filter((f) => heldSet.has(f.hash));
  const toDelete = files.filter((f) => !heldSet.has(f.hash));
  const refs = db.prepare('SELECT COUNT(*) AS n FROM files WHERE hash = ? AND owner <> ?');
  return {
    files: files.length,
    bytes: files.reduce((n, f) => n + f.size, 0),
    toDelete,
    held,
    sharedBlobs: toDelete.filter((f) => refs.get(f.hash, key).n > 0).length, // other wallets hold the same bytes: kept
    links: db.prepare('SELECT COUNT(*) AS n FROM links WHERE owner = ?').get(key).n,
    inboundLinks: db.prepare('SELECT COUNT(*) AS n FROM links WHERE recipient = ?').get(key).n,
    uploads: db.prepare('SELECT id FROM uploads WHERE owner = ?').all(key).map((u) => u.id),
    keyWraps: toDelete.filter((f) => f.key_wrap).length, // deleted with their file rows
    signOutCounter: !!db.prepare('SELECT 1 AS n FROM generations WHERE owner = ?').get(key),
    reports: t.has('reports') && db.prepare('PRAGMA table_info(reports)').all().some((c) => c.name === 'owner')
      ? db.prepare('SELECT COUNT(*) AS n FROM reports WHERE owner = ?').get(key).n : 0,
    alreadyClosed: t.has('closed_accounts') ? db.prepare('SELECT closed_at FROM closed_accounts WHERE key_hash = ?').get(keyHash(key))?.closed_at ?? null : null,
  };
}

/**
 * Close an account (owner decision, Nov 2026: the user emails support@bwalletx.com with their identity key, we confirm,
 * then run this). Deletes the account's files (and each blob nobody else holds, via the store, writing the
 * deletion log so the B2 mirror's --prune follows), its share links, unfinished uploads, the key wraps (they live on
 * the file rows), sign-in nonces and the sign-out counter, and records sha256(key) in closed_accounts so tokens
 * issued before now stop working. There is no account table: those rows ARE the account.
 * Kept: report records (3 years, owner decision) and any file under legal hold (only with keepHeld; otherwise a held
 * file refuses the whole close, deleting nothing).
 * `S` is openDb(...) (the schema is brought up to date), `store` a blob store, `tmpDir` DATA_DIR/tmp.
 */
export async function closeAccount({ S, store, tmpDir, key, keepHeld = false, now = Date.now(), log = () => {} }) {
  const db = S.db;
  const plan = closePlan(db, key);
  if (plan.held.length && !keepHeld) return { refused: `${plan.held.length} file(s) are on legal hold`, plan };
  const out = { plan, filesDeleted: 0, blobsDeleted: 0, blobsKeptShared: 0, blobDeletesQueued: 0, races: 0, linksDeleted: 0, uploadsDeleted: 0 };

  // Rows first, in one transaction: links (all the account's links, held files' too), unheld files, uploads, the
  // sign-out counter, nonces, and the closed_accounts entry. Then the blobs, one by one, outside it.
  const delFile = db.prepare('DELETE FROM files WHERE owner = ? AND hash = ?');
  db.exec('BEGIN IMMEDIATE');
  try {
    out.linksDeleted = Number(db.prepare('DELETE FROM links WHERE owner = ?').run(key).changes);
    for (const f of plan.toDelete) out.filesDeleted += Number(delFile.run(key, f.hash).changes);
    out.uploadsDeleted = Number(db.prepare('DELETE FROM uploads WHERE owner = ?').run(key).changes);
    db.prepare('DELETE FROM generations WHERE owner = ?').run(key);
    db.prepare('DELETE FROM nonces WHERE instr(data, ?) > 0').run(key);
    db.prepare(`INSERT INTO closed_accounts (key_hash, closed_at, purge_after) VALUES (?1, ?2, ?3)
      ON CONFLICT(key_hash) DO UPDATE SET closed_at = ?2, purge_after = ?3`).run(keyHash(key), now, now + CLOSED_KEEP_MS);
    db.exec('COMMIT');
  } catch (e) { db.exec('ROLLBACK'); throw e; }

  for (const id of plan.uploads) await rm(join(tmpDir, id), { force: true });

  const refs = db.prepare('SELECT COUNT(*) AS n FROM files WHERE hash = ?');
  for (const f of plan.toDelete) {
    if (refs.get(f.hash).n) { out.blobsKeptShared++; S.blobDeletes.done.run(f.hash); continue; }
    S.erased.add.run(f.hash, now, 'account closed');
    try {
      await store.del(f.hash);
      S.blobDeletes.done.run(f.hash);
      out.blobsDeleted++;
      log(`deleted blob ${f.hash}`);
    } catch (e) {
      // The server's retry (every BLOB_DELETE_RETRY_MS) takes it from here, re-checking that nobody holds it.
      S.blobDeletes.failed.run(f.hash, now, String(e.message).slice(0, 300));
      out.blobDeletesQueued++;
      log(`could not delete blob ${f.hash} now (${e.message}); the server will retry it`);
    }
    if (refs.get(f.hash).n) {
      // Someone uploaded these exact bytes while it was being deleted (this script shares no lock with the server).
      // Their row is kept and the B2 copy is not pruned (the log row goes), so `mirror-to-b2.mjs --restore` brings it back.
      S.erased.clear.run(f.hash);
      out.races++;
      log(`RACE: ${f.hash} was uploaded again while it was being deleted: run mirror-to-b2.mjs --restore`);
    }
  }
  return out;
}

/** Active holds and reports, for the admin list. Read-only. */
export function holdsReport(db, { releasedSince = 0 } = {}) {
  const t = tablesOf(db);
  if (!t.has('holds')) return { active: [], released: [], reports: [] };
  return {
    active: db.prepare(`SELECT h.*, (SELECT COUNT(*) FROM files f WHERE f.owner = h.owner AND f.hash = h.hash) AS file_exists
      FROM holds h WHERE released_at IS NULL ORDER BY placed_at`).all(),
    released: db.prepare('SELECT * FROM holds WHERE released_at IS NOT NULL AND released_at >= ? ORDER BY released_at DESC').all(releasedSince),
    reports: db.prepare('SELECT link_id, at, reason, owner, hash, ip LIKE \'h:%\' AS ip_hashed FROM reports ORDER BY at DESC LIMIT 200').all(),
  };
}
