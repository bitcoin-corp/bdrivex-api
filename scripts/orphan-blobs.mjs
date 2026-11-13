// Compare the bucket with the database: blobs in the bucket that no file row holds (orphans, e.g. left by a delete that
// failed), and file rows whose blob is not in the bucket (missing: those files can't be downloaded). Looks only, unless
// --delete is given.
//
//   node --env-file=/srv/bdrivex/.env scripts/orphan-blobs.mjs                    # report (the default: a dry run)
//   node --env-file=/srv/bdrivex/.env scripts/orphan-blobs.mjs --delete           # delete the orphans it reports
//        [--min-age-hours=24] [--force] [--max-delete-share=0.1] [--max-delete-floor=25]
//
// Env: DATA_DIR (the database is DATA_DIR/bdrivex.db), S3_ENDPOINT, S3_REGION, S3_BUCKET, S3_ACCESS_KEY_ID,
// S3_SECRET_ACCESS_KEY, S3_PREFIX. For BLOB_STORE=s3 only.
//
// --delete is the only path that deletes from the primary without a user's action. It never touches the B2 backup and
// writes no deletion-log (erased_blobs) rows, so what it removes stays in B2 (the mirror calls it "unreferenced").
//
// Safety:
//   - Only keys that are <S3_PREFIX><sha256> are considered; anything else in the bucket is listed and left alone.
//   - Objects newer than --min-age-hours (default 24) are never orphans: an upload stores its blob a moment before
//     its file row, and a fresh blob may simply not have its row yet.
//   - Each orphan's file rows are checked again right before it is deleted. Even so, a wallet uploading those exact
//     bytes at that moment could lose its blob (the server and this script share no lock), so run --delete when the
//     API is quiet; it says so loudly if it sees that happen.
//   - --delete refuses, deleting nothing, if the database has no file rows but the bucket has blobs (a wrong DATA_DIR
//     looks like that), or if it would delete more than --max-delete-share of the bucket's blobs and more than
//     --max-delete-floor objects, unless --force.
// Rows in the server's blob_deletes table (deletes that failed and are being retried) are shown; --delete clears the
// row for each orphan it deletes, and rows for blobs already gone. Exit 1 if a delete failed or was refused.
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { createS3Client, s3ConfigFromEnv } from '../src/s3.js';

const argv = process.argv.slice(2);
const opt = (name, dflt) => { const a = argv.find((x) => x.startsWith(`--${name}=`)); return a ? Number(a.split('=')[1]) : dflt; };
for (const a of argv) if (!['--delete', '--dry-run', '--force'].includes(a) && !/^--(min-age-hours|max-delete-share|max-delete-floor)=[\d.]+$/.test(a)) { console.error(`unknown option ${a}`); process.exit(2); }
const DELETE = argv.includes('--delete') && !argv.includes('--dry-run');
const FORCE = argv.includes('--force');
const MIN_AGE_MS = opt('min-age-hours', 24) * 3600_000;
const MAX_SHARE = opt('max-delete-share', 0.1);
const MAX_FLOOR = opt('max-delete-floor', 25);
const TAG = '[orphan-blobs]';
const HASH = /^[0-9a-f]{64}$/;

let cfg;
try { cfg = s3ConfigFromEnv(process.env, 'S3'); } catch (e) { console.error(`${TAG} ${e.message}`); process.exit(2); }
const DATA = process.env.DATA_DIR || join(process.cwd(), 'data');
const dbFile = join(DATA, 'bdrivex.db');
if (!existsSync(dbFile)) { console.error(`${TAG} no database at ${dbFile}: set DATA_DIR`); process.exit(2); }
const db = new DatabaseSync(dbFile, { readOnly: !DELETE });
if (DELETE) db.exec('PRAGMA busy_timeout = 5000');
const tables = new Set(db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((t) => t.name));
if (!tables.has('files')) { console.error(`${TAG} ${dbFile} has no files table: not a bdrivex database`); process.exit(2); }
const rowsFor = db.prepare('SELECT COUNT(*) AS n FROM files WHERE hash = ?');
const pending = tables.has('blob_deletes') ? new Map(db.prepare('SELECT hash, attempts FROM blob_deletes').all().map((r) => [r.hash, r.attempts])) : new Map();
const clearPending = DELETE && tables.has('blob_deletes') ? db.prepare('DELETE FROM blob_deletes WHERE hash = ?') : null;

const s3 = createS3Client(cfg);
const t0 = Date.now();
const where = `${new URL(cfg.endpoint).host}/${cfg.bucket}/${cfg.prefix}`;
let exitCode = 0;
try {
  const held = new Set(db.prepare('SELECT DISTINCT hash FROM files').all().map((r) => r.hash));
  const inBucket = new Set();
  const orphans = [];
  let blobs = 0, young = 0, other = 0;
  for await (const o of s3.list(cfg.prefix)) {
    const h = o.key.slice(cfg.prefix.length);
    if (!HASH.test(h)) { other++; console.log(`${TAG} not a blob, left alone: ${o.key}`); continue; }
    blobs++;
    inBucket.add(h);
    if (held.has(h)) continue;
    if (o.lastModified == null || t0 - o.lastModified < MIN_AGE_MS) { young++; continue; }
    orphans.push(o);
  }
  for (const o of orphans) {
    const h = o.key.slice(cfg.prefix.length);
    console.log(`${TAG} orphan ${o.key} · ${o.size} bytes · ${new Date(o.lastModified).toISOString()}${pending.has(h) ? ` · failed delete, ${pending.get(h)} attempts` : ''}`);
  }
  const missing = [...held].filter((h) => !inBucket.has(h));
  for (const h of missing) console.log(`${TAG} missing ${h}: ${rowsFor.get(h).n} file row(s), no blob in the bucket`);

  let deleted = 0, failed = 0, refused = '';
  if (DELETE) {
    const limit = Math.max(Math.floor(blobs * MAX_SHARE), MAX_FLOOR);
    if (held.size === 0 && blobs > 0 && !FORCE) refused = 'the database has no file rows but the bucket has blobs (wrong DATA_DIR?)';
    else if (orphans.length > limit && !FORCE) refused = `${orphans.length} of ${blobs} blobs is more than ${Math.round(MAX_SHARE * 100)}% (and more than ${MAX_FLOOR}); use --force if this is right`;
    if (refused) { console.error(`${TAG} --delete refused: ${refused}. Nothing deleted.`); exitCode = 1; }
    else {
      for (const o of orphans) {
        const h = o.key.slice(cfg.prefix.length);
        if (rowsFor.get(h).n) { console.log(`${TAG} kept ${o.key}: a file row holds it now`); continue; }
        try {
          await s3.del(o.key);
          deleted++;
          clearPending?.run(h);
          console.log(`${TAG} deleted ${o.key}`);
          if (rowsFor.get(h).n) console.error(`${TAG} RACE: ${h} was uploaded again while it was being deleted. Its owner must upload it again.`);
        } catch (e) { failed++; exitCode = 1; console.error(`${TAG} FAILED to delete ${o.key}: ${e.message}`); }
      }
      // Pending retries for blobs that are already gone from the bucket and that nobody holds: nothing left to do.
      for (const h of pending.keys()) if (!inBucket.has(h) && !rowsFor.get(h).n) clearPending?.run(h);
    }
  }
  console.log(`${TAG} ${DELETE ? '' : 'report only (use --delete to remove orphans) · '}${where} ${blobs} blobs · file rows hold ${held.size} hashes · orphans ${orphans.length} (younger than ${MIN_AGE_MS / 3600_000}h skipped: ${young}) · missing ${missing.length} · not blobs ${other} · failed deletes on record ${pending.size}${DELETE ? ` · deleted ${deleted}, failed ${failed}${refused ? ', REFUSED' : ''}` : ''} · ${((Date.now() - t0) / 1000).toFixed(1)}s`);
} catch (e) {
  exitCode = 1;
  console.error(`${TAG} FAILED: ${e.message}. Nothing deleted after this point.`);
} finally { s3.close(); db.close(); }
process.exit(exitCode);
