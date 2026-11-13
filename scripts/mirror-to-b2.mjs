// The B2 backup of the primary bucket. Blobs are named by the SHA-256 of their bytes, so a key in B2 at the same size
// is the same blob.
//
//   node --env-file=/srv/bdrivex/.env scripts/mirror-to-b2.mjs [--prune] [--dry-run] [--force] [--concurrency=4]
//   node --env-file=/srv/bdrivex/.env scripts/mirror-to-b2.mjs --restorable          # report only
//   node --env-file=/srv/bdrivex/.env scripts/mirror-to-b2.mjs --restore [--dry-run]  # copy lost blobs back
//
// Env, primary: S3_ENDPOINT, S3_REGION, S3_BUCKET, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY, S3_PREFIX (optional)
// Env, B2:      B2_ENDPOINT, B2_REGION, B2_BUCKET, B2_ACCESS_KEY_ID, B2_SECRET_ACCESS_KEY, B2_PREFIX (optional, default S3_PREFIX)
// DATA_DIR:     the API's data directory; its database (bdrivex.db) is needed for --prune and --restore, and is used if
//               present to tell lost blobs from erased ones. Opened read-only, except for writing b2_pruned_at.
//
// Default: copy every primary blob B2 lacks (streamed bucket to bucket, signed with its SHA-256, so B2 refuses bytes
// that don't match the name). A B2 copy of the wrong size is reported and left alone.
//
// --prune also deletes from B2 the blobs in the deletion log (erased_blobs, written by the API when a user's delete
// removes the last reference) that are gone from the primary, have no live file row, and haven't been pruned yet; each
// one is logged and marked b2_pruned_at, so it is pruned once and can be audited. It NEVER deletes a blob just because
// the primary no longer has it: a blob lost from the primary (bad migration, bucket mishap) stays in B2, shows up as
// restorable, and makes the run exit 1 if a file row still needs it. Refuses, deleting nothing, if a listing failed or
// was cut short, if the primary listing is empty while the database has files, or if it would delete more than
// --max-delete-share (10%) of B2's blobs and more than --max-delete-floor (25) objects, unless --force.
//
// --restorable: list B2 blobs missing from the primary (no copies, no deletes): "lost" (a file row still needs it:
// restore it), "erased" (in the deletion log, waiting for --prune) or "unreferenced" (no row, not erased: e.g. removed
// with scripts/orphan-blobs.mjs, or deleted before the log existed).
// --restore: copy the "lost" ones back from B2 to the primary (never erased ones). With --dry-run, says what it would.
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { createS3Client, s3ConfigFromEnv } from '../src/s3.js';

const argv = process.argv.slice(2);
const flag = (f) => argv.includes(f);
const opt = (name, dflt) => { const a = argv.find((x) => x.startsWith(`--${name}=`)); return a ? Number(a.split('=')[1]) : dflt; };
const KNOWN = new Set(['--dry-run', '--prune', '--force', '--restorable', '--restore']);
for (const a of argv) if (!KNOWN.has(a) && !/^--(concurrency|max-delete-share|max-delete-floor)=[\d.]+$/.test(a)) { console.error(`unknown option ${a}`); process.exit(2); }
const DRY = flag('--dry-run'), PRUNE = flag('--prune'), FORCE = flag('--force'), REPORT = flag('--restorable'), RESTORE = flag('--restore');
if ([PRUNE, REPORT, RESTORE].filter(Boolean).length > 1) { console.error('use one of --prune, --restorable, --restore'); process.exit(2); }
const CONCURRENCY = Math.max(1, opt('concurrency', 4));
const MAX_SHARE = opt('max-delete-share', 0.1);
const MAX_FLOOR = opt('max-delete-floor', 25);
const HASH_AT_END = /([0-9a-f]{64})$/;
const TAG = '[mirror-to-b2]';
const die = (m) => { console.error(`${TAG} ${m}`); process.exit(2); };

let src, dst;
try {
  src = s3ConfigFromEnv(process.env, 'S3');
  dst = s3ConfigFromEnv({ B2_PREFIX: src.prefix, ...process.env }, 'B2');
} catch (e) { die(e.message); }

// The API's database, read-only. Needed to prune (the deletion log) and to restore (which blobs rows still need).
const dbFile = join(process.env.DATA_DIR || join(process.cwd(), 'data'), 'bdrivex.db');
let db = null;
if (existsSync(dbFile)) db = new DatabaseSync(dbFile, { readOnly: true });
else if (PRUNE || RESTORE) die(`${PRUNE ? '--prune' : '--restore'} needs the API database: no ${dbFile} (set DATA_DIR).`);
const hasTable = (t) => !!db?.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(t);
if (PRUNE && !hasTable('erased_blobs')) die(`${dbFile} has no erased_blobs table: run the updated API once first. Nothing pruned.`);
const rowsFor = db ? db.prepare('SELECT COUNT(*) AS n FROM files WHERE hash = ?') : null;
const erasedPending = hasTable('erased_blobs') ? db.prepare('SELECT hash, erased_at, reason FROM erased_blobs WHERE b2_pruned_at IS NULL') : null;
const stillErased = hasTable('erased_blobs') ? db.prepare('SELECT 1 AS y FROM erased_blobs WHERE hash = ? AND b2_pruned_at IS NULL') : null;
let rw = null; // opened only to write b2_pruned_at
const markPruned = (h) => {
  if (!rw) { rw = new DatabaseSync(dbFile); rw.exec('PRAGMA busy_timeout = 5000'); }
  rw.prepare('UPDATE erased_blobs SET b2_pruned_at = ? WHERE hash = ? AND b2_pruned_at IS NULL').run(Date.now(), h);
};

const from = createS3Client(src), to = createS3Client(dst);
const toKey = (k) => dst.prefix + k.slice(src.prefix.length);
const t0 = Date.now();
const n = { primary: 0, primaryBytes: 0, had: 0, copied: 0, bytes: 0, skipped: 0, mismatched: 0, failed: 0, lost: 0, erased: 0, unreferenced: 0, restored: 0, deleted: 0, marked: 0, waiting: 0, deleteFailed: 0 };
let listed = true, prune = PRUNE ? 'not run' : 'off';
const pool = async (items, fn) => { await Promise.all(Array.from({ length: CONCURRENCY }, async () => { while (items.length) await fn(items.shift()); })); };

try {
  const there = new Map();
  for await (const o of to.list(dst.prefix)) there.set(o.key, o.size);
  const todo = [], inPrimary = new Set();
  for await (const o of from.list(src.prefix)) {
    n.primary++; n.primaryBytes += o.size;
    inPrimary.add(o.key.slice(src.prefix.length));
    const m = HASH_AT_END.exec(o.key);
    if (!m) { n.skipped++; console.warn(`${TAG} skipped ${o.key}: not a blob (no sha256 at the end of its key)`); continue; }
    const have = there.get(toKey(o.key));
    if (have === o.size) { n.had++; continue; }
    if (have != null) { n.mismatched++; console.error(`${TAG} B2 has ${toKey(o.key)} at ${have} bytes, primary at ${o.size}: left alone, look at it by hand`); continue; }
    todo.push({ key: o.key, size: o.size, sha256: m[1] });
  }

  // B2 blobs the primary doesn't have: lost (a row needs it), erased (in the log, waiting for --prune) or unreferenced.
  const pendingErasures = new Map((erasedPending?.all() ?? []).map((r) => [r.hash, r]));
  const b2Only = [];
  for (const [key, size] of there) {
    if (!key.startsWith(dst.prefix)) continue;
    const h = key.slice(dst.prefix.length);
    if (!/^[0-9a-f]{64}$/.test(h) || inPrimary.has(h)) continue;
    const kind = rowsFor?.get(h).n ? 'lost' : pendingErasures.has(h) ? 'erased' : db ? 'unreferenced' : 'unknown (no database)';
    if (kind === 'lost') n.lost++; else if (kind === 'erased') n.erased++; else n.unreferenced++;
    b2Only.push({ key, h, size, kind });
  }
  for (const b of b2Only) {
    if (b.kind === 'lost') console.error(`${TAG} LOST from the primary, restorable from B2: ${b.h} (${b.size} bytes, ${rowsFor.get(b.h).n} file row(s))`);
    else if (REPORT) console.log(`${TAG} in B2 only (${b.kind}): ${b.h} (${b.size} bytes)`);
  }

  if (RESTORE) {
    await pool(b2Only.filter((b) => b.kind === 'lost'), async (b) => {
      if (DRY) { n.restored++; console.log(`${TAG} would restore ${b.h}`); return; }
      try {
        await from.put(src.prefix + b.h, { body: () => to.get(b.key), size: b.size, sha256: b.h });
        n.restored++; console.log(`${TAG} restored ${b.h} from B2 to the primary`);
      } catch (e) { n.failed++; console.error(`${TAG} FAILED to restore ${b.h}: ${e.message}`); }
    });
  } else if (!REPORT) {
    await pool(todo, async (o) => {
      if (DRY) { n.copied++; n.bytes += o.size; return; }
      try {
        await to.put(toKey(o.key), { body: () => from.get(o.key), size: o.size, sha256: o.sha256 });
        n.copied++; n.bytes += o.size;
      } catch (e) { n.failed++; console.error(`${TAG} FAILED ${o.key}: ${e.message}`); }
    });
  }

  if (PRUNE) {
    const liveRows = db.prepare('SELECT COUNT(*) AS n FROM files').get().n;
    const b2Blobs = [...there.keys()].filter((k) => HASH_AT_END.test(k)).length;
    const del = [], markOnly = [];
    for (const h of pendingErasures.keys()) {
      if (rowsFor.get(h).n) continue;                         // live again (a row holds it): never prune
      if (inPrimary.has(h)) { n.waiting++; continue; }         // the primary delete hasn't happened yet (retrying)
      if (there.has(dst.prefix + h)) del.push(h); else markOnly.push(h);
    }
    if (n.primary === 0 && liveRows > 0) {
      prune = 'REFUSED (primary listing is empty)';
      console.error(`${TAG} prune refused: the primary listing of ${src.bucket}/${src.prefix} is empty but the database has ${liveRows} file rows: a wrong bucket, prefix or key? Nothing deleted.`);
    } else if (del.length > Math.max(Math.floor(b2Blobs * MAX_SHARE), MAX_FLOOR) && !FORCE) {
      prune = `REFUSED (${del.length} of ${b2Blobs})`;
      console.error(`${TAG} prune refused: ${del.length} erased blobs is more than ${Math.round(MAX_SHARE * 100)}% of B2's ${b2Blobs} (and more than ${MAX_FLOOR}). Check erased_blobs; run with --force if this is right. Nothing deleted.`);
    } else {
      prune = DRY ? 'dry run' : 'done';
      const why = (h) => `erased ${new Date(pendingErasures.get(h).erased_at).toISOString()}, ${pendingErasures.get(h).reason}`;
      await pool([...del], async (h) => {
        // Look again just before deleting: uploaded again meanwhile means live, keep it.
        if (rowsFor.get(h).n || !stillErased.get(h)) { console.log(`${TAG} kept ${h}: live again`); return; }
        if (DRY) { n.deleted++; console.log(`${TAG} would delete ${dst.bucket}/${dst.prefix}${h} (${why(h)})`); return; }
        try {
          await to.del(dst.prefix + h);
          markPruned(h);
          n.deleted++;
          console.log(`${TAG} deleted ${dst.bucket}/${dst.prefix}${h} (${why(h)})`);
        } catch (e) { n.deleteFailed++; console.error(`${TAG} FAILED to delete ${h}: ${e.message}`); }
      });
      // Erased before B2 ever had a copy: nothing to delete, mark them done.
      for (const h of markOnly) if (!DRY && !rowsFor.get(h).n) { markPruned(h); n.marked++; }
    }
  }
} catch (e) {
  // A listing that failed or was cut short: no copy list we can trust, and above all no prune.
  listed = false;
  n.failed++;
  if (PRUNE) prune = 'REFUSED (listing failed)';
  console.error(`${TAG} FAILED listing: ${e.message}`);
} finally { from.close(); to.close(); db?.close(); rw?.close(); }

const gb = (b) => (b / 2 ** 30).toFixed(2);
const parts = [
  `${DRY ? 'dry run · ' : ''}${REPORT ? 'report only · ' : ''}${listed ? '' : 'incomplete · '}primary ${src.bucket}/${src.prefix} ${n.primary} objects (${gb(n.primaryBytes)} GB)`,
  `already in B2 ${n.had}`,
  REPORT || RESTORE ? null : `${DRY ? 'would copy' : 'copied'} ${n.copied} (${gb(n.bytes)} GB)`,
  `skipped ${n.skipped}`, `size mismatches ${n.mismatched}`, `failed ${n.failed}`,
  `in B2 only: lost ${n.lost}, erased ${n.erased}, unreferenced ${n.unreferenced}`,
  RESTORE ? `${DRY ? 'would restore' : 'restored'} ${n.restored}` : null,
  `prune ${prune}${PRUNE ? `: ${DRY ? 'would delete' : 'deleted'} ${n.deleted}, failed ${n.deleteFailed}, marked ${n.marked}, waiting ${n.waiting}` : ''}`,
  `${((Date.now() - t0) / 1000).toFixed(1)}s`,
];
console.log(`${TAG} ${parts.filter(Boolean).join(' · ')}`);
// A lost blob is an alarm (exit 1), except in the report-only mode and after a restore that brought every one back.
const lostAlarm = n.lost > 0 && !REPORT && !(RESTORE && !DRY && n.restored === n.lost);
process.exit(n.failed || n.mismatched || n.deleteFailed || prune.startsWith('REFUSED') || lostAlarm ? 1 : 0);
