// Nightly second copy: copy every object in the primary bucket that Backblaze B2 doesn't have yet, and with --prune
// delete from B2 what the primary no longer has (so a file deleted here, or erased on request, leaves the backup too).
// Blobs are named by the SHA-256 of their bytes, so a key in B2 at the same size is the same blob.
//
//   node --env-file=/srv/bdrivex/.env scripts/mirror-to-b2.mjs [--prune] [--dry-run] [--force] [--concurrency=4]
//                                                               [--max-delete-share=0.1] [--max-delete-floor=25]
//
// Env, primary: S3_ENDPOINT, S3_REGION, S3_BUCKET, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY, S3_PREFIX (optional)
// Env, B2:      B2_ENDPOINT, B2_REGION, B2_BUCKET, B2_ACCESS_KEY_ID, B2_SECRET_ACCESS_KEY, B2_PREFIX (optional, default S3_PREFIX)
//
// Copy: each copy streams from the primary straight to B2, signed with the blob's SHA-256, so B2 refuses anything that
// doesn't match its name. A B2 copy of the wrong size is reported and left alone.
// Prune (--prune only): deletes B2 objects under B2_PREFIX whose key is a blob (ends in a sha256) and is not in the
// primary listing. Every key deleted is logged. It refuses, deleting nothing, if:
//   - either listing failed or came back cut short (truncated with no continuation token);
//   - the primary listing is empty (a wrong bucket, prefix or key would look exactly like that);
//   - it would delete more than --max-delete-share of B2's blobs (default 0.1 = 10%) and more than --max-delete-floor
//     objects (default 25, so a small bucket can still prune a few), unless --force.
// --dry-run copies and deletes nothing and says what it would do. One summary line (plus a line per key deleted);
// exits 1 if anything failed, a size differed, or a prune was refused.
import { createS3Client, s3ConfigFromEnv } from '../src/s3.js';

const argv = process.argv.slice(2);
const flag = (f) => argv.includes(f);
const opt = (name, dflt) => { const a = argv.find((x) => x.startsWith(`--${name}=`)); return a ? Number(a.split('=')[1]) : dflt; };
const KNOWN = new Set(['--dry-run', '--prune', '--force']);
for (const a of argv) if (!KNOWN.has(a) && !/^--(concurrency|max-delete-share|max-delete-floor)=[\d.]+$/.test(a)) { console.error(`unknown option ${a}`); process.exit(2); }
const DRY = flag('--dry-run'), PRUNE = flag('--prune'), FORCE = flag('--force');
const CONCURRENCY = Math.max(1, opt('concurrency', 4));
const MAX_SHARE = opt('max-delete-share', 0.1);
const MAX_FLOOR = opt('max-delete-floor', 25);
const HASH_AT_END = /([0-9a-f]{64})$/;
const TAG = '[mirror-to-b2]';

let src, dst;
try {
  src = s3ConfigFromEnv(process.env, 'S3');
  dst = s3ConfigFromEnv({ B2_PREFIX: src.prefix, ...process.env }, 'B2');
} catch (e) { console.error(`${TAG} ${e.message}`); process.exit(2); }
const from = createS3Client(src), to = createS3Client(dst);
const toKey = (k) => dst.prefix + k.slice(src.prefix.length);

const t0 = Date.now();
const n = { primary: 0, primaryBytes: 0, had: 0, copied: 0, bytes: 0, skipped: 0, mismatched: 0, failed: 0, deleted: 0, deleteFailed: 0 };
let listed = true, prune = PRUNE ? 'not run' : 'off';
const pool = async (items, fn) => { await Promise.all(Array.from({ length: CONCURRENCY }, async () => { while (items.length) await fn(items.shift()); })); };
try {
  const there = new Map();
  for await (const o of to.list(dst.prefix)) there.set(o.key, o.size);
  const todo = [], inPrimary = new Set();
  for await (const o of from.list(src.prefix)) {
    n.primary++; n.primaryBytes += o.size;
    inPrimary.add(toKey(o.key));
    const m = HASH_AT_END.exec(o.key);
    if (!m) { n.skipped++; console.warn(`${TAG} skipped ${o.key}: not a blob (no sha256 at the end of its key)`); continue; }
    const have = there.get(toKey(o.key));
    if (have === o.size) { n.had++; continue; }
    if (have != null) { n.mismatched++; console.error(`${TAG} B2 has ${toKey(o.key)} at ${have} bytes, primary at ${o.size}: left alone, look at it by hand`); continue; }
    todo.push({ key: o.key, size: o.size, sha256: m[1] });
  }
  await pool(todo, async (o) => {
    if (DRY) { n.copied++; n.bytes += o.size; return; }
    try {
      await to.put(toKey(o.key), { body: () => from.get(o.key), size: o.size, sha256: o.sha256 });
      n.copied++; n.bytes += o.size;
    } catch (e) { n.failed++; console.error(`${TAG} FAILED ${o.key}: ${e.message}`); }
  });

  if (PRUNE) {
    // Only blob keys (ending in a sha256) are ever pruned; anything else someone put in B2 is not ours to delete.
    const b2Blobs = [...there.keys()].filter((k) => HASH_AT_END.test(k));
    const gone = b2Blobs.filter((k) => !inPrimary.has(k));
    const limit = Math.max(Math.floor(b2Blobs.length * MAX_SHARE), MAX_FLOOR);
    if (n.primary === 0 && gone.length) {
      prune = 'REFUSED (primary listing is empty)';
      console.error(`${TAG} prune refused: the primary listing of ${src.bucket}/${src.prefix} is empty, which is what a wrong bucket, prefix or key looks like. Nothing deleted.`);
    } else if (gone.length > limit && !FORCE) {
      prune = `REFUSED (${gone.length} of ${b2Blobs.length})`;
      console.error(`${TAG} prune refused: it would delete ${gone.length} of ${b2Blobs.length} blobs in B2, more than ${Math.round(MAX_SHARE * 100)}% (and more than ${MAX_FLOOR}). Check the settings; run with --force if this is right. Nothing deleted.`);
    } else {
      prune = DRY ? 'dry run' : 'done';
      await pool([...gone], async (k) => {
        if (DRY) { n.deleted++; console.log(`${TAG} would delete ${dst.bucket}/${k}`); return; }
        try { await to.del(k); n.deleted++; console.log(`${TAG} deleted ${dst.bucket}/${k}`); }
        catch (e) { n.deleteFailed++; console.error(`${TAG} FAILED to delete ${k}: ${e.message}`); }
      });
    }
  }
} catch (e) {
  // A listing that failed or was cut short: no copy list we can trust, and above all no prune.
  listed = false;
  n.failed++;
  if (PRUNE) prune = 'REFUSED (listing failed)';
  console.error(`${TAG} FAILED listing: ${e.message}`);
} finally { from.close(); to.close(); }

const gb = (b) => (b / 2 ** 30).toFixed(2);
console.log(`${TAG} ${DRY ? 'dry run · ' : ''}${listed ? '' : 'incomplete · '}primary ${src.bucket}/${src.prefix} ${n.primary} objects (${gb(n.primaryBytes)} GB) · already in B2 ${n.had} · ${DRY ? 'would copy' : 'copied'} ${n.copied} (${gb(n.bytes)} GB) · skipped ${n.skipped} · size mismatches ${n.mismatched} · failed ${n.failed} · prune ${prune}${PRUNE ? `: ${DRY ? 'would delete' : 'deleted'} ${n.deleted}, failed ${n.deleteFailed}` : ''} · ${((Date.now() - t0) / 1000).toFixed(1)}s`);
process.exit(n.failed || n.mismatched || n.deleteFailed || prune.startsWith('REFUSED') ? 1 : 0);
