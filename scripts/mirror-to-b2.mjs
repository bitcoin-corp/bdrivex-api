// Nightly second copy: copy every object in the primary bucket that Backblaze B2 doesn't have yet. Blobs are named by
// the SHA-256 of their bytes, so a key that exists in B2 at the same size is the same blob. Never deletes from B2 (v1),
// so a blob deleted here stays in B2 until someone prunes it by hand.
//
//   node --env-file=/srv/bdrivex/.env scripts/mirror-to-b2.mjs [--dry-run] [--concurrency=4]
//
// Env, primary: S3_ENDPOINT, S3_REGION, S3_BUCKET, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY, S3_PREFIX (optional)
// Env, B2:      B2_ENDPOINT, B2_REGION, B2_BUCKET, B2_ACCESS_KEY_ID, B2_SECRET_ACCESS_KEY, B2_PREFIX (optional, default S3_PREFIX)
// Each copy streams from the primary straight to B2, signed with the blob's SHA-256, so B2 refuses anything that
// doesn't match its name. Prints one summary line; exits 1 if anything failed or a B2 copy has the wrong size.
import { createS3Client, s3ConfigFromEnv } from '../src/s3.js';

const argv = process.argv.slice(2);
const DRY = argv.includes('--dry-run');
for (const a of argv) if (a !== '--dry-run' && !a.startsWith('--concurrency=')) { console.error(`unknown option ${a}`); process.exit(2); }
const CONCURRENCY = Math.max(1, Number(argv.find((a) => a.startsWith('--concurrency='))?.split('=')[1] || 4));
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
const n = { primary: 0, primaryBytes: 0, had: 0, copied: 0, bytes: 0, skipped: 0, mismatched: 0, failed: 0 };
let listed = true;
try {
  const there = new Map();
  for await (const o of to.list(dst.prefix)) there.set(o.key, o.size);
  const todo = [];
  for await (const o of from.list(src.prefix)) {
    n.primary++; n.primaryBytes += o.size;
    const m = HASH_AT_END.exec(o.key);
    if (!m) { n.skipped++; console.warn(`${TAG} skipped ${o.key}: not a blob (no sha256 at the end of its key)`); continue; }
    const have = there.get(toKey(o.key));
    if (have === o.size) { n.had++; continue; }
    if (have != null) { n.mismatched++; console.error(`${TAG} B2 has ${toKey(o.key)} at ${have} bytes, primary at ${o.size}: left alone, look at it by hand`); continue; }
    todo.push({ key: o.key, size: o.size, sha256: m[1] });
  }
  const copy = async (o) => {
    if (DRY) { n.copied++; n.bytes += o.size; return; }
    try {
      await to.put(toKey(o.key), { body: () => from.get(o.key), size: o.size, sha256: o.sha256 });
      n.copied++; n.bytes += o.size;
    } catch (e) { n.failed++; console.error(`${TAG} FAILED ${o.key}: ${e.message}`); }
  };
  await Promise.all(Array.from({ length: CONCURRENCY }, async () => { while (todo.length) await copy(todo.shift()); }));
} catch (e) {
  listed = false;
  n.failed++;
  console.error(`${TAG} FAILED listing: ${e.message}`);
} finally { from.close(); to.close(); }

const gb = (b) => (b / 2 ** 30).toFixed(2);
console.log(`${TAG} ${DRY ? 'dry run · ' : ''}${listed ? '' : 'incomplete · '}primary ${src.bucket}/${src.prefix} ${n.primary} objects (${gb(n.primaryBytes)} GB) · already in B2 ${n.had} · ${DRY ? 'would copy' : 'copied'} ${n.copied} (${gb(n.bytes)} GB) · skipped ${n.skipped} · size mismatches ${n.mismatched} · failed ${n.failed} · ${((Date.now() - t0) / 1000).toFixed(1)}s`);
process.exit(n.failed || n.mismatched ? 1 : 0);
