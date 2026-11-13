// Copy every blob in DATA_DIR/blobs (the fs store) to the S3 bucket, and check each copy. Safe to run again: blobs
// already in the bucket at the right size are skipped. Deletes nothing, local or remote.
//
//   node --env-file=/srv/bdrivex/.env scripts/migrate-blobs-to-s3.mjs [--dry-run] [--verify-existing] [--concurrency=4]
//
// Env: DATA_DIR, S3_ENDPOINT, S3_REGION, S3_BUCKET, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY, S3_PREFIX (optional).
//   --dry-run          look only: say what would be uploaded (reads the bucket, writes nothing)
//   --verify-existing  also download and re-hash blobs that were already in the bucket (slow; the default checks size)
// Each blob uploaded is signed with its SHA-256 (the bucket refuses bytes that don't match), then checked: its size by
// HEAD and its SHA-256 by downloading it again. Exit code 0 only if every blob is in the bucket and checked.
//
// Order for switching a server over: run this, set BLOB_STORE=s3, restart, run this again (to catch blobs that arrived
// in between), and keep DATA_DIR/blobs until you are happy. Then remove it by hand.
import { createHash } from 'node:crypto';
import { createReadStream, existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { createS3Client, s3ConfigFromEnv } from '../src/s3.js';

const args = new Set(process.argv.slice(2).filter((a) => !a.startsWith('--concurrency=')));
const DRY = args.has('--dry-run');
const VERIFY_EXISTING = args.has('--verify-existing');
for (const a of args) if (!['--dry-run', '--verify-existing'].includes(a)) { console.error(`unknown option ${a}`); process.exit(2); }
const CONCURRENCY = Math.max(1, Number(process.argv.find((a) => a.startsWith('--concurrency='))?.split('=')[1] || 4));
const DATA = process.env.DATA_DIR || join(process.cwd(), 'data');
const HASH = /^[0-9a-f]{64}$/;
const log = (...a) => console.log('[migrate-blobs]', ...a);

let cfg;
try { cfg = s3ConfigFromEnv(process.env, 'S3'); } catch (e) { console.error(`[migrate-blobs] ${e.message}`); process.exit(2); }
const s3 = createS3Client(cfg);
const keyOf = (h) => cfg.prefix + h;

function localBlobs() {
  const root = join(DATA, 'blobs');
  if (!existsSync(root)) return [];
  const out = [];
  for (const a of readdirSync(root)) for (const b of existsSync(join(root, a)) && statSync(join(root, a)).isDirectory() ? readdirSync(join(root, a)) : []) {
    const dir = join(root, a, b);
    if (!statSync(dir).isDirectory()) continue;
    for (const h of readdirSync(dir)) if (HASH.test(h) && h.startsWith(a + b)) out.push({ hash: h, path: join(dir, h), size: statSync(join(dir, h)).size });
  }
  return out;
}

async function sha256Of(stream) {
  const h = createHash('sha256');
  for await (const c of stream) h.update(c);
  return h.digest('hex');
}

async function verify(b) {
  const size = await s3.head(keyOf(b.hash));
  if (size !== b.size) throw new Error(`bucket copy is ${size ?? 'missing'}, expected ${b.size} bytes`);
  const got = await sha256Of(await s3.get(keyOf(b.hash)));
  if (got !== b.hash) throw new Error(`bucket copy hashes to ${got}`);
}

const t0 = Date.now();
const blobs = localBlobs();
const total = blobs.reduce((n, b) => n + b.size, 0);
log(`${DRY ? 'dry run: ' : ''}${blobs.length} local blobs (${(total / 2 ** 30).toFixed(2)} GB) in ${join(DATA, 'blobs')} -> ${new URL(cfg.endpoint).host}/${cfg.bucket}/${cfg.prefix}`);
const n = { present: 0, uploaded: 0, wouldUpload: 0, bytes: 0, failed: 0 };

async function one(b) {
  try {
    const remote = await s3.head(keyOf(b.hash));
    if (remote === b.size) {
      if (VERIFY_EXISTING && !DRY) await verify(b);
      n.present++;
      return;
    }
    if (DRY) { n.wouldUpload++; n.bytes += b.size; log(`would upload ${b.hash} (${b.size} bytes${remote != null ? `, bucket has ${remote}` : ''})`); return; }
    // The local file must really be what its name says, or the bucket would refuse it anyway.
    const local = await sha256Of(createReadStream(b.path));
    if (local !== b.hash) throw new Error(`local file hashes to ${local}: not uploaded, look at it by hand`);
    await s3.put(keyOf(b.hash), { body: () => createReadStream(b.path), size: b.size, sha256: b.hash });
    await verify(b);
    n.uploaded++; n.bytes += b.size;
  } catch (e) {
    n.failed++;
    console.error(`[migrate-blobs] FAILED ${b.hash}: ${e.message}`);
  }
}

const queue = [...blobs];
await Promise.all(Array.from({ length: CONCURRENCY }, async () => { while (queue.length) await one(queue.shift()); }));

// Rows whose blob is in neither place would 404 after the switch (and already do on fs). Report them, if the DB is here.
let missing = 0;
const dbFile = join(DATA, 'bdrivex.db');
if (existsSync(dbFile)) {
  try {
    const { DatabaseSync } = await import('node:sqlite');
    const db = new DatabaseSync(dbFile, { readOnly: true });
    const have = new Set(blobs.map((b) => b.hash));
    for (const { hash } of db.prepare('SELECT DISTINCT hash FROM files').all()) {
      if (have.has(hash)) continue;
      if ((await s3.head(keyOf(hash))) == null) { missing++; console.error(`[migrate-blobs] file row ${hash} has no blob locally or in the bucket`); }
    }
    db.close();
  } catch (e) { console.error(`[migrate-blobs] could not check the database: ${e.message}`); }
}
s3.close();

const secs = ((Date.now() - t0) / 1000).toFixed(1);
log(DRY
  ? `dry run done: ${n.present} already in the bucket, ${n.wouldUpload} to upload (${(n.bytes / 2 ** 20).toFixed(1)} MB), ${n.failed} failed, ${missing} rows without a blob, ${secs}s`
  : `done: ${n.present} already in the bucket, ${n.uploaded} uploaded and checked (${(n.bytes / 2 ** 20).toFixed(1)} MB), ${n.failed} failed, ${missing} rows without a blob, ${secs}s`);
process.exit(n.failed ? 1 : 0);
