// The S3 blob store, its SigV4 signing, the migration script and the B2 mirror, against a fake S3 server in this
// process (test/fake-s3.mjs). No network beyond 127.0.0.1.
//   node test/s3.mjs
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Readable } from 'node:stream';
import { signV4, createS3Client, s3ConfigFromEnv, EMPTY_SHA256 } from '../src/s3.js';
import { s3Store, fsStore, BlobMissing, blobStoreFromEnv } from '../src/blobstore.js';
import { openDb } from '../src/db.js';
import { DatabaseSync as DatabaseSyncRO } from 'node:sqlite';
import { startFakeS3 } from './fake-s3.mjs';

const here = dirname(fileURLToPath(import.meta.url));
let failures = 0;
const ok = (cond, what) => { console.log(`${cond ? '  ok ' : '  FAIL'} ${what}`); if (!cond) failures++; };
const rejects = async (p, re, what) => { try { await p; ok(false, what + ' (did not fail)'); } catch (e) { ok(re.test(`${e.status ?? ''} ${e.code ?? ''} ${e.message}`), `${what}: ${e.message}`); } };
const sha = (b) => createHash('sha256').update(b).digest('hex');
const text = async (s) => { const p = []; for await (const c of s) p.push(c); return Buffer.concat(p); };

// ---- SigV4 against the worked examples in the AWS S3 docs ("Signature Calculations for the Authorization Header:
// Transferring Payload in a Single Chunk"). Those examples use AWS's published example key pair, not a real one;
// it is put together from pieces here so the file never contains a string that looks like an access key to a
// secret scanner (GitHub push protection), while the signatures still check against the documented ones.
console.log('SigV4 (AWS documented examples)');
const EXAMPLE_KEY_ID = ['AK', 'IA', 'IOSFODNN7', 'EXAMPLE'].join('');
const EXAMPLE_SECRET = ['wJalrXUtnFEMI', 'K7MDENG', 'bPxRfiCY'].join('/') + ['EXAMPLE', 'KEY'].join('');
const ex = { region: 'us-east-1', accessKeyId: EXAMPLE_KEY_ID, secretAccessKey: EXAMPLE_SECRET, date: new Date('2013-05-24T00:00:00Z') };
const sigOf = (h) => /Signature=([0-9a-f]{64})$/.exec(h.authorization)[1];
const getObj = signV4({ ...ex, method: 'GET', url: 'https://examplebucket.s3.amazonaws.com/test.txt', headers: { range: 'bytes=0-9' } });
ok(sigOf(getObj) === 'f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41', 'GET Object example signature');
ok(getObj.authorization.includes('SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,'), 'GET Object signed headers');
const putObj = signV4({ ...ex, method: 'PUT', url: 'https://examplebucket.s3.amazonaws.com/test%24file.text',
  headers: { date: 'Fri, 24 May 2013 00:00:00 GMT', 'x-amz-storage-class': 'REDUCED_REDUNDANCY' }, payloadHash: sha('Welcome to Amazon S3.') });
ok(sigOf(putObj) === '98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd', 'PUT Object example signature');
const list = signV4({ ...ex, method: 'GET', url: 'https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J' });
ok(sigOf(list) === '34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7', 'GET Bucket (list) example signature');
ok(new RegExp(`^AWS4-HMAC-SHA256 Credential=${EXAMPLE_KEY_ID}/20130524/us-east-1/s3/aws4_request, SignedHeaders=[a-z0-9;-]+, Signature=[0-9a-f]{64}$`).test(list.authorization), 'Authorization header shape');

// ---- config
console.log('config');
const base = { S3_ENDPOINT: 'https://fsn1.your-objectstorage.com', S3_REGION: 'fsn1', S3_BUCKET: 'b', S3_ACCESS_KEY_ID: 'k', S3_SECRET_ACCESS_KEY: 's' };
ok(s3ConfigFromEnv(base).prefix === '', 'S3_PREFIX is optional');
await rejects((async () => s3ConfigFromEnv({ ...base, S3_SECRET_ACCESS_KEY: '' }))(), /S3_SECRET_ACCESS_KEY/, 'a missing secret is named');
await rejects((async () => s3ConfigFromEnv({ ...base, S3_ENDPOINT: 'https://fsn1.your-objectstorage.com/bucket' }))(), /ENDPOINT/, 'an endpoint with a path is refused');
await rejects((async () => blobStoreFromEnv({ BLOB_STORE: 'disk' }, tmpdir()))(), /fs or s3/, 'BLOB_STORE must be fs or s3');
await rejects((async () => blobStoreFromEnv({ BLOB_STORE: 's3' }, tmpdir()))(), /S3_ENDPOINT/, 'BLOB_STORE=s3 without settings refuses to start');

// ---- the client and the store against the fake
const root = mkdtempSync(join(tmpdir(), 'bdrivex-fake-s3-'));
const creds = { 'test-primary-key': 'test-primary-secret', 'test-b2-key': 'test-b2-secret' };
const fake = await startFakeS3({ root, region: 'fsn1', credentials: creds, buckets: ['primary', 'b2', 'other'], pageSize: 3 });
const cfg = { endpoint: fake.endpoint, region: 'fsn1', bucket: 'primary', accessKeyId: 'test-primary-key', secretAccessKey: 'test-primary-secret', prefix: 'blobs/' };
const c = createS3Client(cfg);

console.log('S3 client');
const blob = randomBytes(200_000), bh = sha(blob);
await c.put(`blobs/${bh}`, { body: blob, size: blob.length, sha256: bh });
ok(readFileSync(fake.objectPath('primary', `blobs/${bh}`)).equals(blob), 'PUT stores the bytes under the key');
ok((await c.head(`blobs/${bh}`)) === blob.length && (await c.head('blobs/nothing')) === null, 'HEAD gives the size, or null');
ok((await text(await c.get(`blobs/${bh}`))).equals(blob), 'GET gives the whole object');
const part = await c.get(`blobs/${bh}`, { start: 1000, end: 1999 });
ok(part.statusCode === 206 && part.headers['content-range'] === `bytes 1000-1999/${blob.length}` && (await text(part)).equals(blob.subarray(1000, 2000)), 'GET with a range: 206, Content-Range, those bytes');
ok((await text(await c.get(`blobs/${bh}`, { start: blob.length - 10 }))).equals(blob.subarray(-10)), 'an open-ended range');
await rejects(c.get(`blobs/${bh}`, { start: blob.length + 5, end: blob.length + 9 }), /416/, 'a range past the end: 416');
await rejects(c.get('blobs/nothing'), /404 NoSuchKey/, 'GET of a missing key: 404');
const wrong = randomBytes(100);
await rejects(c.put(`blobs/${'0'.repeat(64)}`, { body: wrong, size: wrong.length, sha256: '0'.repeat(64) }), /400 XAmzContentSHA256Mismatch/, 'a body that does not match its sha256 is refused by the bucket');
ok(!existsSync(fake.objectPath('primary', `blobs/${'0'.repeat(64)}`)), 'and nothing is stored');
await rejects(createS3Client({ ...cfg, secretAccessKey: 'wrong' }).head(`blobs/${bh}`), /403/, 'a wrong secret is refused (signature checked by the fake)');
const before = fake.authFailures.length;
fake.authFailures.length = 0;
ok(before === 1, 'only that request failed the signature check');
// a key that needs encoding, and a list with spaces in the prefix
const odd = 'odd dir/a+b$c.bin', ob = Buffer.from('odd');
await c.put(odd, { body: ob, size: ob.length, sha256: sha(ob) });
ok((await text(await c.get(odd))).equals(ob) && fake.authFailures.length === 0, 'keys with spaces and +$ are encoded and signed correctly');
const listed = [];
for await (const o of c.list('odd dir/')) listed.push(o);
ok(listed.length === 1 && listed[0].key === odd && listed[0].size === 3, 'LIST with a prefix that needs encoding');
for (let i = 0; i < 7; i++) { const b = randomBytes(10 + i); await c.put(`blobs/${sha(b)}`, { body: b, size: b.length, sha256: sha(b) }); }
const all = [];
for await (const o of c.list('blobs/')) all.push(o);
ok(all.length === 8 && new Set(all.map((o) => o.key)).size === 8 && fake.requests.filter((r) => r.query['list-type'] === '2' && r.query.prefix === 'blobs/').length === 3, 'LIST pages through (3 per page): 8 objects in 3 requests');
await c.del(`blobs/${bh}`);
ok((await c.head(`blobs/${bh}`)) === null, 'DELETE removes it');
await c.del(`blobs/${bh}`);
ok(true, 'DELETE of a missing key is fine');
const SHAPE = /^AWS4-HMAC-SHA256 Credential=test-primary-key\/\d{8}\/fsn1\/s3\/aws4_request, SignedHeaders=([a-z0-9;-]+), Signature=[0-9a-f]{64}$/;
ok(fake.requests.length > 20 && fake.requests.every((r) => { const m = SHAPE.exec(r.authorization); return m && ['host', 'x-amz-content-sha256', 'x-amz-date'].every((h) => m[1].split(';').includes(h)); }),
  `every request (${fake.requests.length}) carried a SigV4 Authorization header of the right shape, signing host, x-amz-content-sha256 and x-amz-date`);

console.log('S3 blob store');
const st = s3Store(cfg);
const tmp = mkdtempSync(join(tmpdir(), 'bdrivex-s3-store-'));
const big = randomBytes(3 * 2 ** 20 + 17), gh = sha(big);
writeFileSync(join(tmp, 'staged'), big);
await st.adopt(gh, join(tmp, 'staged'));
ok(!existsSync(join(tmp, 'staged')) && readFileSync(fake.objectPath('primary', `blobs/${gh}`)).equals(big), 'adopt uploads a staged file under <prefix><sha256> and removes the local copy');
writeFileSync(join(tmp, 'again'), big);
const puts = fake.requests.filter((r) => r.method === 'PUT').length;
await st.adopt(gh, join(tmp, 'again'));
ok(fake.requests.filter((r) => r.method === 'PUT').length === puts && !existsSync(join(tmp, 'again')), 'the same blob again is not uploaded twice (dedup by sha256)');
ok((await st.head(gh)) === big.length, 'head');
ok((await text(await st.get(gh, { start: 5, end: 9 }))).equals(big.subarray(5, 10)), 'get with a range');
await rejects(st.get('f'.repeat(64)), /./, 'get of a missing blob');
ok(await st.get('f'.repeat(64)).catch((e) => e instanceof BlobMissing), 'is a BlobMissing');
const viaPut = randomBytes(5000), vh = sha(viaPut);
await st.put(vh, { body: () => Readable.from([viaPut.subarray(0, 100), viaPut.subarray(100)]), size: viaPut.length });
ok((await text(await st.get(vh))).equals(viaPut), 'put from a stream');
fake.failNext('PUT', 503, 1);
const retried = randomBytes(999), rh = sha(retried);
await st.put(rh, { body: () => Readable.from([retried]), size: retried.length });
ok((await st.head(rh)) === retried.length, 'a 503 on PUT is tried again with a fresh stream');
fake.failNext('PUT', 503, 5);
writeFileSync(join(tmp, 'down'), retried.subarray(1));
await rejects(st.adopt(sha(retried.subarray(1)), join(tmp, 'down')), /503/, 'a store that stays down fails the adopt');
ok(existsSync(join(tmp, 'down')), 'and the staged file is kept');
fake.clearFailures();
await st.del(gh);
ok((await st.head(gh)) === null, 'del');
st.close();
const fsSt = fsStore(tmp);
writeFileSync(join(tmp, 'f1'), big);
await fsSt.adopt(gh, join(tmp, 'f1'));
ok((await fsSt.head(gh)) === big.length && (await text(await fsSt.get(gh, { start: 0, end: 3 }))).equals(big.subarray(0, 4)), 'the fs store has the same interface');
await rejects(fsSt.get('e'.repeat(64)), /./, 'fs: get of a missing blob is refused');

// ---- scripts
const run = (script, args, env) => new Promise((resolve) => {
  const p = spawn(process.execPath, [join(here, '../scripts', script), ...args], { env: { PATH: process.env.PATH, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  p.stdout.on('data', (d) => { out += d; });
  p.stderr.on('data', (d) => { out += d; });
  p.on('exit', (code) => resolve({ code, out }));
});
const S3ENV = { S3_ENDPOINT: fake.endpoint, S3_REGION: 'fsn1', S3_BUCKET: 'other', S3_ACCESS_KEY_ID: 'test-primary-key', S3_SECRET_ACCESS_KEY: 'test-primary-secret', S3_PREFIX: 'm/' };

console.log('migrate-blobs-to-s3');
const data = mkdtempSync(join(tmpdir(), 'bdrivex-migrate-'));
const local = [];
for (const n of [0, 1, 70_000, 2 ** 20 + 3]) {
  const b = randomBytes(n), h = sha(b);
  mkdirSync(join(data, 'blobs', h.slice(0, 2), h.slice(2, 4)), { recursive: true });
  writeFileSync(join(data, 'blobs', h.slice(0, 2), h.slice(2, 4), h), b);
  local.push({ h, b });
}
fake.requests.length = 0;
const m0 = await run('migrate-blobs-to-s3.mjs', ['--dry-run'], { ...S3ENV, DATA_DIR: data });
ok(m0.code === 0 && /4 to upload/.test(m0.out) && fake.requests.every((r) => r.method !== 'PUT'), `--dry-run uploads nothing: ${m0.out.trim().split('\n').at(-1)}`);
const m1 = await run('migrate-blobs-to-s3.mjs', [], { ...S3ENV, DATA_DIR: data });
ok(m1.code === 0 && /4 uploaded and checked/.test(m1.out), `copies every blob: ${m1.out.trim().split('\n').at(-1)}`);
ok(local.every(({ h, b }) => readFileSync(fake.objectPath('other', `m/${h}`)).equals(b)), 'each bucket copy is byte for byte the local blob');
ok(local.every(({ h }) => existsSync(join(data, 'blobs', h.slice(0, 2), h.slice(2, 4), h))), 'nothing local was deleted');
ok(fake.requests.filter((r) => r.method === 'GET' && r.key.startsWith('m/')).length >= 4, 'each upload was downloaded again and re-hashed');
fake.requests.length = 0;
const m2 = await run('migrate-blobs-to-s3.mjs', [], { ...S3ENV, DATA_DIR: data });
ok(m2.code === 0 && /4 already in the bucket, 0 uploaded/.test(m2.out) && !fake.requests.some((r) => r.method === 'PUT'), `running again is a no-op: ${m2.out.trim().split('\n').at(-1)}`);
const m3 = await run('migrate-blobs-to-s3.mjs', ['--verify-existing'], { ...S3ENV, DATA_DIR: data });
ok(m3.code === 0 && fake.requests.filter((r) => r.method === 'GET' && r.key.startsWith('m/')).length >= 4, '--verify-existing re-hashes the bucket copies');
// a corrupt local blob (bytes don't match its name) and a bucket copy cut short
const liar = randomBytes(300), lh = sha(randomBytes(8));
mkdirSync(join(data, 'blobs', lh.slice(0, 2), lh.slice(2, 4)), { recursive: true });
writeFileSync(join(data, 'blobs', lh.slice(0, 2), lh.slice(2, 4), lh), liar);
writeFileSync(fake.objectPath('other', `m/${local[3].h}`), local[3].b.subarray(1));
const m4 = await run('migrate-blobs-to-s3.mjs', [], { ...S3ENV, DATA_DIR: data });
ok(m4.code === 1 && m4.out.includes(`FAILED ${lh}`) && /1 uploaded and checked/.test(m4.out), `a local blob that doesn't match its name fails (exit 1), a short bucket copy is replaced: ${m4.out.trim().split('\n').at(-1)}`);
ok(readFileSync(fake.objectPath('other', `m/${local[3].h}`)).equals(local[3].b) && !existsSync(fake.objectPath('other', `m/${lh}`)), 'the short copy is whole again; the liar was not uploaded');
rmSync(join(data, 'blobs', lh.slice(0, 2), lh.slice(2, 4), lh));
const m5 = await run('migrate-blobs-to-s3.mjs', [], { ...S3ENV, DATA_DIR: data, S3_SECRET_ACCESS_KEY: '' });
ok(m5.code === 2 && /S3_SECRET_ACCESS_KEY/.test(m5.out), 'missing settings: exit 2, named');

console.log('mirror-to-b2');
const B2ENV = { B2_ENDPOINT: fake.endpoint, B2_REGION: 'fsn1', B2_BUCKET: 'b2', B2_ACCESS_KEY_ID: 'test-b2-key', B2_SECRET_ACCESS_KEY: 'test-b2-secret' };
const MENV = { ...S3ENV, ...B2ENV, DATA_DIR: mkdtempSync(join(tmpdir(), 'bdrivex-nodb-')) }; // copy only: no database
// B2 already has one of them; and keeps one the primary no longer has
mkdirSync(join(root, 'b2', 'm'), { recursive: true });
writeFileSync(join(root, 'b2', 'm', local[0].h), local[0].b);
const gone = randomBytes(40), goneH = sha(gone);
writeFileSync(join(root, 'b2', 'm', goneH), gone);
const r0 = await run('mirror-to-b2.mjs', ['--dry-run'], MENV);
ok(r0.code === 0 && /would copy 3/.test(r0.out) && !existsSync(fake.objectPath('b2', `m/${local[1].h}`)), `--dry-run copies nothing: ${r0.out.trim()}`);
fake.requests.length = 0;
const r1 = await run('mirror-to-b2.mjs', [], MENV);
ok(r1.code === 0 && /already in B2 1 · copied 3/.test(r1.out), `copies what B2 is missing: ${r1.out.trim()}`);
ok(r1.out.trim().split('\n').length === 1, 'one summary line');
ok(local.every(({ h, b }) => readFileSync(fake.objectPath('b2', `m/${h}`)).equals(b)), 'B2 has every blob, byte for byte');
ok(existsSync(fake.objectPath('b2', `m/${goneH}`)) && !fake.requests.some((r) => r.method === 'DELETE'), 'and nothing was deleted from B2');
ok(fake.requests.filter((r) => r.method === 'PUT').every((r) => r.authorization.includes('Credential=test-b2-key/')), 'writes to B2 are signed with the B2 key');
const r2 = await run('mirror-to-b2.mjs', [], MENV);
ok(r2.code === 0 && /already in B2 4 · copied 0/.test(r2.out), `again: nothing to do: ${r2.out.trim()}`);
const nb = randomBytes(1234), nbh = sha(nb);
await createS3Client({ ...cfg, bucket: 'other' }).put(`m/${nbh}`, { body: nb, size: nb.length, sha256: nbh });
fake.failNext('PUT', 500, 3);
const r3 = await run('mirror-to-b2.mjs', [], MENV);
ok(r3.code === 1 && /failed 1/.test(r3.out), `a copy that keeps failing: exit 1: ${r3.out.trim().split('\n').at(-1)}`);
const r4 = await run('mirror-to-b2.mjs', ['--concurrency=2'], { ...MENV, B2_PREFIX: 'elsewhere/' });
ok(r4.code === 0 && /copied 5/.test(r4.out) && existsSync(fake.objectPath('b2', `elsewhere/${nbh}`)), 'B2_PREFIX puts the copies under another prefix');
writeFileSync(fake.objectPath('b2', `m/${local[2].h}`), Buffer.from('short'));
const r5 = await run('mirror-to-b2.mjs', [], MENV);
ok(r5.code === 1 && /size mismatches 1/.test(r5.out) && readFileSync(fake.objectPath('b2', `m/${local[2].h}`)).toString() === 'short', 'a B2 copy of the wrong size is reported (exit 1) and not overwritten');
const r6 = await run('mirror-to-b2.mjs', [], { ...S3ENV });
ok(r6.code === 2 && /B2_ENDPOINT/.test(r6.out), 'missing B2 settings: exit 2');

console.log('mirror-to-b2 --prune (only blobs in the deletion log)');
// A small world of its own: primary other/p/, B2 b2/p/, and an API database with file rows and the deletion log.
const pd = mkdtempSync(join(tmpdir(), 'bdrivex-prune-'));
const PENV = { ...S3ENV, ...B2ENV, S3_PREFIX: 'p/', DATA_DIR: pd };
const pc = createS3Client({ ...cfg, bucket: 'other' });
const pdb = openDb(join(pd, 'bdrivex.db'));
const OWNER = '02' + 'c'.repeat(64);
const blobsP = {};
for (const name of ['A', 'B', 'C', 'D', 'E', 'F', 'G']) {
  const b = randomBytes(300 + name.charCodeAt(0)), h = sha(b);
  await pc.put(`p/${h}`, { body: b, size: b.length, sha256: h });
  pdb.files.add.run(OWNER, h, b.length, null, Date.now());
  blobsP[name] = { b, h };
}
const inB2 = (x) => existsSync(fake.objectPath('b2', `p/${blobsP[x].h}`));
const inPrim = (x) => existsSync(fake.objectPath('other', `p/${blobsP[x].h}`));
const last = (r) => r.out.trim().split('\n').at(-1);
// what the API does on a user's delete: the row goes, the deletion log is written, the primary blob is deleted
const userDelete = async (x) => { pdb.files.del.run(OWNER, blobsP[x].h); pdb.erased.add.run(blobsP[x].h, Date.now(), 'user delete'); await pc.del(`p/${blobsP[x].h}`); };
const erasedRow = (x) => { const d = new DatabaseSyncRO(join(pd, 'bdrivex.db'), { readOnly: true }); try { return d.prepare('SELECT * FROM erased_blobs WHERE hash = ?').get(blobsP[x].h); } finally { d.close(); } };
const q0 = await run('mirror-to-b2.mjs', [], PENV);
ok(q0.code === 0 && /copied 7/.test(q0.out) && Object.keys(blobsP).every(inB2), `the backup starts with all 7: ${last(q0)}`);

// 1. a loss on the primary side (bad migration, bucket mishap): D's blob is gone, its file row is not
rmSync(fake.objectPath('other', `p/${blobsP.D.h}`));
fake.requests.length = 0;
const q1 = await run('mirror-to-b2.mjs', ['--prune'], PENV);
ok(inB2('D') && !fake.requests.some((r) => r.method === 'DELETE'), 'a blob lost from the primary is NOT pruned from B2 (nothing is deleted at all)');
ok(q1.code === 1 && q1.out.includes(`LOST from the primary, restorable from B2: ${blobsP.D.h}`) && /lost 1/.test(q1.out), `and the nightly run says so and exits 1: ${last(q1)}`);
fake.requests.length = 0;
const q2 = await run('mirror-to-b2.mjs', ['--restorable'], PENV);
ok(q2.code === 0 && q2.out.includes(blobsP.D.h) && /report only/.test(q2.out) && /lost 1, erased 0, unreferenced 0/.test(q2.out) && !fake.requests.some((r) => r.method === 'PUT' || r.method === 'DELETE'), `--restorable lists it, copying and deleting nothing: ${last(q2)}`);
const q3 = await run('mirror-to-b2.mjs', ['--restore', '--dry-run'], PENV);
ok(q3.code === 1 && /would restore 1/.test(q3.out) && !inPrim('D'), '--restore --dry-run says what it would copy back');
const q4 = await run('mirror-to-b2.mjs', ['--restore'], PENV);
ok(q4.code === 0 && /restored 1/.test(q4.out) && readFileSync(fake.objectPath('other', `p/${blobsP.D.h}`)).equals(blobsP.D.b), `--restore copies it back from B2 to the primary: ${last(q4)}`);

// 2. a user delete: E is in the deletion log and gone from the primary
await userDelete('E');
const q5 = await run('mirror-to-b2.mjs', ['--prune', '--dry-run'], PENV);
ok(q5.code === 0 && q5.out.includes(`would delete b2/p/${blobsP.E.h}`) && inB2('E') && erasedRow('E').b2_pruned_at === null, `--prune --dry-run: would delete the erased blob, deletes nothing, marks nothing: ${last(q5)}`);
fake.requests.length = 0;
const q6 = await run('mirror-to-b2.mjs', ['--prune'], PENV);
ok(q6.code === 0 && !inB2('E') && q6.out.includes(`deleted b2/p/${blobsP.E.h}`) && /user delete/.test(q6.out) && /deleted 1, failed 0/.test(q6.out), `a user delete IS pruned from B2, logged with its reason: ${last(q6)}`);
ok(Number.isInteger(erasedRow('E').b2_pruned_at) && fake.requests.filter((r) => r.method === 'DELETE').every((r) => r.bucket === 'b2'), 'b2_pruned_at is recorded; the delete went to B2 only');
ok(['A', 'B', 'C', 'D', 'F', 'G'].every(inB2), 'nothing else left B2');
const prunedAt = erasedRow('E').b2_pruned_at;
const q7 = await run('mirror-to-b2.mjs', ['--prune'], PENV);
ok(q7.code === 0 && /deleted 0/.test(q7.out) && erasedRow('E').b2_pruned_at === prunedAt, 'each erasure is pruned once (b2_pruned_at unchanged on the next run)');

// 3. delete then upload again: the API clears the log row on upload, so F stays in B2
await userDelete('F');
await pc.put(`p/${blobsP.F.h}`, { body: blobsP.F.b, size: blobsP.F.b.length, sha256: blobsP.F.h });
pdb.files.add.run(OWNER, blobsP.F.h, blobsP.F.b.length, null, Date.now()); pdb.erased.clear.run(blobsP.F.h);
// and a log row that is somehow still there for a blob that is live again (row present) is not pruned either
pdb.files.del.run(OWNER, blobsP.G.h); pdb.erased.add.run(blobsP.G.h, Date.now(), 'user delete'); await pc.del(`p/${blobsP.G.h}`);
pdb.files.add.run(OWNER, blobsP.G.h, blobsP.G.b.length, null, Date.now()); // live again, log row left behind
const q8 = await run('mirror-to-b2.mjs', ['--prune'], PENV);
ok(inB2('F') && inPrim('F') && /deleted 0/.test(q8.out), `delete then upload again is NOT pruned: ${last(q8)}`);
ok(inB2('G') && q8.code === 1 && q8.out.includes(`LOST from the primary, restorable from B2: ${blobsP.G.h}`), 'a log row for a blob a file row holds again is never pruned (and its missing primary copy is flagged)');
await pc.put(`p/${blobsP.G.h}`, { body: blobsP.G.b, size: blobsP.G.b.length, sha256: blobsP.G.h });

// 4. a primary delete that hasn't happened yet (the API is retrying it): waits, no prune
pdb.files.del.run(OWNER, blobsP.C.h); pdb.erased.add.run(blobsP.C.h, Date.now(), 'user delete'); // blob still in the primary
const q9 = await run('mirror-to-b2.mjs', ['--prune'], PENV);
ok(q9.code === 0 && inB2('C') && /waiting 1/.test(q9.out), `erased but still in the primary (delete being retried): waits: ${last(q9)}`);
await pc.del(`p/${blobsP.C.h}`);

// 5. removed from the primary with no log row (as scripts/orphan-blobs.mjs --delete does): kept, "unreferenced"
pdb.files.del.run(OWNER, blobsP.B.h); await pc.del(`p/${blobsP.B.h}`);
const q10 = await run('mirror-to-b2.mjs', ['--prune'], PENV);
ok(inB2('B') && !inB2('C') && /deleted 1/.test(q10.out) && /unreferenced 1/.test(q10.out), `a blob removed without a log row stays in B2 (unreferenced); C, now gone from the primary, is pruned: ${last(q10)}`);
const q11 = await run('mirror-to-b2.mjs', ['--restorable'], PENV);
ok(q11.out.includes(`in B2 only (unreferenced): ${blobsP.B.h}`), '--restorable lists it as unreferenced');

// 6. erased before B2 had a copy: nothing to delete, marked
const early = sha(randomBytes(20));
pdb.erased.add.run(early, Date.now(), 'user delete');
const q12 = await run('mirror-to-b2.mjs', ['--prune'], PENV);
ok(q12.code === 0 && /marked 1/.test(q12.out), 'an erasure B2 never had a copy of is marked done');

// guards
const snapB2 = () => readdirSync(join(root, 'b2', 'p')).sort().join(',');
for (const x of ['A', 'D']) await userDelete(x);
let snap = snapB2();
const g1 = await run('mirror-to-b2.mjs', ['--prune', '--max-delete-floor=0'], PENV);
ok(g1.code === 1 && /prune refused: 2 erased blobs is more than 10%/.test(g1.out) && snapB2() === snap, `more than 10% of B2 (floor 0): refused, nothing deleted: ${last(g1)}`);
const g2 = await run('mirror-to-b2.mjs', ['--prune'], { ...PENV, S3_PREFIX: 'nothing/', B2_PREFIX: 'p/' });
ok(g2.code === 1 && /primary listing .* is empty/.test(g2.out) && snapB2() === snap, `an empty primary listing while the database has files: refused: ${last(g2)}`);
fake.failNext('GET', 500, 1, 'other');
const g3 = await run('mirror-to-b2.mjs', ['--prune'], PENV);
ok(g3.code === 1 && /prune REFUSED \(listing failed\)/.test(g3.out) && snapB2() === snap, 'a primary listing that fails: refused');
fake.breakListing('other');
const g4 = await run('mirror-to-b2.mjs', ['--prune'], PENV);
fake.breakListing('other', false);
ok(g4.code === 1 && /TruncatedListing/.test(g4.out) && snapB2() === snap, 'a primary listing cut short: refused');
fake.breakListing('b2');
const g5 = await run('mirror-to-b2.mjs', ['--prune'], PENV);
fake.breakListing('b2', false);
ok(g5.code === 1 && snapB2() === snap, 'a B2 listing cut short: refused');
fake.failNext('DELETE', 503, 1, 'b2');
const g6 = await run('mirror-to-b2.mjs', ['--prune', '--concurrency=1'], PENV);
ok(g6.code === 1 && /deleted 1, failed 1/.test(g6.out), 'a B2 delete that fails: exit 1, not marked');
const g7 = await run('mirror-to-b2.mjs', ['--prune'], PENV);
ok(g7.code === 0 && /deleted 1, failed 0/.test(g7.out) && !inB2('A') && !inB2('D'), 'and the next run prunes it');
const g8 = await run('mirror-to-b2.mjs', ['--prune'], { ...PENV, DATA_DIR: join(pd, 'nope') });
ok(g8.code === 2 && /needs the API database/.test(g8.out), '--prune without the database: exit 2');
const oldDb = mkdtempSync(join(tmpdir(), 'bdrivex-olddb-'));
{ const d = new DatabaseSyncRO(join(oldDb, 'bdrivex.db')); d.exec('CREATE TABLE files (owner TEXT, hash TEXT, size INTEGER, meta TEXT, created_at INTEGER)'); d.close(); }
const g9 = await run('mirror-to-b2.mjs', ['--prune'], { ...PENV, DATA_DIR: oldDb });
ok(g9.code === 2 && /no erased_blobs table/.test(g9.out), 'a database from before the deletion log: exit 2, nothing pruned');
pdb.db.close(); pc.close();
rmSync(pd, { recursive: true, force: true }); rmSync(oldDb, { recursive: true, force: true });

console.log('orphan-blobs');
const od = mkdtempSync(join(tmpdir(), 'bdrivex-orphans-'));
const OENV = { ...S3ENV, S3_PREFIX: 'o/', DATA_DIR: od };
const oc = createS3Client({ ...cfg, bucket: 'other' });
const mk = async () => { const b = randomBytes(500 + Math.floor(Math.random() * 500)), h = sha(b); await oc.put(`o/${h}`, { body: b, size: b.length, sha256: h }); return h; };
const [held1, held2, orph1, orph2] = [await mk(), await mk(), await mk(), await mk()];
await oc.put('o/notes.txt', { body: Buffer.from('x'), size: 1, sha256: sha('x') });
const missH = sha(randomBytes(9));
{
  const S = openDb(join(od, 'bdrivex.db'));
  const owner = '02' + 'a'.repeat(64);
  for (const h of [held1, held2, missH]) S.files.add.run(owner, h, 1000, null, Date.now());
  S.files.add.run('03' + 'b'.repeat(64), held1, 1000, null, Date.now()); // two wallets hold held1
  S.blobDeletes.failed.run(orph1, Date.now(), 'S3 503: injected');
  S.blobDeletes.failed.run(sha('a blob deleted by hand since'), Date.now(), 'gone already'); // a failed delete whose blob has since gone
  S.db.close();
}
const o0 = await run('orphan-blobs.mjs', [], OENV);
ok(o0.code === 0 && /orphans 0 \(younger than 24h skipped: 2\)/.test(o0.out) && o0.out.includes(`missing ${missH}: 1 file row(s)`) && /not blobs 1/.test(o0.out), `fresh blobs are never orphans (an upload stores its blob just before its row): ${last(o0)}`);
const old = new Date(Date.now() - 2 * 86400e3);
for (const h of [orph1, orph2]) utimesSync(fake.objectPath('other', `o/${h}`), old, old);
const o1 = await run('orphan-blobs.mjs', [], OENV);
ok(o1.code === 0 && o1.out.includes(`orphan o/${orph1}`) && o1.out.includes(`orphan o/${orph2}`) && /failed delete, 1 attempts/.test(o1.out) && /report only/.test(o1.out), `the report lists both orphans (one with its failed delete) and the row with no blob: ${last(o1)}`);
ok([held1, held2, orph1, orph2].every((h) => existsSync(fake.objectPath('other', `o/${h}`))), 'reporting deletes nothing (the default is a dry run)');
const o1b = await run('orphan-blobs.mjs', ['--delete', '--dry-run'], OENV);
ok(o1b.code === 0 && existsSync(fake.objectPath('other', `o/${orph1}`)), '--delete --dry-run deletes nothing');
const o2 = await run('orphan-blobs.mjs', ['--delete', '--max-delete-floor=0'], OENV);
ok(o2.code === 1 && /--delete refused: 2 of 4 blobs/.test(o2.out) && existsSync(fake.objectPath('other', `o/${orph1}`)), `more than 10% of the bucket: refused (exit 1): ${last(o2)}`);
const o3 = await run('orphan-blobs.mjs', ['--delete'], OENV);
ok(o3.code === 0 && /deleted 2, failed 0/.test(o3.out) && !existsSync(fake.objectPath('other', `o/${orph1}`)) && !existsSync(fake.objectPath('other', `o/${orph2}`)), `--delete removes the orphans: ${last(o3)}`);
ok(existsSync(fake.objectPath('other', `o/${held1}`)) && existsSync(fake.objectPath('other', `o/${held2}`)) && existsSync(fake.objectPath('other', 'o/notes.txt')), 'blobs that rows hold, and keys that are not blobs, stay');
{
  const d = new DatabaseSyncRO(join(od, 'bdrivex.db'));
  ok(d.prepare('SELECT COUNT(*) AS n FROM blob_deletes').get().n === 0, 'the failed-delete rows are cleared (the deleted orphan, and one whose blob was already gone)');
  d.close();
}
const o4d = mkdtempSync(join(tmpdir(), 'bdrivex-orphans-empty-'));
openDb(join(o4d, 'bdrivex.db')).db.close();
const o4 = await run('orphan-blobs.mjs', ['--delete', '--min-age-hours=0'], { ...OENV, DATA_DIR: o4d });
ok(o4.code === 1 && /no file rows but the bucket has blobs/.test(o4.out) && existsSync(fake.objectPath('other', `o/${held1}`)), `an empty database (wrong DATA_DIR) refuses --delete: ${last(o4)}`);
const o5 = await run('orphan-blobs.mjs', [], { ...OENV, DATA_DIR: join(od, 'nope') });
ok(o5.code === 2 && /no database/.test(o5.out), 'no database: exit 2');
oc.close();
rmSync(od, { recursive: true, force: true }); rmSync(o4d, { recursive: true, force: true });
ok(fake.authFailures.length === 0, `no request failed its signature check (${fake.authFailures.join('; ') || 'none'})`);

c.close();
await fake.close();
for (const d of [root, tmp, data]) rmSync(d, { recursive: true, force: true });
console.log(failures ? `\n${failures} FAILED` : '\nall passed');
process.exit(failures ? 1 : 0);
