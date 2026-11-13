// End to end against a real server on a temp data dir, with the site's own client code:
// sign in (throwaway key) -> upload -> link -> download as a stranger -> same SHA-256. Plus the failure cases.
//   pnpm test [file]      (default: the APK for Jon if it's on the Desktop, else 24 MB of random bytes)
//   BLOB_STORE=s3 pnpm test   the same, with every server storing blobs in a fake S3 bucket run in this process
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, openSync, readSync, readFileSync, writeFileSync, statSync, rmSync, readdirSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join, resolve, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PrivateKey, ProtoWallet } from '@bsv/sdk';

const here = dirname(fileURLToPath(import.meta.url));
const SITE = resolve(process.env.SITE_DIR || join(here, '../../bdrivex-site'));
const { uploadFile, openLink, downloadLink, shareUrl, parseShare, api, saveKeyWrap, unwrapKey, makeLink, openBoundLink, linkInfo, wrapForRecipient, unwrapFromSender } = await import(join(SITE, 'js/bdx-client.js'));
const { newSeal, sealSegment, sealMeta, importKey, b64u } = await import(join(SITE, 'js/bdx-crypto.js'));
const { parseRecipient } = await import(join(SITE, 'js/paymail.js'));
const { DatabaseSync } = await import('node:sqlite');
const { startFakeS3 } = await import('./fake-s3.mjs');
const { keyHash } = await import('../src/admin.js');

// Where blobs go: the fs store (default) or, with BLOB_STORE=s3, a fake S3 bucket here, one prefix per server's data dir.
const S3 = process.env.BLOB_STORE === 's3';
const s3root = S3 ? mkdtempSync(join(tmpdir(), 'bdrivex-fake-s3-')) : null;
const s3fake = S3 ? await startFakeS3({ root: s3root, region: 'fsn1', credentials: { 'test-key-id': 'test-secret' }, buckets: ['bdrivex', 'b2mirror'] }) : null;
const storeEnv = (dir) => S3
  ? { BLOB_STORE: 's3', S3_ENDPOINT: s3fake.endpoint, S3_REGION: 'fsn1', S3_BUCKET: 'bdrivex', S3_ACCESS_KEY_ID: 'test-key-id', S3_SECRET_ACCESS_KEY: 'test-secret', S3_PREFIX: `${basename(dir)}/`, BLOB_DELETE_RETRY_MS: '300' }
  : { BLOB_STORE: 'fs' };
const blobFile = (dir, h) => S3 ? s3fake.objectPath('bdrivex', `${basename(dir)}/${h}`) : join(dir, 'blobs', h.slice(0, 2), h.slice(2, 4), h);
const placeBlob = (dir, h, buf) => { mkdirSync(dirname(blobFile(dir, h)), { recursive: true }); writeFileSync(blobFile(dir, h), buf); };
console.log(`blob store: ${S3 ? `s3 (fake, ${s3fake.endpoint})` : 'fs'}`);
/** Run one of scripts/ against a server's data dir and store; resolves { code, out }. */
const runScript = (dir, script, args) => new Promise((resolve) => {
  const p = spawn(process.execPath, [join(dirname(fileURLToPath(import.meta.url)), '../scripts', script), ...args], { env: { PATH: process.env.PATH, DATA_DIR: dir, ...storeEnv(dir) }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = ''; p.stdout.on('data', (x) => { out += x; }); p.stderr.on('data', (x) => { out += x; });
  p.on('exit', (code) => resolve({ code, out }));
});

const PORT = 8799, BASE = `http://127.0.0.1:${PORT}`, ORIGIN = 'http://127.0.0.1:5173';
const wallet = new ProtoWallet(PrivateKey.fromRandom());
const { publicKey: identityKey } = await wallet.getPublicKey({ identityKey: true });
const data = mkdtempSync(join(tmpdir(), 'bdrivex-test-'));
const srv = spawn(process.execPath, [join(here, '../src/server.js')], {
  env: { ...process.env, PORT: String(PORT), DATA_DIR: data, ALLOWED_ORIGINS: ORIGIN, SESSION_SECRET: randomBytes(32).toString('hex'), SIGNUP: 'open', SHARING: 'open', ...storeEnv(data), QUOTA_BYTES: String(100 * 2 ** 20), QUOTA_OVERRIDES: `${identityKey}:${200 * 2 ** 20}` },
  stdio: ['ignore', 'inherit', 'inherit'],
});
const stop = () => { srv.kill(); rmSync(data, { recursive: true, force: true }); if (s3root) rmSync(s3root, { recursive: true, force: true }); };
process.on('exit', stop);
for (let i = 0; ; i++) { try { await fetch(BASE + '/health'); break; } catch { if (i > 50) throw new Error('server did not start'); await new Promise((r) => setTimeout(r, 100)); } }

let failures = 0;
const ok = (cond, what) => { console.log(`${cond ? '  ok ' : '  FAIL'} ${what}`); if (!cond) failures++; };
const rejects = async (p, re, what) => { try { await p; ok(false, what + ' (did not fail)'); } catch (e) { ok(re.test(String(e.status ?? '') + ' ' + e.message), `${what}: ${e.status ?? ''} ${e.message}`); } };
const sha = (buf) => createHash('sha256').update(buf).digest('hex');

// ---- sign in with a throwaway wallet, exactly as signInWithBwalletX does in the browser
const post = (p, b, h = {}) => fetch(BASE + p, { method: 'POST', headers: { 'content-type': 'application/json', origin: ORIGIN, ...h }, body: JSON.stringify(b) });
async function signIn(w = wallet, key = identityKey) {
  const ch = await (await post('/v1/auth/challenge', { identityKey: key })).json();
  const { signature } = await w.createSignature({ protocolID: ch.protocolID, keyID: ch.keyID, counterparty: 'anyone', data: Array.from(new TextEncoder().encode(ch.message)) });
  return { ch, res: await post('/v1/auth/verify', { identityKey: key, nonce: ch.nonce, signature: Array.from(signature) }) };
}
console.log('sign in');
const { ch, res } = await signIn();
const session = await res.json();
ok(res.status === 200 && session.token && session.identityKey === identityKey, 'verify gives a session token for the identity key');
const replay = await post('/v1/auth/verify', { identityKey, nonce: ch.nonce, signature: [1, 2, 3] });
ok(replay.status === 401, 'a used nonce cannot be tried again');
const bad = await post('/v1/auth/challenge', { identityKey }, { origin: 'https://evil.example' });
ok(bad.status === 403, 'challenge refused from an origin not on the list');
const other = new ProtoWallet(PrivateKey.fromRandom());
const forged = await signIn(other, identityKey);
ok(forged.res.status === 401, 'a signature from a different key is refused');
const T = session.token;
await rejects(api(BASE).get('/v1/files'), /^401/, 'files need a session');
const crossSite = await fetch(BASE + '/v1/files', { headers: { authorization: `Bearer ${T}`, origin: 'https://bphotosx.com' } });
ok(crossSite.status === 401, 'a token signed for one site is refused from another');

// ---- sessions: 7 days, sign out one, sign out everywhere
ok(session.expiresAt - Date.now() > 6.9 * 86400e3 && session.expiresAt - Date.now() <= 7 * 86400e3, 'sessions last 7 days');
const me = (t) => fetch(BASE + '/v1/me', { headers: { authorization: `Bearer ${t}` } }).then((r) => r.status);
const s2 = await (await signIn()).res.json(), s3 = await (await signIn()).res.json();
await fetch(BASE + '/v1/auth/signout', { method: 'POST', headers: { authorization: `Bearer ${s2.token}` } });
ok((await me(s2.token)) === 401 && (await me(s3.token)) === 200 && (await me(T)) === 200, 'sign out ends only that session');
await fetch(BASE + '/v1/auth/signout-all', { method: 'POST', headers: { authorization: `Bearer ${s3.token}` } });
ok((await me(s3.token)) === 401 && (await me(T)) === 401, 'sign out everywhere ends every session for the wallet');
const fresh = await (await signIn()).res.json();
ok((await me(fresh.token)) === 200, 'signing in again afterwards works');
const T2 = fresh.token;

// ---- the file
const arg = process.argv[2];
const apk = join(homedir(), 'Desktop/bwallet-5.2.49-fix-for-jon.apk');
const path = arg ? resolve(arg) : existsSync(apk) ? apk : (() => { const p = join(data, 'random.bin'); writeFileSync(p, randomBytes(24 * 2 ** 20 + 12345)); return p; })();
const size = statSync(path).size;
const want = sha(readFileSync(path));
console.log(`upload ${basename(path)} · ${(size / 2 ** 20).toFixed(1)} MB · sha256 ${want}`);
const fd = openSync(path, 'r');
const source = { size, read: async (s, e) => { const b = Buffer.alloc(e - s); readSync(fd, b, 0, e - s, s); return new Uint8Array(b); } };

// interrupt after the first chunk, then resume with what onStart saved
const ac = new AbortController();
let saved = null, chunks = 0;
await rejects(uploadFile({ base: BASE, token: T2, source, name: basename(path), type: 'application/vnd.android.package-archive', signal: ac.signal,
  onStart: (s) => { saved = s; }, onProgress: () => { if (++chunks === 1) ac.abort(new Error('simulated drop')); } }), /drop|abort/i, 'upload interrupted after one chunk');
const mid = await api(BASE, T2).get(`/v1/uploads/${saved.id}`);
ok(mid.offset > 0 && mid.offset < mid.size, `server kept ${mid.offset} of ${mid.size} bytes`);
const t0 = Date.now();
const up = await uploadFile({ base: BASE, token: T2, source, name: basename(path), type: 'application/vnd.android.package-archive', resume: saved });
ok(HASH(up.hash) && up.key.length === 43, `resumed and completed in ${Date.now() - t0} ms · blob ${up.hash.slice(0, 16)}…`);
function HASH(h) { return /^[0-9a-f]{64}$/.test(h); }
const onDisk = readFileSync(blobFile(data, up.hash));
ok(sha(onDisk) === up.hash, `stored blob (${S3 ? 'in the bucket' : 'on disk'}) is under the sha256 of its bytes`);
ok(!onDisk.includes(readFileSync(path).subarray(4096, 4160)), 'the stored blob does not contain the plaintext');
ok(!onDisk.includes(Buffer.from(basename(path))), 'nor the file name');

// ---- link and download as someone with no wallet
const link = await api(BASE, T2).post('/v1/links', { hash: up.hash, ttl: 7 * 86400 });
const url = shareUrl('https://bdrivex.com', link.id, up.key);
console.log('link', url.replace(/#k=.*/, '#k=…'));
const key = parseShare(new URL(url).hash);
const info = await openLink({ base: BASE, id: link.id, key });
ok(info.meta.name === basename(path) && info.meta.size === size, `link opens: ${info.meta.name}, ${info.meta.size} bytes`);
const parts = [];
const got = await downloadLink({ base: BASE, id: link.id, link: info, sink: { write: (u8) => { parts.push(u8); } } });
const out = Buffer.concat(parts);
ok(out.length === size && sha(out) === want && got.sha256 === want, `downloaded and decrypted: sha256 ${got.sha256}`);

// download resumes with Range after a drop: cut the connection once mid-stream
const realFetch = globalThis.fetch;
let cut = false;
globalThis.fetch = async (u, o) => {
  const r = await realFetch(u, o);
  if (cut || !String(u).endsWith('/blob')) return r;
  cut = true;
  const rd = r.body.getReader();
  let n = 0;
  const body = new ReadableStream({ async pull(c) { const { done, value } = await rd.read(); if (done || (n += value.length) > 3e6) { rd.cancel(); return c.error(new TypeError('network dropped')); } c.enqueue(value); } });
  return new Response(body, { status: r.status, headers: r.headers });
};
const parts2 = [];
const got2 = await downloadLink({ base: BASE, id: link.id, link: info, sink: { write: (u8) => { parts2.push(u8); } } });
globalThis.fetch = realFetch;
ok(cut && got2.sha256 === want, 'download picked up again after a dropped connection');

await rejects(openLink({ base: BASE, id: link.id, key: 'A'.repeat(43) }), /key/i, 'wrong key is caught');

// ---- tampering: flip a byte in the stored blob
const blob = blobFile(data, up.hash);
const orig = readFileSync(blob);
const evil = Buffer.from(orig); evil[orig.length >> 1] ^= 1; writeFileSync(blob, evil);
await rejects(downloadLink({ base: BASE, id: link.id, link: info, sink: { write() {} } }), /decrypt/i, 'a changed byte on the server is caught');
writeFileSync(blob, orig);

// ---- my files, usage, revoke, delete
const mine = await api(BASE, T2).get('/v1/files');
ok(mine.files.length === 1 && mine.files[0].links[0].downloads >= 2 && mine.usage.bytes === up.size, `files: 1, downloads counted ${mine.files[0].links[0].downloads}, usage ${mine.usage.bytes} bytes`);
await api(BASE, T2).del(`/v1/links/${link.id}`);
await rejects(openLink({ base: BASE, id: link.id, key }), /^404/, 'a revoked link stops working');
const short = await api(BASE, T2).post('/v1/links', { hash: up.hash, ttl: 60 });
const dflt = await api(BASE, T2).post('/v1/links', { hash: up.hash });
ok(Math.abs(dflt.expiresAt - Date.now() - 30 * 86400e3) < 60e3, 'links last 30 days by default');
await rejects(api(BASE, T2).post('/v1/links', { hash: up.hash, ttl: 31 * 86400 }), /^400/, 'links can\'t last longer than 30 days');
const rep = await fetch(`${BASE}/v1/s/${dflt.id}/report`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ reason: 'test report' }) });
ok(rep.status === 204, 'anyone with a link can report it');
await rejects(openLink({ base: BASE, id: dflt.id, key: up.key }), /report/, 'a reported link is switched off at once');
ok((await api(BASE, T2).get('/v1/files')).files[0].links.some((l) => l.id === dflt.id && l.reported), 'the sender sees it was reported');
ok(short.expiresAt > Date.now(), 'links can expire');

// ---- small edge sizes (empty, exactly one segment, one byte over)
for (const n of [0, 1, 2 ** 20, 2 ** 20 + 1]) {
  const b = randomBytes(n);
  const u = await uploadFile({ base: BASE, token: T2, source: { size: n, read: async (s, e) => new Uint8Array(b.subarray(s, e)) }, name: `edge-${n}` });
  const l = await api(BASE, T2).post('/v1/links', { hash: u.hash, ttl: null });
  const i = await openLink({ base: BASE, id: l.id, key: u.key });
  const ps = [];
  const d = await downloadLink({ base: BASE, id: l.id, link: i, sink: { write: (x) => { ps.push(x); } } });
  ok(d.sha256 === sha(b) && Buffer.concat(ps).equals(b), `round trip ${n} bytes`);
}

// ---- the server re-hashes and refuses a lie
const fake = await api(BASE, T2).post('/v1/uploads', { size: 64 });
await api(BASE, T2).call('PATCH', `/v1/uploads/${fake.id}`, { body: randomBytes(64), headers: { 'content-type': 'application/offset+octet-stream', 'upload-offset': '0' } });
await rejects(api(BASE, T2).post(`/v1/uploads/${fake.id}/complete`, { sha256: '0'.repeat(64) }), /^422/, 'complete with the wrong sha256 is refused');
const over = await api(BASE, T2).post('/v1/uploads', { size: 64 });
await rejects(api(BASE, T2).call('PATCH', `/v1/uploads/${over.id}`, { body: randomBytes(65), headers: { 'content-type': 'application/offset+octet-stream', 'upload-offset': '0' } }), /^413/, 'a chunk past the declared size is refused');
await rejects(api(BASE, T2).call('PATCH', `/v1/uploads/${over.id}`, { body: randomBytes(8), headers: { 'content-type': 'application/offset+octet-stream', 'upload-offset': '8' } }), /^409/, 'a chunk at the wrong offset is refused');
await rejects(api(BASE, T2).post('/v1/uploads', { size: 300 * 2 ** 20 }), /^413/, 'quota is enforced');
ok((await api(BASE, T2).get('/v1/me')).usage.quota === 200 * 2 ** 20, 'a server-side override raises one wallet\'s quota');
const stranger = new ProtoWallet(PrivateKey.fromRandom());
const sk = (await stranger.getPublicKey({ identityKey: true })).publicKey;
const st = await (await signIn(stranger, sk)).res.json();
ok((await api(BASE, st.token).get('/v1/me')).usage.quota === 100 * 2 ** 20, 'anyone with a wallet can sign up and gets the free quota');
await rejects(api(BASE, st.token).post('/v1/uploads', { size: 3 * 2 ** 30 }), /^413.*2 GB/, 'files over 2 GB are refused');

// bPhotosX-style single PUT by hash
const photo = randomBytes(300_000), ph = sha(photo);
const put = await api(BASE, T2).call('PUT', `/v1/blobs/${ph}`, { body: photo });
ok(put.status === 201, 'PUT /v1/blobs/:sha256 stores a small blob');
await rejects(api(BASE, T2).call('PUT', `/v1/blobs/${'1'.repeat(64)}`, { body: photo }), /^422/, 'PUT with a body that does not match its hash is refused');
const back = Buffer.from(await (await api(BASE, T2).call('GET', `/v1/blobs/${ph}`, { headers: { range: 'bytes=100-199' } })).arrayBuffer());
ok(back.equals(photo.subarray(100, 200)), 'GET /v1/blobs/:sha256 serves Range reads to the owner');
{
  // Range details, the same whichever store is behind it
  const g = (range, method = 'GET') => fetch(`${BASE}/v1/blobs/${ph}`, { method, headers: { authorization: `Bearer ${T2}`, ...(range ? { range } : {}) } });
  const n = photo.length;
  let r = await g('bytes=100-199');
  ok(r.status === 206 && r.headers.get('content-range') === `bytes 100-199/${n}` && r.headers.get('content-length') === '100', 'a range: 206, Content-Range and Content-Length');
  await r.arrayBuffer();
  r = await g(`bytes=${n - 50}-`);
  ok(r.status === 206 && Buffer.from(await r.arrayBuffer()).equals(photo.subarray(n - 50)) && r.headers.get('content-range') === `bytes ${n - 50}-${n - 1}/${n}`, 'an open-ended range');
  r = await g('bytes=-10');
  ok(r.status === 206 && Buffer.from(await r.arrayBuffer()).equals(photo.subarray(n - 10)), 'a suffix range (the last 10 bytes)');
  r = await g(`bytes=${n - 5}-${n + 1000}`);
  ok(r.status === 206 && r.headers.get('content-range') === `bytes ${n - 5}-${n - 1}/${n}` && (await r.arrayBuffer()).byteLength === 5, 'a range past the end is cut to the end');
  r = await g(`bytes=${n}-`);
  ok(r.status === 416 && r.headers.get('content-range') === `bytes */${n}`, 'a range starting past the end: 416, bytes */size');
  await r.arrayBuffer();
  r = await g(null);
  ok(r.status === 200 && r.headers.get('accept-ranges') === 'bytes' && sha(Buffer.from(await r.arrayBuffer())) === ph, 'no range: 200, the whole blob, Accept-Ranges');
  r = await g('bytes=0-9', 'HEAD');
  ok(r.status === 206 && r.headers.get('content-length') === '10', 'HEAD with a range');
}

// ---- v1.1: the file key wrapped by the owner's wallet, kept beside the file
console.log('wallet-wrapped keys');
const wrapOf = async (t = T2) => (await api(BASE, t).get('/v1/files')).files.find((f) => f.hash === up.hash)?.keyWrap;
ok((await wrapOf()) === null, 'a file starts with no wrapped key');
await saveKeyWrap({ base: BASE, token: T2, wallet, hash: up.hash, key: up.key });
const wrap = await wrapOf();
ok(typeof wrap === 'string' && !wrap.includes(up.key), 'PUT /v1/files/:sha256/key keeps the wrap, and it is not the key');
ok((await unwrapKey(wallet, up.hash, wrap)) === up.key, 'the same wallet unwraps the same key (another device, same wallet)');
await rejects(unwrapKey(stranger, up.hash, wrap), /./, 'another wallet cannot unwrap it');
await rejects(unwrapKey(wallet, ph, wrap), /./, 'the wrap is bound to its file (key ID = hash)');
const pub = await api(BASE).get(`/v1/s/${short.id}`);
ok(!('keyWrap' in pub) && !JSON.stringify(pub).includes(wrap), 'a share link never shows the wrap');
await rejects(api(BASE, st.token).call('PUT', `/v1/files/${up.hash}/key`, { json: { keyWrap: 'AAAA' } }), /^404/, 'nobody else can set a wrap on your file');
await rejects(api(BASE, T2).call('PUT', `/v1/files/${up.hash}/key`, { json: { keyWrap: 'not base64url!' } }), /^400/, 'a wrap must be base64url');
await rejects(api(BASE, T2).call('PUT', `/v1/files/${up.hash}/key`, { json: { keyWrap: 'A'.repeat(1025) } }), /^400/, 'and 1 KB at most');
await api(BASE, T2).call('PUT', `/v1/files/${up.hash}/key`, { json: { keyWrap: null } });
ok((await wrapOf()) === null, 'null clears it');

// it was reported above, so it is on legal hold until an admin releases it
const held1 = await fetch(`${BASE}/v1/files/${up.hash}`, { method: 'DELETE', headers: { authorization: `Bearer ${T2}` } });
ok(held1.status === 423 && (await held1.json()).code === 'legal_hold' && existsSync(blob), 'the reported file is on legal hold: DELETE answers 423 and the blob stays');
ok((await runScript(data, 'legal-hold.mjs', ['release', identityKey, up.hash, '--note', 'test', '--yes'])).code === 0, 'an admin releases the hold (scripts/legal-hold.mjs)');
await api(BASE, T2).del(`/v1/files/${up.hash}`);
ok(!existsSync(blob), 'deleting a file removes its blob');
await rejects(openLink({ base: BASE, id: short.id, key: up.key }), /^404/, 'and its links');
ok(readdirSync(join(data, 'tmp')).length === 1, 'only the unfinished test upload is left in tmp');
if (S3) {
  ok(!existsSync(join(data, 'blobs')), 's3: no blob was ever written under DATA_DIR/blobs');
  // the bucket is down when an upload finishes: 503, the upload and its staged bytes are kept, and finishing again works
  const body = randomBytes(5000), bh = sha(body);
  const u = await api(BASE, T2).post('/v1/uploads', { size: body.length });
  await api(BASE, T2).call('PATCH', `/v1/uploads/${u.id}`, { body, headers: { 'content-type': 'application/offset+octet-stream', 'upload-offset': '0' } });
  s3fake.failNext('PUT', 503, 3);
  await rejects(api(BASE, T2).post(`/v1/uploads/${u.id}/complete`, { sha256: bh }), /^503 Storage is not answering/, 's3 down at /complete: 503');
  ok((await api(BASE, T2).get(`/v1/uploads/${u.id}`)).offset === body.length && readdirSync(join(data, 'tmp')).includes(u.id), 'and the upload is kept, with its staged bytes');
  const done = await api(BASE, T2).post(`/v1/uploads/${u.id}/complete`, { sha256: bh });
  ok(done.hash === bh && readFileSync(blobFile(data, bh)).equals(body) && !readdirSync(join(data, 'tmp')).includes(u.id), 'finishing again uploads it to the bucket and clears the staged file');
  // two wallets hold the same blob: deleting one copy keeps it, deleting the last removes it
  const sp = await api(BASE, st.token).call('PUT', `/v1/blobs/${bh}`, { body });
  ok(sp.status === 201 && (await api(BASE, st.token).get('/v1/files')).files.some((f) => f.hash === bh), 'a second wallet stores the same bytes (deduplicated)');
  await api(BASE, T2).del(`/v1/files/${bh}`);
  ok(existsSync(blobFile(data, bh)), 'deleting one holder keeps the blob in the bucket');
  await api(BASE, st.token).del(`/v1/files/${bh}`);
  ok(!existsSync(blobFile(data, bh)), 'deleting the last holder removes it from the bucket');
  // the bucket refuses the delete: the user's delete still succeeds, the blob is recorded and the server retries it
  const ob = randomBytes(3000), oh = sha(ob);
  await api(BASE, T2).call('PUT', `/v1/blobs/${oh}`, { body: ob });
  s3fake.failNext('DELETE', 503, 1);
  const delRes = await fetch(`${BASE}/v1/files/${oh}`, { method: 'DELETE', headers: { authorization: `Bearer ${T2}` } });
  const pendingRows = () => { const d = new DatabaseSync(join(data, 'bdrivex.db')); try { return d.prepare('SELECT hash, attempts FROM blob_deletes').all(); } finally { d.close(); } };
  const rec = pendingRows();
  ok(delRes.status === 204 && (await api(BASE, T2).get('/v1/files')).files.every((f) => f.hash !== oh), 's3 refuses a delete: the user\'s delete still succeeds');
  ok(existsSync(blobFile(data, oh)) && rec.length === 1 && rec[0].hash === oh, 'the orphan blob is recorded in blob_deletes');
  for (let i = 0; i < 50 && (existsSync(blobFile(data, oh)) || pendingRows().length); i++) await new Promise((r) => setTimeout(r, 100));
  ok(!existsSync(blobFile(data, oh)) && pendingRows().length === 0, 'and the server retries it: blob gone, record cleared');
  // a recorded blob that someone uploads again before the retry is kept, and its record dropped
  await api(BASE, T2).call('PUT', `/v1/blobs/${oh}`, { body: ob });
  s3fake.failNext('DELETE', 503, 1);
  await api(BASE, T2).del(`/v1/files/${oh}`);
  await api(BASE, st.token).call('PUT', `/v1/blobs/${oh}`, { body: ob });
  for (let i = 0; i < 50 && pendingRows().length; i++) await new Promise((r) => setTimeout(r, 100));
  ok(pendingRows().length === 0 && existsSync(blobFile(data, oh)) && readFileSync(blobFile(data, oh)).equals(ob), 'a recorded blob that was uploaded again before the retry is kept');
  await api(BASE, st.token).del(`/v1/files/${oh}`);

  // the deletion log, written by the server, and the B2 mirror pruning by it (and only by it)
  const erased = (h) => { const d = new DatabaseSync(join(data, 'bdrivex.db')); try { return d.prepare('SELECT * FROM erased_blobs WHERE hash = ?').get(h); } finally { d.close(); } };
  ok(erased(oh)?.reason === 'user delete', 'deleting the last holder writes the deletion log (erased_blobs, reason user delete)');
  const mirror = (args) => new Promise((resolve) => {
    const p = spawn(process.execPath, [join(here, '../scripts/mirror-to-b2.mjs'), ...args], {
      env: { PATH: process.env.PATH, DATA_DIR: data, ...storeEnv(data), B2_ENDPOINT: s3fake.endpoint, B2_REGION: 'fsn1', B2_BUCKET: 'b2mirror', B2_ACCESS_KEY_ID: 'test-key-id', B2_SECRET_ACCESS_KEY: 'test-secret' },
      stdio: ['ignore', 'pipe', 'pipe'] });
    let out = ''; p.stdout.on('data', (d) => { out += d; }); p.stderr.on('data', (d) => { out += d; });
    p.on('exit', (code) => resolve({ code, out, last: out.trim().split('\n').at(-1) }));
  });
  const inB2 = (h) => existsSync(s3fake.objectPath('b2mirror', `${basename(data)}/${h}`));
  const put = async (b) => { const h = sha(b); await api(BASE, T2).call('PUT', `/v1/blobs/${h}`, { body: b }); return h; };
  const [kb, rb, lb] = [randomBytes(4000), randomBytes(4100), randomBytes(4200)];
  const [kh, rh, lh] = [await put(kb), await put(rb), await put(lb)];
  const mm0 = await mirror(['--prune']);
  ok(mm0.code === 0 && [kh, rh, lh].every(inB2), `mirror: the three new blobs are in B2: ${mm0.last}`);
  // a user delete: pruned from B2
  await api(BASE, T2).del(`/v1/files/${kh}`);
  ok(erased(kh) && erased(kh).b2_pruned_at === null && !existsSync(blobFile(data, kh)), 'a user delete: blob gone from the primary, logged');
  // delete then upload again: the log row is cleared, so it stays in B2
  await api(BASE, T2).del(`/v1/files/${rh}`);
  ok(erased(rh), 'deleted: logged');
  await put(rb);
  ok(!erased(rh), 'uploaded again: the log row is cleared');
  // a loss on the primary side: the blob vanishes from the bucket, the file row stays
  rmSync(blobFile(data, lh));
  const mm1 = await mirror(['--prune']);
  ok(!inB2(kh) && mm1.out.includes(`deleted b2mirror/${basename(data)}/${kh}`) && Number.isInteger(erased(kh).b2_pruned_at), `server + mirror: a user delete IS pruned from B2, and marked: ${mm1.last}`);
  ok(inB2(rh) && existsSync(blobFile(data, rh)), 'delete then upload again is NOT pruned');
  ok(inB2(lh) && mm1.code === 1 && mm1.out.includes(`LOST from the primary, restorable from B2: ${lh}`), 'a primary-side loss is NOT pruned, and the run flags it (exit 1)');
  const mm2 = await mirror(['--restorable']);
  ok(mm2.code === 0 && mm2.out.includes(lh) && /lost 1/.test(mm2.out), `--restorable lists it: ${mm2.last}`);
  const mm3 = await mirror(['--restore']);
  const back2 = Buffer.from(await (await api(BASE, T2).call('GET', `/v1/blobs/${lh}`)).arrayBuffer());
  ok(mm3.code === 0 && back2.equals(lb), 'after --restore the owner downloads it again');
  for (const h of [rh, lh]) await api(BASE, T2).del(`/v1/files/${h}`);
}

// ---- invite-only mode: a second server that admits only the test wallet (and a second invited wallet, O2)
const startServer = async (port, dir, extra = {}) => {
  const p = spawn(process.execPath, [join(here, '../src/server.js')], {
    env: { ...process.env, NODE_ENV: 'production', PORT: String(port), DATA_DIR: dir, ALLOWED_ORIGINS: ORIGIN, SESSION_SECRET: randomBytes(32).toString('hex'), ...storeEnv(dir), ...extra },
    stdio: ['ignore', 'ignore', 'inherit'],
  });
  for (let i = 0; ; i++) { try { await fetch(`http://127.0.0.1:${port}/health`); break; } catch { if (i > 50) throw new Error(`server on ${port} did not start`); await new Promise((r) => setTimeout(r, 100)); } }
  return p;
};
{
  const P2 = 8798, B2 = `http://127.0.0.1:${P2}`, d2 = mkdtempSync(join(tmpdir(), 'bdrivex-test-'));
  const o2 = new ProtoWallet(PrivateKey.fromRandom()), o2k = (await o2.getPublicKey({ identityKey: true })).publicKey;
  const s2 = await startServer(P2, d2, { ALLOWED_KEYS: `${identityKey},${o2k}` });
  const sign = async (w, k) => {
    const c = await (await fetch(B2 + '/v1/auth/challenge', { method: 'POST', headers: { 'content-type': 'application/json', origin: ORIGIN }, body: JSON.stringify({ identityKey: k }) })).json();
    const { signature } = await w.createSignature({ protocolID: c.protocolID, keyID: c.keyID, counterparty: 'anyone', data: Array.from(new TextEncoder().encode(c.message)) });
    return fetch(B2 + '/v1/auth/verify', { method: 'POST', headers: { 'content-type': 'application/json', origin: ORIGIN }, body: JSON.stringify({ identityKey: k, nonce: c.nonce, signature: Array.from(signature) }) });
  };
  const ownerRes = await sign(wallet, identityKey);
  ok(ownerRes.status === 200, 'production defaults to invite-only: an invited wallet signs in');
  const refused = await sign(stranger, sk);
  const rj = await refused.json();
  ok(refused.status === 403 && rj.code === 'not_invited' && /invite-only/.test(rj.error) && rj.message === rj.error, 'and a wallet not on the list is refused: 403 { error, code: not_invited, message }');

  // ---- v1.2: send to one person
  console.log('send to one person (v1.2)');
  const OT = (await ownerRes.json()).token;
  const O2T = (await (await sign(o2, o2k)).json()).token;
  const rw = new ProtoWallet(PrivateKey.fromRandom()), rk = (await rw.getPublicKey({ identityKey: true })).publicKey; // recipient, not invited
  const xw = new ProtoWallet(PrivateKey.fromRandom()), xk = (await xw.getPublicKey({ identityKey: true })).publicKey; // a third wallet, not invited
  ok((await sign(rw, rk)).status === 403, 'before anything is sent to it, a wallet that is not invited cannot sign in');

  const body = randomBytes(3 * 2 ** 20 + 777);
  const up2 = await uploadFile({ base: B2, token: OT, source: { size: body.length, read: async (a, b) => new Uint8Array(body.subarray(a, b)) }, name: 'for-jon.bin', type: 'application/octet-stream' });
  const bl = await makeLink({ base: B2, token: OT, site: 'https://bdrivex.com', hash: up2.hash, key: up2.key, ttl: 7 * 86400, recipient: rk, recipientLabel: '$jon', wallet });
  ok(bl.bound && bl.url === `https://bdrivex.com/s/${bl.id}` && !bl.url.includes('#'), `a link sent to one person has no key in it: ${bl.url.replace(bl.id, '…')}`);

  // input validation on POST /v1/links and PUT /v1/links/:id/recipient
  const O = api(B2, OT);
  await rejects(O.post('/v1/links', { hash: up2.hash, recipient: 'zz' + rk.slice(2) }), /^400.*identity key/, 'recipient must be an identity key (hex)');
  await rejects(O.post('/v1/links', { hash: up2.hash, recipient: '04' + rk.slice(2) }), /^400/, 'recipient must start 02 or 03');
  await rejects(O.post('/v1/links', { hash: up2.hash, recipient: rk + '00' }), /^400/, 'recipient must be 66 characters');
  await rejects(O.post('/v1/links', { hash: up2.hash, recipientWrap: 'AAAA' }), /^400/, 'a wrap needs a recipient');
  await rejects(O.post('/v1/links', { hash: up2.hash, recipient: rk, recipientWrap: 'not base64url!' }), /^400/, 'recipientWrap must be base64url');
  await rejects(O.post('/v1/links', { hash: up2.hash, recipient: rk, recipientWrap: 'A'.repeat(1025) }), /^400/, 'and 1 KB at most');
  await rejects(O.post('/v1/links', { hash: up2.hash, recipient: rk, recipientLabel: '<script>' }), /^400/, 'recipientLabel must be a $handle or paymail');
  await rejects(O.post('/v1/links', { hash: up2.hash, recipient: rk, senderKey: xk }), /^400/, 'senderKey can only be your own key');
  await rejects(api(B2, O2T).call('PUT', `/v1/links/${bl.id}/recipient`, { json: { recipient: rk, recipientWrap: 'AAAA' } }), /^404/, 'nobody else can rebind your link');
  await rejects(O.call('PUT', `/v1/links/${bl.id}/recipient`, { json: { recipient: xk, recipientWrap: 'AAAA' } }), /^409/, 'a link\'s recipient can\'t be changed');
  await rejects(O.call('PUT', `/v1/links/${bl.id}/recipient`, { json: { recipient: rk } }), /^400/, 'PUT needs the wrap');

  // what other people see
  const anon = await linkInfo({ base: B2, id: bl.id });
  const anonJson = JSON.stringify(anon);
  ok(anon.bound && anon.forYou === false && anon.to === null && anon.from === identityKey && anon.size === up2.size, 'anyone else sees only: bound, who sent it, size, dates');
  ok(!('meta' in anon) && !('recipientWrap' in anon) && !('hash' in anon) && !anonJson.includes(rk) && !anonJson.includes('$jon'), 'no meta, no wrap, no hash, nothing about the recipient');
  const blobAs = (t, headers = {}) => fetch(`${B2}/v1/s/${bl.id}/blob`, { headers: { ...(t ? { authorization: `Bearer ${t}` } : {}), ...headers } });
  let r = await blobAs(null);
  const rjson = await r.json();
  ok(r.status === 403 && /someone else/.test(rjson.error) && rjson.code === 'not_recipient', 'the blob is refused to an anonymous user (403, sent to someone else, code not_recipient)');
  ok((await fetch(`${B2}/v1/s/${bl.id}/blob`, { method: 'HEAD' })).status === 403, 'HEAD too');
  await rejects(openLink({ base: B2, id: bl.id, key: up2.key }), /^403/, 'even with the file key, the anyone-link path refuses a bound link');
  const asOwner = await linkInfo({ base: B2, id: bl.id, token: OT });
  ok(asOwner.forYou === false && !('recipientWrap' in asOwner) && !('meta' in asOwner), 'the owner reading the share link gets the public view');
  ok((await blobAs(OT)).status === 403, 'the owner cannot download as the recipient');
  ok((await O.call('GET', `/v1/blobs/${up2.hash}`)).status === 200, 'the owner keeps owner access through the owner routes');
  ok((await blobAs(O2T)).status === 403, 'a different signed-in (invited) wallet is refused');
  ok((await sign(xw, xk)).status === 403, 'a third wallet that is not invited still cannot sign in');
  const rep2 = await fetch(`${B2}/v1/s/${bl.id}/report`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ reason: 'grief' }) });
  ok(rep2.status === 403, 'only the recipient can report (and switch off) a bound link');

  // the owner's list: who it's for, never the wrap
  const ownerFiles = await O.get('/v1/files');
  const ol = ownerFiles.files.find((f) => f.hash === up2.hash).links.find((l) => l.id === bl.id);
  ok(ol.bound && ol.recipient === rk && ol.recipientLabel === '$jon' && ol.ready && !JSON.stringify(ownerFiles).includes('recipientWrap'), 'the owner sees who it\'s for ($jon) and that it\'s ready, not the wrap');

  // the recipient: a recipient-only session
  const rRes = await sign(rw, rk);
  const rs = await rRes.json();
  ok(rRes.status === 200 && rs.scope === 'recipient' && rs.expiresAt - Date.now() <= 24 * 3600e3 + 5e3, 'a non-invited recipient can sign in while a link exists for it: scope recipient, 1 day');
  const RT = rs.token, R = api(B2, RT);
  await rejects(R.get('/v1/files'), /^403/, 'a recipient session cannot list files');
  await rejects(R.get('/v1/me'), /^403/, 'or see an account');
  await rejects(R.post('/v1/uploads', { size: 64 }), /^403/, 'or upload');
  await rejects(R.call('PUT', `/v1/blobs/${ph}`, { body: photo }), /^403/, 'or PUT a blob');
  await rejects(R.call('GET', `/v1/blobs/${up2.hash}`), /^403/, 'or read the owner\'s blob by hash');
  await rejects(R.post('/v1/links', { hash: up2.hash }), /^403/, 'or make links');
  await rejects(R.del(`/v1/files/${up2.hash}`), /^403/, 'or delete the owner\'s file');
  await rejects(R.del(`/v1/links/${bl.id}`), /^403/, 'or switch off the owner\'s link');
  const mine2 = await linkInfo({ base: B2, id: bl.id, token: RT });
  ok(mine2.forYou && mine2.hash === up2.hash && mine2.senderKey === identityKey && typeof mine2.recipientWrap === 'string' && mine2.meta, 'signed in as the recipient: hash, meta, wrap and sender key');
  ok(!mine2.recipientWrap.includes(up2.key) && !JSON.stringify(mine2).includes(up2.key), 'the wrap is not the key');
  const opened2 = await openBoundLink({ base: B2, id: bl.id, token: RT, wallet: rw });
  ok(opened2.meta.name === 'for-jon.bin', 'the recipient\'s wallet unwraps the key and reads the name');
  const ps2 = [];
  const got3 = await downloadLink({ base: B2, id: bl.id, link: opened2, sink: { write: (u8) => { ps2.push(u8); } } });
  ok(got3.sha256 === sha(body) && Buffer.concat(ps2).equals(body), 'the recipient downloads and decrypts it, sha256 matches');
  await rejects(unwrapFromSender(xw, { hash: up2.hash, linkId: bl.id, wrap: mine2.recipientWrap, senderKey: identityKey }), /./, 'a third wallet cannot unwrap the wrap');
  await rejects(unwrapFromSender(rw, { hash: up2.hash, linkId: 'A'.repeat(22), wrap: mine2.recipientWrap, senderKey: identityKey }), /./, 'the wrap is bound to its link (key ID = hash.linkId)');
  await rejects(unwrapFromSender(rw, { hash: up2.hash, linkId: bl.id, wrap: mine2.recipientWrap, senderKey: o2k }), /./, 'and to its sender');
  const crossSite2 = await fetch(`${B2}/v1/s/${bl.id}/blob`, { headers: { authorization: `Bearer ${RT}`, origin: 'https://evil.example' } });
  ok(crossSite2.status === 403, 'the recipient token from another site counts as no sign-in');

  // a recipient session reads only links addressed to it
  const forX = await makeLink({ base: B2, token: OT, site: 'https://bdrivex.com', hash: up2.hash, key: up2.key, recipient: xk, wallet });
  const xi = await linkInfo({ base: B2, id: forX.id, token: RT });
  ok(xi.forYou === false && !('recipientWrap' in xi) && !('meta' in xi), 'a recipient session gets only the public view of someone else\'s link');
  ok((await fetch(`${B2}/v1/s/${forX.id}/blob`, { headers: { authorization: `Bearer ${RT}` } })).status === 403, 'and cannot download it');
  await O.del(`/v1/links/${forX.id}`);

  // a wrap that isn't in place yet: the recipient is told to wait
  const half = await O.post('/v1/links', { hash: up2.hash, recipient: rk });
  await rejects(linkInfo({ base: B2, id: half.id, token: RT }), /^409/, 'a link whose wrap isn\'t in place yet asks the recipient to wait');
  await O.del(`/v1/links/${half.id}`);

  // anyone-links and v1.1 still work on the same server
  const anyL = await makeLink({ base: B2, token: OT, site: 'https://bdrivex.com', hash: up2.hash, key: up2.key });
  ok(/#k=/.test(anyL.url) && !anyL.bound, 'an anyone-link still carries #k');
  const ai = await openLink({ base: B2, id: anyL.id, key: parseShare(new URL(anyL.url).hash) });
  const ps3 = [];
  ok((await downloadLink({ base: B2, id: anyL.id, link: ai, sink: { write: (u8) => { ps3.push(u8); } } })).sha256 === sha(body), 'and downloads without a wallet');
  await saveKeyWrap({ base: B2, token: OT, wallet, hash: up2.hash, key: up2.key });
  ok((await unwrapKey(wallet, up2.hash, (await O.get('/v1/files')).files.find((f) => f.hash === up2.hash).keyWrap)) === up2.key, 'the v1.1 owner wrap still works');

  // the server never holds the file key: look through every stored row
  const db2 = new DatabaseSync(join(d2, 'bdrivex.db'));
  const rows = JSON.stringify([db2.prepare('SELECT * FROM links').all(), db2.prepare('SELECT * FROM files').all()]);
  ok(!rows.includes(up2.key) && !rows.includes(Buffer.from(up2.key, 'base64url').toString('hex')), 'no stored row contains the file key');

  // revoke: the recipient loses the link, and a non-invited wallet can't sign in any more
  await O.del(`/v1/links/${bl.id}`);
  await rejects(linkInfo({ base: B2, id: bl.id, token: RT }), /^404/, 'a revoked bound link stops working for the recipient');
  ok((await blobAs(RT)).status === 404, 'and its blob');
  ok((await sign(rw, rk)).status === 403, 'with no live link left, the recipient cannot sign in again');

  // expiry: same again with a link whose time is up
  const ex = await makeLink({ base: B2, token: OT, site: 'https://bdrivex.com', hash: up2.hash, key: up2.key, ttl: 3600, recipient: rk, wallet });
  ok((await sign(rw, rk)).status === 200, 'a new link for the recipient lets them sign in again');
  db2.prepare('UPDATE links SET expires_at = ? WHERE id = ?').run(Date.now() - 1000, ex.id);
  await rejects(linkInfo({ base: B2, id: ex.id, token: RT }), /^410/, 'an expired bound link says so');
  ok((await fetch(`${B2}/v1/s/${ex.id}/blob`, { headers: { authorization: `Bearer ${RT}` } })).status === 410, 'and its blob is gone');
  ok((await sign(rw, rk)).status === 403, 'and the recipient cannot sign in once it has expired');
  await rejects(O.call('PUT', `/v1/links/${ex.id}/recipient`, { json: { recipient: rk, recipientWrap: 'AAAA' } }), /^410/, 'an expired link cannot be rebound');
  db2.close();

  // a recipient can sign out
  ok((await R.call('POST', '/v1/auth/signout')).status === 204 && (await fetch(`${B2}/v1/s/${ex.id}`, { headers: { authorization: `Bearer ${RT}` } })).status === 410, 'a recipient session can sign out');
  const rAfter = await fetch(`${B2}/v1/auth/signout`, { method: 'POST', headers: { authorization: `Bearer ${RT}` } });
  ok(rAfter.status === 401, 'and its token stops working');

  // the site's recipient parsing
  ok(parseRecipient('$Jon')?.paymail === 'jon@bwalletx.com' && parseRecipient('jon')?.label === '$jon' && parseRecipient('jon@HandCash.io')?.label === 'jon@handcash.io' && parseRecipient('jon@') === null && parseRecipient('a b@c.d') === null, 'recipients: $handle, handle, paymail; junk refused');

  s2.kill(); rmSync(d2, { recursive: true, force: true });
}

// ---- open sign-up, invite-only sharing: anyone stores files, only invited wallets make or bind links
{
  console.log('open sign-up, invite-only sharing');
  const P4 = 8796, B4 = `http://127.0.0.1:${P4}`, d4 = mkdtempSync(join(tmpdir(), 'bdrivex-test-'));
  const bogus = spawn(process.execPath, [join(here, '../src/server.js')], {
    env: { ...process.env, NODE_ENV: 'production', PORT: String(P4), DATA_DIR: d4, SESSION_SECRET: randomBytes(32).toString('hex'), SHARING: 'yes' }, stdio: 'ignore',
  });
  ok((await new Promise((r) => bogus.on('exit', r))) !== 0, 'SHARING must be open or invited (the server will not start otherwise)');
  const s4 = await startServer(P4, d4, { SIGNUP: 'open', ALLOWED_KEYS: identityKey }); // SHARING not set: invited
  const sign4 = async (w, k) => {
    const c = await (await fetch(B4 + '/v1/auth/challenge', { method: 'POST', headers: { 'content-type': 'application/json', origin: ORIGIN }, body: JSON.stringify({ identityKey: k }) })).json();
    const { signature } = await w.createSignature({ protocolID: c.protocolID, keyID: c.keyID, counterparty: 'anyone', data: Array.from(new TextEncoder().encode(c.message)) });
    return (await fetch(B4 + '/v1/auth/verify', { method: 'POST', headers: { 'content-type': 'application/json', origin: ORIGIN }, body: JSON.stringify({ identityKey: k, nonce: c.nonce, signature: Array.from(signature) }) })).json();
  };
  const small = (n, name, t) => { const b = randomBytes(n); return uploadFile({ base: B4, token: t, source: { size: n, read: async (a, z) => new Uint8Array(b.subarray(a, z)) }, name }).then((u) => ({ ...u, body: b })); };
  const IT = (await sign4(wallet, identityKey)).token;
  const nw = new ProtoWallet(PrivateKey.fromRandom()), nk = (await nw.getPublicKey({ identityKey: true })).publicKey; // signs up, not invited
  const ns = await sign4(nw, nk);
  ok(ns.token && ns.scope === 'full', 'with SIGNUP=open a wallet that is not invited signs up with a full session');
  const N = api(B4, ns.token);
  const nf = await small(70_000, 'mine.bin', ns.token);
  ok(HASH(nf.hash) && (await N.get('/v1/files')).files.length === 1 && (await N.get('/v1/me')).usage.files === 1, 'its storage works: upload, list, usage');
  const nb = Buffer.from(await (await N.call('GET', `/v1/blobs/${nf.hash}`)).arrayBuffer());
  ok(sha(nb) === nf.hash, 'and it reads its own blob back');

  const SHUT = { error: 'sharing_invite_only', code: 'sharing_invite_only', message: 'Sharing links are invite-only for now. Your storage works as normal.' };
  const raw = await fetch(B4 + '/v1/links', { method: 'POST', headers: { authorization: `Bearer ${ns.token}`, 'content-type': 'application/json' }, body: JSON.stringify({ hash: nf.hash }) });
  ok(raw.status === 403 && JSON.stringify(await raw.json()) === JSON.stringify(SHUT), 'POST /v1/links: 403 { error: sharing_invite_only, code: sharing_invite_only, message } (error stays the code for the site)');
  await rejects(N.post('/v1/links', { hash: nf.hash, recipient: identityKey }), /^403 Sharing links are invite-only for now\. Your storage works as normal\.$/, 'a link for one person too (and the site client shows the message)');
  await rejects(makeLink({ base: B4, token: ns.token, site: 'https://bdrivex.com', hash: nf.hash, key: nf.key, recipient: identityKey, wallet: nw }), /^403 Sharing/, 'makeLink stops before asking the wallet to wrap anything');
  const e403 = await N.post('/v1/links', { hash: nf.hash }).catch((e) => e);
  ok(e403?.body?.error === 'sharing_invite_only', 'the client keeps the code on ApiError.body for the page to check');

  // a link the new wallet already had (made while sharing was open) keeps working; it can't be bound, but can be switched off
  const db4 = new DatabaseSync(join(d4, 'bdrivex.db'));
  const oldId = randomBytes(16).toString('base64url');
  db4.prepare('INSERT INTO links (id, owner, hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)').run(oldId, nk, nf.hash, Date.now(), Date.now() + 86400e3);
  db4.close();
  const oi = await openLink({ base: B4, id: oldId, key: nf.key });
  const ps5 = [];
  ok((await downloadLink({ base: B4, id: oldId, link: oi, sink: { write: (u8) => { ps5.push(u8); } } })).sha256 === sha(nf.body), 'an existing link still opens and downloads');
  const bind = await fetch(`${B4}/v1/links/${oldId}/recipient`, { method: 'PUT', headers: { authorization: `Bearer ${ns.token}`, 'content-type': 'application/json' }, body: JSON.stringify({ recipient: identityKey, recipientWrap: 'AAAA' }) });
  ok(bind.status === 403 && (await bind.json()).error === 'sharing_invite_only', 'PUT /v1/links/:id/recipient is gated the same way');
  ok((await N.get('/v1/files')).files[0].links.some((l) => l.id === oldId), 'the owner still sees it in the file list');
  await N.del(`/v1/links/${oldId}`);
  await rejects(openLink({ base: B4, id: oldId, key: nf.key }), /^404/, 'and can still switch it off');

  // invited wallets share as before, and people they send to can open it
  const ivf = await small(50_000, 'from-invited.bin', IT);
  const any4 = await makeLink({ base: B4, token: IT, site: 'https://bdrivex.com', hash: ivf.hash, key: ivf.key });
  ok(/#k=/.test(any4.url), 'an invited wallet still makes anyone-links');
  const to4 = await makeLink({ base: B4, token: IT, site: 'https://bdrivex.com', hash: ivf.hash, key: ivf.key, recipient: nk, wallet });
  const got4 = await openBoundLink({ base: B4, id: to4.id, token: ns.token, wallet: nw });
  ok(to4.bound && got4.meta.name === 'from-invited.bin', 'and links for one person (POST + PUT), which the not-invited recipient opens');
  await new Promise((r) => { s4.on('exit', r); s4.kill(); }); // free the port before the restart

  // SHARING=open on the same data: the same wallet can now make links
  const s4b = await startServer(P4, d4, { SIGNUP: 'open', SHARING: 'open', ALLOWED_KEYS: identityKey });
  const ns2 = await sign4(nw, nk);
  const opened4 = await api(B4, ns2.token).post('/v1/links', { hash: nf.hash });
  ok(opened4.id && !opened4.bound, 'with SHARING=open any signed-in wallet makes links');
  s4b.kill(); rmSync(d4, { recursive: true, force: true });
}

// ---- legal hold, report retention, scrubbing revoked/expired links, closing an account, CORS for bstorex, error codes
{
  console.log('legal hold, retention, scrubbing, closing an account');
  const P5 = 8795, B5 = `http://127.0.0.1:${P5}`, d5 = mkdtempSync(join(tmpdir(), 'bdrivex-test-'));
  const s5 = await startServer(P5, d5, { SIGNUP: 'open', SHARING: 'open', HOUSEKEEPING_MS: '300', BLOB_DELETE_RETRY_MS: '300' });
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const until = async (fn, ms = 4000) => { for (let i = 0; i < ms / 100 && !fn(); i++) await sleep(100); return fn(); };
  const sign5 = async (w, k) => {
    const c = await (await fetch(B5 + '/v1/auth/challenge', { method: 'POST', headers: { 'content-type': 'application/json', origin: ORIGIN }, body: JSON.stringify({ identityKey: k }) })).json();
    const { signature } = await w.createSignature({ protocolID: c.protocolID, keyID: c.keyID, counterparty: 'anyone', data: Array.from(new TextEncoder().encode(c.message)) });
    return (await fetch(B5 + '/v1/auth/verify', { method: 'POST', headers: { 'content-type': 'application/json', origin: ORIGIN }, body: JSON.stringify({ identityKey: k, nonce: c.nonce, signature: Array.from(signature) }) })).json();
  };
  const db5 = () => { const d = new DatabaseSync(join(d5, 'bdrivex.db')); d.exec('PRAGMA busy_timeout = 5000'); return d; };
  const q5 = (sql, ...a) => { const d = db5(); try { return d.prepare(sql).all(...a); } finally { d.close(); } };
  const run5 = (script, args) => runScript(d5, script, args);
  const aw = new ProtoWallet(PrivateKey.fromRandom()), ak = (await aw.getPublicKey({ identityKey: true })).publicKey; // the account to close
  const bw = new ProtoWallet(PrivateKey.fromRandom()), bk = (await bw.getPublicKey({ identityKey: true })).publicKey;
  let AT = (await sign5(aw, ak)).token;
  await fetch(B5 + '/v1/auth/signout-all', { method: 'POST', headers: { authorization: `Bearer ${AT}` } }); // gives it a sign-out counter row
  AT = (await sign5(aw, ak)).token;
  const BT = (await sign5(bw, bk)).token;
  const A = api(B5, AT), Bw = api(B5, BT);
  const put5 = async (who, b) => { const h = sha(b); await who.call('PUT', `/v1/blobs/${h}`, { body: b }); return h; };
  const [b1, b2, b3, b4] = [randomBytes(3000), randomBytes(3100), randomBytes(3200), randomBytes(3300)];
  const [h1, h2, h3, h4] = [await put5(A, b1), await put5(A, b2), await put5(A, b3), await put5(A, b4)];
  await put5(Bw, b3); // bw holds the same bytes as h3
  await A.call('PUT', `/v1/files/${h2}/key`, { json: { keyWrap: 'AAAA' } });
  const pending5 = await A.post('/v1/uploads', { size: 64 });

  // a report holds the file
  const l1 = await A.post('/v1/links', { hash: h1 });
  ok((await fetch(`${B5}/v1/s/${l1.id}/report`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ reason: 'illegal' }) })).status === 204, 'a report is taken');
  const files5 = (await A.get('/v1/files')).files;
  ok(files5.find((f) => f.hash === h1).held === true && files5.find((f) => f.hash === h2).held === false, 'GET /v1/files: the reported file shows held: true, the others false');
  const d423 = await fetch(`${B5}/v1/files/${h1}`, { method: 'DELETE', headers: { authorization: `Bearer ${AT}` } });
  const j423 = await d423.json();
  ok(d423.status === 423 && j423.code === 'legal_hold' && /support@bwalletx\.com/.test(j423.error), `DELETE a held file: 423 { code: legal_hold }: ${j423.error}`);
  ok((await A.get('/v1/files')).files.some((f) => f.hash === h1) && existsSync(blobFile(d5, h1)), 'and the file and its blob stay');
  const rrow = q5('SELECT * FROM reports WHERE link_id = ?', l1.id)[0];
  ok(rrow.owner === ak && rrow.hash === h1 && /127\.0\.0\.1|::1/.test(rrow.ip), 'the report record keeps owner, file and (for now) the reporter IP');
  ok(q5('SELECT * FROM holds WHERE owner = ? AND hash = ? AND released_at IS NULL', ak, h1).length === 1, 'and a hold row');
  const again = await fetch(`${B5}/v1/s/${l1.id}/report`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ reason: 'again' }) });
  ok(again.status === 204 && q5('SELECT * FROM holds WHERE owner = ? AND hash = ?', ak, h1).length === 1, 'a second report of the same link adds no second hold');

  // release by the admin script, then the owner can delete; the report outlives the file
  const l4 = await A.post('/v1/links', { hash: h4 });
  await fetch(`${B5}/v1/s/${l4.id}/report`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ reason: 'spam' }) });
  const ls = await run5('legal-hold.mjs', ['list']);
  ok(ls.code === 0 && ls.out.includes(`file ${h1}`) && ls.out.includes(`file ${h4}`) && /active holds: 2/.test(ls.out), 'legal-hold.mjs list shows both holds and their reports');
  const rl0 = await run5('legal-hold.mjs', ['release', ak, h4, '--note', 'reviewed, fine']);
  ok(rl0.code === 0 && /would release/.test(rl0.out) && q5('SELECT 1 FROM holds WHERE hash = ? AND released_at IS NULL', h4).length === 1, 'release without --yes changes nothing');
  ok((await run5('legal-hold.mjs', ['release', ak, h4])).code === 2, 'release needs --note');
  const rl1 = await run5('legal-hold.mjs', ['release', ak, h4, '--note', 'reviewed, fine', '--yes']);
  ok(rl1.code === 0 && /released 1/.test(rl1.out), `release --yes: ${rl1.out.trim()}`);
  ok((await fetch(`${B5}/v1/files/${h4}`, { method: 'DELETE', headers: { authorization: `Bearer ${AT}` } })).status === 204, 'once released, the owner can delete it');
  ok(q5('SELECT * FROM reports WHERE link_id = ?', l4.id)[0]?.hash === h4 && q5('SELECT 1 FROM links WHERE id = ?', l4.id).length === 0, 'the report record survives the file (and its links) being deleted');

  // scrubbing who a link was for, 7 days after it was revoked or expired
  const g = await put5(Bw, randomBytes(2000));
  const mk = async (who, hash, rk) => { const l = await who.post('/v1/links', { hash, recipient: rk, recipientLabel: '$someone' }); await who.call('PUT', `/v1/links/${l.id}/recipient`, { json: { recipient: rk, recipientWrap: 'AAAA' } }); return l.id; };
  const [oldRevoked, oldExpired, newRevoked, live, heldOld] = [await mk(Bw, g, ak), await mk(Bw, g, ak), await mk(Bw, g, ak), await mk(Bw, g, ak), await mk(A, h1, bk)];
  await Bw.del(`/v1/links/${newRevoked}`);
  {
    const d = db5(), eight = Date.now() - 8 * 86400e3;
    d.prepare('UPDATE links SET revoked_at = ? WHERE id IN (?, ?)').run(eight, oldRevoked, heldOld);
    d.prepare('UPDATE links SET expires_at = ? WHERE id = ?').run(eight, oldExpired);
    // retention rows: a report older than 3 years, one 31 days old with a raw IP, an old released hold, an old active hold
    const t = Date.now();
    d.prepare('INSERT INTO reports (link_id, at, reason, ip, owner, hash) VALUES (?, ?, ?, ?, ?, ?)').run('A'.repeat(22), t - 1097 * 86400e3, 'ancient', '198.51.100.7', bk, g);
    d.prepare('INSERT INTO reports (link_id, at, reason, ip, owner, hash) VALUES (?, ?, ?, ?, ?, ?)').run('B'.repeat(22), t - 31 * 86400e3, 'last month', '203.0.113.9', bk, g);
    d.prepare('INSERT INTO holds (owner, hash, link_id, placed_at, reason, released_at, released_note) VALUES (?, ?, ?, ?, ?, ?, ?)').run(bk, 'c'.repeat(64), null, t - 1200 * 86400e3, 'x', t - 1097 * 86400e3, 'old');
    d.prepare('INSERT INTO holds (owner, hash, link_id, placed_at, reason) VALUES (?, ?, ?, ?, ?)').run(bk, 'd'.repeat(64), null, t - 1200 * 86400e3, 'still active');
    d.close();
  }
  const linkRow = (id) => q5('SELECT * FROM links WHERE id = ?', id)[0];
  await until(() => linkRow(oldRevoked).recipient === null && linkRow(oldExpired).recipient === null);
  const scrubbed = (id) => { const l = linkRow(id); return l.recipient === null && l.recipient_wrap === null && l.recipient_label === null && Number.isInteger(l.recipient_scrubbed_at); };
  ok(scrubbed(oldRevoked) && scrubbed(oldExpired), 'links revoked or expired over 7 days ago lose recipient key, wrap and label (housekeeping)');
  ok(linkRow(newRevoked).recipient === ak && linkRow(live).recipient === ak && linkRow(live).recipient_label === '$someone', 'a link revoked just now, and a live link, keep theirs');
  ok(linkRow(heldOld).recipient === bk, 'a link on a file under legal hold keeps its recipient while the hold lasts');
  const bl5 = (await Bw.get('/v1/files')).files.find((f) => f.hash === g).links.find((l) => l.id === oldRevoked);
  ok(bl5.bound === true && bl5.recipient === null && bl5.recipientLabel === null && Number.isInteger(bl5.scrubbedAt), 'the sender still sees it was sent to one person, not to whom');
  await until(() => q5("SELECT ip FROM reports WHERE link_id = ?", 'B'.repeat(22))[0]?.ip?.startsWith('h:'));
  ok(q5('SELECT 1 FROM reports WHERE link_id = ?', 'A'.repeat(22)).length === 0, 'report records older than 3 years are deleted');
  const hashed = q5('SELECT ip FROM reports WHERE link_id = ?', 'B'.repeat(22))[0].ip;
  ok(/^h:[0-9a-f]{32}$/.test(hashed) && !hashed.includes('203.0.113.9'), `a reporter IP older than 30 days is replaced by a keyed hash (${hashed.slice(0, 10)}…)`);
  ok(!q5('SELECT ip FROM reports WHERE link_id = ?', l1.id)[0].ip.startsWith('h:'), 'a recent reporter IP is kept as it is');
  ok(q5('SELECT 1 FROM holds WHERE hash = ?', 'c'.repeat(64)).length === 0 && q5('SELECT 1 FROM holds WHERE hash = ?', 'd'.repeat(64)).length === 1, 'released holds older than 3 years go; an active hold is never aged out');

  // closing the account
  const before = q5('SELECT COUNT(*) AS n FROM files WHERE owner = ?', ak)[0].n;
  const dry = await run5('close-account.mjs', [ak]);
  ok(dry.code === 0 && /dry run: nothing changed/.test(dry.out) && /would REFUSE/.test(dry.out) && q5('SELECT COUNT(*) AS n FROM files WHERE owner = ?', ak)[0].n === before && (await me5(AT)) === 200, 'close-account without --yes is a dry run: nothing changes, and it warns about the hold');
  async function me5(t) { return (await fetch(B5 + '/v1/me', { headers: { authorization: `Bearer ${t}` } })).status; }
  ok((await run5('close-account.mjs', ['nonsense'])).code === 2, 'a bad identity key is refused');
  const ref = await run5('close-account.mjs', [ak, '--yes']);
  ok(ref.code === 1 && /REFUSED/.test(ref.out) && q5('SELECT COUNT(*) AS n FROM files WHERE owner = ?', ak)[0].n === before && (await me5(AT)) === 200, 'with a held file, --yes refuses and deletes nothing');
  const kh = await run5('close-account.mjs', [ak, '--yes', '--keep-held']);
  ok(kh.code === 0 && /closed /.test(kh.out), `--yes --keep-held: ${kh.out.trim().split('\n').at(-1)}`);
  const rowsA = q5('SELECT hash FROM files WHERE owner = ?', ak).map((r) => r.hash);
  ok(rowsA.length === 1 && rowsA[0] === h1 && existsSync(blobFile(d5, h1)), 'the held file stays, with its blob');
  ok(!existsSync(blobFile(d5, h2)) && existsSync(blobFile(d5, h3)), 'its own blob is deleted; a blob another wallet also holds is kept');
  ok(q5('SELECT reason FROM erased_blobs WHERE hash = ?', h2)[0]?.reason === 'account closed' && q5('SELECT 1 FROM erased_blobs WHERE hash = ?', h3).length === 0, 'the deletion log names the deleted blob (so the B2 prune follows), not the shared one');
  ok(q5('SELECT COUNT(*) AS n FROM links WHERE owner = ?', ak)[0].n === 0 && q5('SELECT COUNT(*) AS n FROM uploads WHERE owner = ?', ak)[0].n === 0 && !existsSync(join(d5, 'tmp', pending5.id)), 'its links and unfinished uploads (rows and staged bytes) are gone');
  ok(q5('SELECT COUNT(*) AS n FROM generations WHERE owner = ?', ak)[0].n === 0 && q5('SELECT COUNT(*) AS n FROM nonces WHERE instr(data, ?) > 0', ak)[0].n === 0, 'the sign-out counter and sign-in nonces for the key are gone');
  const closedRows = q5('SELECT * FROM closed_accounts');
  ok(closedRows.length === 1 && closedRows[0].key_hash === keyHash(ak) && !JSON.stringify(closedRows).includes(ak) && closedRows[0].purge_after - closedRows[0].closed_at === 8 * 86400e3, 'closed_accounts keeps a hash of the key (never the key), for 8 days');
  const m401 = await fetch(B5 + '/v1/me', { headers: { authorization: `Bearer ${AT}` } });
  ok(m401.status === 401 && (await m401.json()).code === 'account_closed', 'a token from before the close is refused: 401 account_closed');
  ok((await Bw.get('/v1/files')).files.some((f) => f.hash === h3) && (await me5(BT)) === 200, 'the other wallet keeps its file and its session');
  ok(q5('SELECT COUNT(*) AS n FROM reports WHERE owner = ?', ak)[0].n === 2, 'report records about the account are kept');
  await run5('legal-hold.mjs', ['release', ak, h1, '--note', 'reviewed', '--yes']);
  const fin = await run5('close-account.mjs', [ak, '--yes']);
  ok(fin.code === 0 && q5('SELECT COUNT(*) AS n FROM files WHERE owner = ?', ak)[0].n === 0 && !existsSync(blobFile(d5, h1)), 'after the hold is released, closing again removes the last file and its blob');
  await sleep(1100); // tokens carry iat in seconds
  const reborn = await sign5(aw, ak);
  ok(reborn.token && (await me5(reborn.token)) === 200 && (await api(B5, reborn.token).get('/v1/files')).files.length === 0, 'the wallet can sign up again afterwards, with nothing left');

  // CORS: bstorex.com is on the production default list; Retry-After is exposed; 429 says rate_limited
  let r429;
  for (let i = 0; i < 12 && !r429; i++) {
    const r = await fetch(`${B5}/v1/s/${'Z'.repeat(22)}/report`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    if (r.status === 429) r429 = r; else await r.arrayBuffer();
  }
  const j429 = r429 && await r429.json();
  ok(r429 && j429.code === 'rate_limited' && /Too many/.test(j429.error) && Number(r429.headers.get('retry-after')) > 0, `429: { code: rate_limited } with Retry-After ${r429?.headers.get('retry-after')}`);
  ok(/Retry-After/.test(r429?.headers.get('access-control-expose-headers') || ''), 'Retry-After is in Access-Control-Expose-Headers');
  await new Promise((r) => { s5.on('exit', r); s5.kill(); });
  rmSync(d5, { recursive: true, force: true });

  const P6 = 8794, B6 = `http://127.0.0.1:${P6}`, d6 = mkdtempSync(join(tmpdir(), 'bdrivex-test-'));
  const s6 = await startServer(P6, d6, { ALLOWED_ORIGINS: '' }); // production, no ALLOWED_ORIGINS: the default list
  const acao = async (origin) => (await fetch(B6 + '/v1/me', { headers: { origin } })).headers.get('access-control-allow-origin');
  ok(await acao('https://bstorex.com') === 'https://bstorex.com' && await acao('https://www.bstorex.com') === 'https://www.bstorex.com', 'production default origins include bstorex.com and www.bstorex.com');
  ok(await acao('https://bdrivex.com') === 'https://bdrivex.com' && await acao('https://www.bdrivex.com') === 'https://www.bdrivex.com' && await acao('https://evil.example') === null, 'and still bdrivex.com, www.bdrivex.com, and nothing else');
  const chB = await fetch(B6 + '/v1/auth/challenge', { method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://bstorex.com' }, body: JSON.stringify({ identityKey }) });
  const chE = await fetch(B6 + '/v1/auth/challenge', { method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://evil.example' }, body: JSON.stringify({ identityKey }) });
  ok(chB.status === 200 && chE.status === 403 && (await chE.json()).code === 'origin_not_allowed', 'sign-in challenge from bstorex.com works; another origin gets 403 origin_not_allowed');
  const s401 = await fetch(B6 + '/v1/files');
  ok(s401.status === 401 && (await s401.json()).code === 'signin_required', 'no session: 401 signin_required');
  s6.kill(); rmSync(d6, { recursive: true, force: true });
}

// ---- migration: a v1.1 database (no recipient columns) opens, gains them, and its links keep working
{
  console.log('migration from a v1.1 database');
  const P3 = 8797, B3 = `http://127.0.0.1:${P3}`, d3 = mkdtempSync(join(tmpdir(), 'bdrivex-test-'));
  const old = new DatabaseSync(join(d3, 'bdrivex.db'));
  old.exec(`PRAGMA journal_mode = WAL;
    CREATE TABLE nonces (nonce TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at INTEGER NOT NULL);
    CREATE TABLE uploads (id TEXT PRIMARY KEY, owner TEXT NOT NULL, size INTEGER NOT NULL, received INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
    CREATE TABLE files (owner TEXT NOT NULL, hash TEXT NOT NULL, size INTEGER NOT NULL, meta TEXT, created_at INTEGER NOT NULL, key_wrap TEXT, PRIMARY KEY (owner, hash));
    CREATE TABLE links (id TEXT PRIMARY KEY, owner TEXT NOT NULL, hash TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER, revoked_at INTEGER, downloads INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY (owner, hash) REFERENCES files(owner, hash) ON DELETE CASCADE);
    CREATE TABLE revoked (sid TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
    CREATE TABLE generations (owner TEXT PRIMARY KEY, gen INTEGER NOT NULL);
    CREATE TABLE reports (link_id TEXT PRIMARY KEY, at INTEGER NOT NULL, reason TEXT, ip TEXT);`);
  // one small sealed file, made the way the site makes them
  const plain = randomBytes(5000);
  const { key: k3, header: h3 } = newSeal();
  const ck3 = await importKey(k3);
  const sealed = Buffer.concat([h3, await sealSegment(ck3, h3, 0, true, plain)]);
  const hh = sha(sealed);
  placeBlob(d3, hh, sealed);
  const lid = randomBytes(16).toString('base64url');
  old.prepare('INSERT INTO files (owner, hash, size, meta, created_at, key_wrap) VALUES (?, ?, ?, ?, ?, ?)').run(identityKey, hh, sealed.length, await sealMeta(ck3, h3, { name: 'old.bin', type: '', size: plain.length }), Date.now(), 'AAAA');
  old.prepare('INSERT INTO links (id, owner, hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)').run(lid, identityKey, hh, Date.now(), Date.now() + 86400e3);
  // a second link that was reported before reports kept owner and hash, or files were held
  const lid2 = randomBytes(16).toString('base64url');
  old.prepare('INSERT INTO links (id, owner, hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)').run(lid2, identityKey, hh, Date.now(), Date.now() + 86400e3);
  old.prepare('INSERT INTO reports (link_id, at, reason, ip) VALUES (?, ?, ?, ?)').run(lid2, Date.now() - 1000, 'old report', '192.0.2.1');
  ok(!old.prepare('PRAGMA table_info(links)').all().some((c) => c.name === 'recipient'), 'the v1.1 database has no recipient columns');
  old.close();
  const s3 = await startServer(P3, d3, { ALLOWED_KEYS: identityKey });
  const db3 = new DatabaseSync(join(d3, 'bdrivex.db'));
  const cols = db3.prepare('PRAGMA table_info(links)').all().map((c) => c.name);
  ok(['recipient', 'recipient_wrap', 'recipient_label'].every((c) => cols.includes(c)), `after start the links table has ${cols.slice(-3).join(', ')}`);
  ok(db3.prepare("SELECT 1 AS n FROM sqlite_master WHERE type = 'index' AND name = 'links_recipient'").get()?.n === 1, 'and an index on recipient');
  const oldRep = db3.prepare('SELECT * FROM reports WHERE link_id = ?').get(lid2);
  ok(oldRep.owner === identityKey && oldRep.hash === hh, 'a report from before the migration gains owner and file from its link');
  ok(db3.prepare('SELECT COUNT(*) AS n FROM holds WHERE owner = ? AND hash = ? AND released_at IS NULL').get(identityKey, hh).n === 1, 'and its file is put on legal hold');
  db3.close();
  const li = await openLink({ base: B3, id: lid, key: b64u(k3) });
  const ps4 = [];
  const d4 = await downloadLink({ base: B3, id: lid, link: li, sink: { write: (u8) => { ps4.push(u8); } } });
  ok(li.meta.name === 'old.bin' && d4.sha256 === sha(plain), 'a link made before the migration still opens and downloads');
  s3.kill();
  // a second start on the migrated database is a no-op
  const s3b = await startServer(P3, d3, { ALLOWED_KEYS: identityKey });
  ok((await fetch(B3 + '/health')).status === 200, 'starting again on the migrated database works (migration is idempotent)');
  { const d = new DatabaseSync(join(d3, 'bdrivex.db')); ok(d.prepare('SELECT COUNT(*) AS n FROM holds').get().n === 1, 'and places no second hold'); d.close(); }
  s3b.kill(); rmSync(d3, { recursive: true, force: true });
}

if (S3) ok(s3fake.requests.some((r) => r.method === 'GET' && r.range === 'bytes=100-199'), 's3: a Range read is passed through to the bucket as a Range request');
if (S3) ok(s3fake.authFailures.length === 0 && s3fake.requests.length > 0, `s3: ${s3fake.requests.length} requests to the fake bucket, every SigV4 signature checked and good${s3fake.authFailures.length ? ': ' + s3fake.authFailures.join('; ') : ''}`);
console.log(failures ? `\n${failures} FAILED` : '\nall passed');
stop();
process.exit(failures ? 1 : 0);
