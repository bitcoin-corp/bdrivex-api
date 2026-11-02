// End to end against a real server on a temp data dir, with the site's own client code:
// sign in (throwaway key) -> upload -> link -> download as a stranger -> same SHA-256. Plus the failure cases.
//   pnpm test [file]      (default: the APK for Jon if it's on the Desktop, else 24 MB of random bytes)
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, openSync, readSync, readFileSync, writeFileSync, statSync, rmSync, readdirSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join, resolve, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PrivateKey, ProtoWallet } from '@bsv/sdk';

const here = dirname(fileURLToPath(import.meta.url));
const SITE = resolve(process.env.SITE_DIR || join(here, '../../bdrivex-site'));
const { uploadFile, openLink, downloadLink, shareUrl, parseShare, api } = await import(join(SITE, 'js/bdx-client.js'));

const PORT = 8799, BASE = `http://127.0.0.1:${PORT}`, ORIGIN = 'http://127.0.0.1:5173';
const wallet = new ProtoWallet(PrivateKey.fromRandom());
const { publicKey: identityKey } = await wallet.getPublicKey({ identityKey: true });
const data = mkdtempSync(join(tmpdir(), 'bdrivex-test-'));
const srv = spawn(process.execPath, [join(here, '../src/server.js')], {
  env: { ...process.env, PORT: String(PORT), DATA_DIR: data, ALLOWED_ORIGINS: ORIGIN, SESSION_SECRET: randomBytes(32).toString('hex'), SIGNUP: 'open', QUOTA_BYTES: String(100 * 2 ** 20), QUOTA_OVERRIDES: `${identityKey}:${200 * 2 ** 20}` },
  stdio: ['ignore', 'inherit', 'inherit'],
});
const stop = () => { srv.kill(); rmSync(data, { recursive: true, force: true }); };
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
const onDisk = readFileSync(join(data, 'blobs', up.hash.slice(0, 2), up.hash.slice(2, 4), up.hash));
ok(sha(onDisk) === up.hash, 'blob on disk is stored under the sha256 of its bytes');
ok(!onDisk.includes(readFileSync(path).subarray(4096, 4160)), 'blob on disk does not contain the plaintext');
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
const blob = join(data, 'blobs', up.hash.slice(0, 2), up.hash.slice(2, 4), up.hash);
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

await api(BASE, T2).del(`/v1/files/${up.hash}`);
ok(!existsSync(blob), 'deleting a file removes its blob');
await rejects(openLink({ base: BASE, id: short.id, key: up.key }), /^404/, 'and its links');
ok(readdirSync(join(data, 'tmp')).length === 1, 'only the unfinished test upload is left in tmp');

// ---- invite-only mode: a second server that admits only the test wallet
{
  const P2 = 8798, B2 = `http://127.0.0.1:${P2}`, d2 = mkdtempSync(join(tmpdir(), 'bdrivex-test-'));
  const s2 = spawn(process.execPath, [join(here, '../src/server.js')], {
    env: { ...process.env, NODE_ENV: 'production', PORT: String(P2), DATA_DIR: d2, ALLOWED_ORIGINS: ORIGIN, SESSION_SECRET: randomBytes(32).toString('hex'), ALLOWED_KEYS: identityKey },
    stdio: 'ignore',
  });
  for (let i = 0; ; i++) { try { await fetch(B2 + '/health'); break; } catch { if (i > 50) throw new Error('server 2 did not start'); await new Promise((r) => setTimeout(r, 100)); } }
  const sign = async (w, k) => {
    const c = await (await fetch(B2 + '/v1/auth/challenge', { method: 'POST', headers: { 'content-type': 'application/json', origin: ORIGIN }, body: JSON.stringify({ identityKey: k }) })).json();
    const { signature } = await w.createSignature({ protocolID: c.protocolID, keyID: c.keyID, counterparty: 'anyone', data: Array.from(new TextEncoder().encode(c.message)) });
    return fetch(B2 + '/v1/auth/verify', { method: 'POST', headers: { 'content-type': 'application/json', origin: ORIGIN }, body: JSON.stringify({ identityKey: k, nonce: c.nonce, signature: Array.from(signature) }) });
  };
  ok((await sign(wallet, identityKey)).status === 200, 'production defaults to invite-only: an invited wallet signs in');
  ok((await sign(stranger, sk)).status === 403, 'and a wallet not on the list is refused');
  s2.kill(); rmSync(d2, { recursive: true, force: true });
}

console.log(failures ? `\n${failures} FAILED` : '\nall passed');
stop();
process.exit(failures ? 1 : 0);
