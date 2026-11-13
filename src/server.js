// bDriveX storage API. Holds opaque ciphertext only: files are sealed in the browser (BDX1, see
// bdrivex-site/js/bdx-crypto.js) and the key travels in the share link's #fragment, never here.
//
//   POST   /v1/auth/challenge      { identityKey }                      -> challenge to sign in bWalletX
//   POST   /v1/auth/verify         { identityKey, nonce, signature }    -> { token, identityKey, expiresAt }
//   POST   /v1/auth/signout                                             -> this token stops working
//   POST   /v1/auth/signout-all                                         -> every token for this wallet stops working
//   GET    /v1/me                                                       -> { identityKey, usage }
//   POST   /v1/uploads             { size }                             -> { id, offset: 0, chunkMax }
//   GET    /v1/uploads/:id                                              -> { id, size, offset }
//   PATCH  /v1/uploads/:id         Upload-Offset: n, body = next bytes  -> 204, Upload-Offset: n + len
//   POST   /v1/uploads/:id/complete { sha256, meta }                    -> { hash, size }  (re-hashed here)
//   DELETE /v1/uploads/:id
//   PUT    /v1/blobs/:sha256       body = small blob (bPhotosX)         -> { hash, size }
//   GET    /v1/blobs/:sha256                                            -> the blob, owner only, Range ok
//   GET    /v1/files                                                    -> { files: [...links, keyWrap], usage }
//   PUT    /v1/files/:sha256/key   { keyWrap }  (null clears)           -> 204, owner only, never shown on links
//   DELETE /v1/files/:sha256
//   POST   /v1/links               { hash, ttl, recipient?, recipientLabel?, recipientWrap? }   -> { id, expiresAt }
//                                  ttl: seconds, default and max 30 days. recipient: an identity key (v1.2, see below)
//   PUT    /v1/links/:id/recipient { recipient, recipientWrap, recipientLabel? }  -> 204, owner only
//   DELETE /v1/links/:id                                                -> revoke
//   GET    /v1/s/:id               public                               -> { size, meta, createdAt, expiresAt }
//   GET    /v1/s/:id/blob          public, Range ok                     -> ciphertext
//   POST   /v1/s/:id/report        public { reason }                   -> the link is switched off at once
//
// v1.2 links sent to one person. A link with a `recipient` (identity key) is bound to that wallet:
//   - GET /v1/s/:id shows anyone else only { bound, from, size, createdAt, expiresAt }: no meta, no wrap, nothing
//     about the recipient. Signed in as the recipient it adds { hash, meta, recipientWrap, senderKey }.
//   - GET /v1/s/:id/blob is served only to a session whose identity key is the recipient, else 403.
//   - recipientWrap is the file key wrapped by the sender's wallet for the recipient (BRC-2, protocol
//     [2,'bdrivex share'], key ID '<hash>.<link id>'). The server never has the file key. Make the link first
//     (POST with recipient), then wrap with its id and PUT the wrap.
//
// Auth: Authorization: Bearer <token> from /v1/auth/verify: a 7-day session signed with SESSION_SECRET, carrying
// aud (the site it was signed for), sid (for revoking one) and gen (bumped by sign-out-everywhere).
// A wallet that isn't admitted (SIGNUP=invite) but is the recipient of a live link gets a recipient session instead:
// scope 'recipient', 1 day, it can only read links addressed to it and sign out. No uploads, no files, no quota.
// SHARING=invited (default): only invited wallets (ALLOWED_KEYS) can POST /v1/links or PUT /v1/links/:id/recipient,
// even with SIGNUP=open; anyone else gets 403 { error: 'sharing_invite_only', message }. Existing links still open.
//
// Blobs: BLOB_STORE=fs (default, DATA_DIR/blobs) or s3 (an S3-compatible bucket, see src/blobstore.js). Uploads are
// always staged in DATA_DIR/tmp and hashed here; only a finished, verified blob goes to the store.
import { createServer } from 'node:http';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createReadStream, createWriteStream, mkdirSync } from 'node:fs';
import { open, rm, truncate } from 'node:fs/promises';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import { createChallenge, signSession, verifySession, verifySignIn } from '@bwalletx/connect/server';
import { openDb } from './db.js';
import { blobStoreFromEnv, BlobMissing } from './blobstore.js';

const env = process.env;
const PROD = env.NODE_ENV === 'production';
const PORT = Number(env.PORT || 8787);
const HOST = env.HOST || '127.0.0.1';
const DATA = env.DATA_DIR || join(process.cwd(), 'data');
const ORIGINS = (env.ALLOWED_ORIGINS || (PROD ? 'https://bdrivex.com,https://www.bdrivex.com' : 'http://127.0.0.1:5173,http://localhost:5173'))
  .split(',').map((s) => s.trim()).filter(Boolean);
const GiB = 1024 ** 3;
// Open sign-up, free storage (owner, 2 Nov 2026): anyone with a bWalletX gets QUOTA_BYTES until payments exist.
// QUOTA_OVERRIDES="<identityKey>:<bytes>,..." gives the owner and team more, server-side only.
const QUOTA = Number(env.QUOTA_BYTES || 1 * GiB);
const QUOTA_FOR = new Map((env.QUOTA_OVERRIDES || '').split(',').map((s) => s.trim().split(':')).filter(([k, b]) => k && Number(b) > 0)
  .map(([k, b]) => [k.toLowerCase(), Number(b)]));
const quotaOf = (owner) => QUOTA_FOR.get(owner) ?? QUOTA;
const MAX_FILE = Number(env.MAX_FILE_BYTES || 2 * GiB);
const LINK_DAYS = Number(env.LINK_MAX_DAYS || 30);
const UPLOAD_PER_DAY = Number(env.UPLOAD_BYTES_PER_DAY || 10 * GiB);
const EGRESS_PER_DAY = Number(env.LINK_EGRESS_BYTES_PER_DAY || 50 * GiB);
const CHUNK_MAX = 32 * 1024 * 1024;
const PUT_MAX = 64 * 1024 * 1024;
const SESSION_DAYS = 7;
const RECIPIENT_SESSION_HOURS = 24;
// Who can sign in (CTO, 2 Nov 2026): SIGNUP=invite (default in production) admits only ALLOWED_KEYS, the owner, the
// team and invitees, until the Online Safety Act risk assessment, terms and takedown route are in place. SIGNUP=open
// admits any bWalletX. Local dev defaults to open.
const SIGNUP = env.SIGNUP || (PROD ? 'invite' : 'open');
if (!['open', 'invite'].includes(SIGNUP)) throw new Error('SIGNUP must be open or invite.');
const ALLOWED_KEYS = new Set((env.ALLOWED_KEYS || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean));
// Who can share (owner, 3 Nov 2026): sign-up can open for private storage while links, which let one wallet's file
// reach another person, stay with invited wallets (ALLOWED_KEYS, the same list SIGNUP=invite uses) until the legal
// pack is done. SHARING=invited (the default everywhere) gates making and binding links; SHARING=open lets any
// signed-in wallet make them. Links that already exist keep working either way.
const SHARING = env.SHARING || 'invited';
if (!['open', 'invited'].includes(SHARING)) throw new Error('SHARING must be open or invited.');
const TRUST_PROXY = env.TRUST_PROXY === '1';
// How often blob deletes that failed (store unreachable) are tried again. Default 10 minutes.
const BLOB_DELETE_RETRY_MS = Number(env.BLOB_DELETE_RETRY_MS || 600_000);

let SECRET = env.SESSION_SECRET || '';
if (SECRET.length < 32) {
  if (PROD) throw new Error('SESSION_SECRET (32+ chars) is required in production.');
  SECRET = randomBytes(32).toString('hex');
  console.warn('[bdrivex] no SESSION_SECRET: using a random one, so sign-ins end when this process restarts.');
}

mkdirSync(join(DATA, 'tmp'), { recursive: true });
const S = openDb(join(DATA, 'bdrivex.db'));
const blobs = blobStoreFromEnv(env, DATA);
const tmpPath = (id) => join(DATA, 'tmp', id);
const now = () => Date.now();
const HASH = /^[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9_-]{22}$/;
const newId = () => randomBytes(16).toString('base64url');
const KEY = /^0[23][0-9a-f]{64}$/; // compressed secp256k1 public key, lowercase hex
const B64U = /^[A-Za-z0-9_-]+$/;
const LABEL = /^\$?[A-Za-z0-9._+-]{1,64}(@[A-Za-z0-9.-]{1,190})?$/; // $handle, handle@domain or any paymail
/** Constant-time string compare (identity keys, tokens). */
const same = (a, b) => {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

// Nonces for sign-in live in SQLite, so a restart between the two steps is harmless. take() reads and deletes at once.
const nonceStore = {
  put: (nonce, c) => { S.nonces.prune.run(now()); S.nonces.put.run(nonce, JSON.stringify(c), c.expiresAt); },
  take: (nonce) => {
    const row = S.nonces.get.get(String(nonce));
    if (!row) return null;
    S.nonces.del.run(String(nonce));
    return JSON.parse(row.data);
  },
};

// ---------- small HTTP helpers

// `code`, when given, goes out as { error: code, message } so a client can tell this refusal from the others.
class HttpError extends Error {
  constructor(status, message, headers, code) { super(message); this.status = status; this.headers = headers; this.code = code; }
}
const fail = (status, message, headers, code) => { throw new HttpError(status, message, headers, code); };

function send(res, status, body, headers = {}) {
  if (body === undefined || body === null) { res.writeHead(status, headers); return res.end(); }
  const s = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers });
  res.end(s);
}

async function readJson(req, limit = 64 * 1024) {
  let n = 0;
  const parts = [];
  for await (const c of req) {
    n += c.length;
    if (n > limit) fail(413, 'Request too large.');
    parts.push(c);
  }
  try { return JSON.parse(Buffer.concat(parts).toString('utf8') || '{}'); } catch { fail(400, 'Bad JSON.'); }
}

const ip = (req) => (TRUST_PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || '?';
// Fixed-window counters in memory (one process). limit() counts requests per IP and, when given, per identity too;
// spend() counts bytes against a daily allowance.
const windows = new Map();
function bump(k, perMs, by = 1) {
  const t = now();
  let w = windows.get(k);
  if (!w || t - w.start > perMs) windows.set(k, (w = { start: t, n: 0 }));
  w.n += by;
  return w.n;
}
const slowDown = (perMs, msg = 'Too many requests. Wait a minute and try again.') =>
  fail(429, msg, { 'retry-after': String(Math.ceil(Math.min(perMs, 3600_000) / 1000)) });
function limit(req, name, max, perMs, owner, ownerMax = max) {
  if (bump(`${name}|ip|${ip(req)}`, perMs) > max) slowDown(perMs);
  if (owner && bump(`${name}|key|${owner}`, perMs) > ownerMax) slowDown(perMs);
}
function spend(name, who, bytes, max, msg) {
  if (bump(`${name}|${who}`, 86400_000, bytes) > max) slowDown(86400_000, msg);
}

function cors(req, res, isPublic) {
  const o = req.headers.origin;
  if (isPublic) res.setHeader('access-control-allow-origin', '*');
  else if (o && ORIGINS.includes(o)) { res.setHeader('access-control-allow-origin', o); res.setHeader('vary', 'Origin'); }
  res.setHeader('access-control-expose-headers', 'Upload-Offset, Upload-Length, Content-Range, Content-Length, Accept-Ranges');
}

const invited = (key) => ALLOWED_KEYS.has(key);
const admitted = (key) => SIGNUP === 'open' || invited(key);
const canShare = (key) => SHARING === 'open' || invited(key);
const SHARING_SHUT = 'Sharing links are invite-only for now. Your storage works as normal.';
const genOf = (owner) => S.sessions.gen.get(owner)?.gen ?? 0;
/** The verified session on this request, or a 401. */
async function sessionFrom(req) {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  const s = m && (await verifySession(m[1], { secret: SECRET }));
  if (!s || typeof s.sid !== 'string' || S.sessions.isRevoked.get(s.sid) || s.gen !== genOf(s.sub)) fail(401, 'Sign in with bWalletX first.');
  // A browser token works only on the site it was signed for. Agents and CLIs send no Origin.
  if (req.headers.origin && s.aud && req.headers.origin !== s.aud) fail(401, 'This sign-in belongs to another site.');
  return s;
}
/** Public routes: the session if a valid one was sent, else null (a stale token is treated as none). */
async function maybeSession(req) {
  if (!req.headers.authorization) return null;
  try { return await sessionFrom(req); } catch { return null; }
}
const isRecipientSession = (s) => s.scope === 'recipient'; // v1.1 tokens have no scope: full sessions
async function auth(req, r) {
  const s = await sessionFrom(req);
  if (isRecipientSession(s)) { if (!r.recipientOk) fail(403, 'This sign-in can only open files sent to you.'); }
  else if (!admitted(s.sub)) fail(403, 'bDriveX is invite-only for now, and this wallet is not on the list.');
  else if (r.share && !canShare(s.sub)) fail(403, SHARING_SHUT, undefined, 'sharing_invite_only');
  req.session = s;
  return s.sub;
}

function usage(owner) {
  const u = S.usage.get(owner);
  return { bytes: u.stored, files: u.files, pending: u.pending, quota: quotaOf(owner), maxFile: MAX_FILE };
}
function roomFor(owner, size) {
  if (size > MAX_FILE) fail(413, `Files up to ${Math.floor(MAX_FILE / GiB)} GB for now.`);
  const u = usage(owner);
  if (u.bytes + u.pending + size > quotaOf(owner)) fail(413, 'That would take you over your storage allowance. Delete something first.');
}

const sha256File = async (path) => {
  const h = createHash('sha256');
  for await (const c of createReadStream(path)) h.update(c);
  return h.digest('hex');
};

// One thing at a time per hash: storing a blob and recording its file row, or removing a row and then the blob if it
// was the last. Without this, a delete could see no holders and remove a blob that a finishing upload has just
// found already stored (a wider window with a network store). In memory, so it holds only while the API is ONE
// process: run it in pm2 fork mode (instances: 1), never cluster mode.
const hashQueues = new Map();
async function oneAtATime(hash, fn) {
  const before = hashQueues.get(hash) ?? Promise.resolve();
  let done;
  const mine = before.then(() => new Promise((r) => { done = r; }));
  hashQueues.set(hash, mine);
  await before;
  try { return await fn(); } finally { done(); if (hashQueues.get(hash) === mine) hashQueues.delete(hash); }
}

const STORE_DOWN = 'Storage is not answering right now. Your upload is safe here: try finishing it again in a minute.';
/** Move a finished, hashed tmp file into the blob store under its hash (identical ciphertext is stored once). */
async function store(tmp, hash) {
  try { await blobs.adopt(hash, tmp); }
  catch (e) { console.error('[bdrivex] blob store put failed', hash.slice(0, 12), e.message); fail(503, STORE_DOWN, { 'retry-after': '60' }); }
}

/** Call inside oneAtATime(hash). Deletes the blob if no file row holds it; a failed delete is recorded and retried. */
async function unlinkIfOrphan(hash) {
  if (S.files.refs.get(hash).n !== 0) { S.blobDeletes.done.run(hash); return; }
  // The file row is gone already, so the user's delete has happened: don't fail it. Record the blob for the retry.
  try { await blobs.del(hash); S.blobDeletes.done.run(hash); }
  catch (e) {
    S.blobDeletes.failed.run(hash, now(), String(e.message).slice(0, 300));
    console.error(`[bdrivex] could not delete orphan blob ${hash} (will retry): ${e.message}`);
  }
}

let retrying = false;
async function retryBlobDeletes() {
  if (retrying) return;
  retrying = true;
  try { for (const { hash } of S.blobDeletes.all.all()) await oneAtATime(hash, () => unlinkIfOrphan(hash)); }
  finally { retrying = false; }
}

/** Stream a blob with Range support. Ciphertext only, never rendered by a browser. */
async function serveBlob(req, res, hash, extra = {}) {
  let size;
  try { size = await blobs.head(hash); }
  catch (e) { console.error('[bdrivex] blob store head failed', hash.slice(0, 12), e.message); fail(503, 'Storage is not answering right now. Try again in a minute.', { 'retry-after': '30' }); }
  if (size == null) fail(404, 'That file is gone.');
  const headers = {
    'content-type': 'application/octet-stream',
    'content-disposition': `attachment; filename="${hash.slice(0, 16)}.bdx"`,
    'x-content-type-options': 'nosniff',
    'content-security-policy': "default-src 'none'; sandbox",
    'accept-ranges': 'bytes',
    'cache-control': 'no-store',
    ...extra,
  };
  let start = 0, end = size - 1, status = 200;
  const range = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range || '');
  if (range && (range[1] || range[2])) {
    if (range[1]) { start = Number(range[1]); if (range[2]) end = Math.min(Number(range[2]), size - 1); }
    else { start = Math.max(0, size - Number(range[2])); }
    if (start > end || start >= size) fail(416, 'Range not satisfiable.', { 'content-range': `bytes */${size}` });
    status = 206;
    headers['content-range'] = `bytes ${start}-${end}/${size}`;
  }
  headers['content-length'] = String(size ? end - start + 1 : 0);
  if (req.method === 'HEAD' || size === 0) { res.writeHead(status, headers); return res.end(); }
  let body;
  try { body = await blobs.get(hash, { start, end }); } catch (e) { if (e instanceof BlobMissing) fail(404, 'That file is gone.'); throw e; }
  res.writeHead(status, headers);
  await pipeline(body, res);
}

/** Write the request body to `path` at `offset`, at most `max` bytes. On any failure the file is cut back. */
async function writeBody(req, path, offset, max, onChunk) {
  let n = 0;
  const counter = new Transform({
    transform(c, _e, cb) {
      n += c.length;
      if (n > max) return cb(new HttpError(413, 'Chunk is larger than the upload has room for.'));
      onChunk?.(c);
      cb(null, c);
    },
  });
  try {
    await pipeline(req, counter, createWriteStream(path, { flags: 'r+', start: offset }));
  } catch (e) {
    await truncate(path, offset).catch(() => {});
    if (e instanceof HttpError) throw e;
    fail(400, 'The upload was interrupted. Send that chunk again.');
  }
  return n;
}

const busy = new Set(); // uploads with a PATCH or complete in flight

// ---------- routes

const routes = [];
const route = (method, pattern, fn, opts = {}) => routes.push({ method, pattern, fn, ...opts });

route('POST', /^\/v1\/auth\/challenge$/, async (req) => {
  limit(req, 'auth', 30, 600_000);
  const origin = req.headers.origin;
  if (!origin || !ORIGINS.includes(origin)) fail(403, 'Sign in from bdrivex.com.');
  const { identityKey } = await readJson(req);
  try { return [200, await createChallenge({ origin, identityKey, store: nonceStore })]; }
  catch (e) { fail(400, e.message); }
});

route('POST', /^\/v1\/auth\/verify$/, async (req) => {
  limit(req, 'auth', 30, 600_000);
  const origin = req.headers.origin;
  if (!origin || !ORIGINS.includes(origin)) fail(403, 'Sign in from bdrivex.com.');
  const b = await readJson(req);
  const key = await verifySignIn({ origin, store: nonceStore, identityKey: b.identityKey, nonce: b.nonce, signature: b.signature });
  if (!key) fail(401, 'That signature was not accepted. Start again.');
  let scope = 'full', maxAge = SESSION_DAYS * 86400;
  if (!admitted(key)) {
    // Not invited, but someone sent this wallet a file: a recipient session that can only open it (v1.2).
    limit(req, 'auth-recipient', 20, 3600_000, key, 10);
    if (!S.links.liveFor.get(key, now())) fail(403, 'bDriveX is invite-only for now, and this wallet is not on the list yet.');
    scope = 'recipient';
    maxAge = RECIPIENT_SESSION_HOURS * 3600;
  }
  const claims = { sub: key, aud: origin, sid: newId(), gen: genOf(key), ...(scope === 'recipient' ? { scope } : {}) };
  const token = await signSession(claims, { secret: SECRET, maxAge });
  return [200, { token, identityKey: key, expiresAt: now() + maxAge * 1000, scope }];
});

route('POST', /^\/v1\/auth\/signout$/, async (req) => {
  S.sessions.revoke.run(req.session.sid, req.session.exp * 1000);
  return [204, null];
}, { auth: true, recipientOk: true });

route('POST', /^\/v1\/auth\/signout-all$/, async (req, owner) => {
  S.sessions.bump.run(owner);
  return [204, null];
}, { auth: true, recipientOk: true });

route('GET', /^\/v1\/me$/, async (req, owner) => [200, { identityKey: owner, usage: usage(owner) }], { auth: true });

route('POST', /^\/v1\/uploads$/, async (req, owner) => {
  limit(req, 'upload-new', 120, 3600_000, owner, 60);
  const { size } = await readJson(req);
  if (!Number.isSafeInteger(size) || size < 32) fail(400, 'size (bytes of sealed file) is required.');
  roomFor(owner, size);
  const id = newId();
  await (await open(tmpPath(id), 'w')).close();
  S.uploads.add.run(id, owner, size, now(), now());
  return [201, { id, size, offset: 0, chunkMax: CHUNK_MAX }];
}, { auth: true });

const myUpload = (id, owner) => {
  const u = ID.test(id) && S.uploads.get.get(id);
  if (!u || u.owner !== owner) fail(404, 'No such upload. Start again.');
  return u;
};

route('GET', /^\/v1\/uploads\/([\w-]+)$/, async (req, owner, [id]) => {
  const u = myUpload(id, owner);
  return [200, { id, size: u.size, offset: u.received }, { 'upload-offset': String(u.received), 'upload-length': String(u.size) }];
}, { auth: true, head: true });

route('PATCH', /^\/v1\/uploads\/([\w-]+)$/, async (req, owner, [id]) => {
  const u = myUpload(id, owner);
  const off = Number(req.headers['upload-offset']);
  if (off !== u.received) fail(409, 'Offset does not match the server.', { 'upload-offset': String(u.received) });
  if (busy.has(id)) fail(409, 'This upload is already receiving a chunk.', { 'upload-offset': String(u.received) });
  const len = Number(req.headers['content-length']) || CHUNK_MAX;
  spend('upload', owner, Math.min(len, CHUNK_MAX), UPLOAD_PER_DAY, 'You have uploaded a lot today. Carry on tomorrow.');
  busy.add(id);
  try {
    const n = await writeBody(req, tmpPath(id), off, Math.min(CHUNK_MAX, u.size - off));
    S.uploads.advance.run(off + n, now(), id);
    return [204, null, { 'upload-offset': String(off + n) }];
  } finally { busy.delete(id); }
}, { auth: true });

route('POST', /^\/v1\/uploads\/([\w-]+)\/complete$/, async (req, owner, [id]) => {
  const u = myUpload(id, owner);
  const { sha256, meta } = await readJson(req);
  if (u.received !== u.size) fail(409, `Upload is not finished (${u.received} of ${u.size} bytes).`);
  if (!HASH.test(String(sha256))) fail(400, 'sha256 (hex) of the sealed file is required.');
  if (meta != null && (typeof meta !== 'string' || meta.length > 8192 || !/^[A-Za-z0-9_-]*$/.test(meta))) fail(400, 'meta must be base64url, 8 KB at most.');
  if (busy.has(id)) fail(409, 'This upload is busy.');
  busy.add(id);
  try {
    const got = await sha256File(tmpPath(id));
    if (got !== sha256) {
      S.uploads.del.run(id);
      await rm(tmpPath(id), { force: true });
      fail(422, 'The file arrived changed (its hash does not match). Upload it again.');
    }
    // If the store is down, store() answers 503 and leaves the upload and its staged file as they were, to finish later.
    await oneAtATime(got, async () => {
      await store(tmpPath(id), got);
      S.files.add.run(owner, got, u.size, meta ?? null, now());
    });
    S.uploads.del.run(id);
    return [200, { hash: got, size: u.size }];
  } finally { busy.delete(id); }
}, { auth: true });

route('DELETE', /^\/v1\/uploads\/([\w-]+)$/, async (req, owner, [id]) => {
  myUpload(id, owner);
  if (busy.has(id)) fail(409, 'This upload is busy.');
  S.uploads.del.run(id);
  await rm(tmpPath(id), { force: true });
  return [204, null];
}, { auth: true });

// Small blobs in one request, addressed by the hash the client already knows (bPhotosX photos).
route('PUT', /^\/v1\/blobs\/([0-9a-f]{64})$/, async (req, owner, [hash]) => {
  limit(req, 'put', 1200, 3600_000, owner, 600);
  const len = Number(req.headers['content-length']);
  if (!Number.isSafeInteger(len) || len < 1) fail(411, 'Content-Length is required.');
  if (len > PUT_MAX) fail(413, 'Use /v1/uploads for files over 64 MB.');
  if (S.files.get.get(owner, hash)) { req.resume(); return [200, { hash, size: len }]; }
  roomFor(owner, len);
  spend('upload', owner, len, UPLOAD_PER_DAY, 'You have uploaded a lot today. Carry on tomorrow.');
  const id = newId(), tmp = tmpPath(id);
  await (await open(tmp, 'w')).close();
  const h = createHash('sha256');
  const n = await writeBody(req, tmp, 0, len, (c) => h.update(c));
  if (n !== len || h.digest('hex') !== hash) {
    await rm(tmp, { force: true });
    fail(422, 'The body does not match its hash.');
  }
  try {
    await oneAtATime(hash, async () => {
      await store(tmp, hash);
      S.files.add.run(owner, hash, len, req.headers['x-bdx-meta'] || null, now());
    });
  } finally { await rm(tmp, { force: true }); } // nothing to resume for a single PUT
  return [201, { hash, size: len }];
}, { auth: true });

route('GET', /^\/v1\/blobs\/([0-9a-f]{64})$/, async (req, owner, [hash], res) => {
  if (!S.files.get.get(owner, hash)) fail(404, 'No such file.');
  await serveBlob(req, res, hash);
}, { auth: true, head: true, raw: true });

// The owner's view of a link. For a link sent to one person: who (key and the label the sender typed) and whether the
// wrap is in place. The wrap itself is not repeated here; only the recipient needs it.
const linkView = (l) => ({
  id: l.id, createdAt: l.created_at, expiresAt: l.expires_at, revokedAt: l.revoked_at, downloads: l.downloads, reported: !!S.reports.get.get(l.id),
  bound: !!l.recipient, recipient: l.recipient ?? null, recipientLabel: l.recipient_label ?? null, ready: !l.recipient || !!l.recipient_wrap,
});

route('GET', /^\/v1\/files$/, async (req, owner) => {
  const files = S.files.mine.all(owner).map((f) => ({
    hash: f.hash, size: f.size, meta: f.meta, keyWrap: f.key_wrap ?? null, createdAt: f.created_at,
    links: S.links.forFile.all(owner, f.hash).map(linkView),
  }));
  return [200, { files, usage: usage(owner) }];
}, { auth: true });

// The file key wrapped by the owner's own wallet, so any device signed in to that wallet can open its files.
// Opaque here like everything else; it goes back only to the owner, in GET /v1/files.
route('PUT', /^\/v1\/files\/([0-9a-f]{64})\/key$/, async (req, owner, [hash]) => {
  limit(req, 'key', 1200, 3600_000, owner, 600);
  const { keyWrap } = await readJson(req);
  if (keyWrap != null && (typeof keyWrap !== 'string' || keyWrap.length < 1 || keyWrap.length > 1024 || !/^[A-Za-z0-9_-]+$/.test(keyWrap))) fail(400, 'keyWrap must be base64url, 1 KB at most.');
  if (!S.files.get.get(owner, hash)) fail(404, 'No such file.');
  S.files.wrap.run(keyWrap ?? null, owner, hash);
  return [204, null];
}, { auth: true });

route('DELETE', /^\/v1\/files\/([0-9a-f]{64})$/, async (req, owner, [hash]) => {
  if (!S.files.get.get(owner, hash)) fail(404, 'No such file.');
  await oneAtATime(hash, async () => {
    S.files.del.run(owner, hash); // its links go with it (ON DELETE CASCADE)
    await unlinkIfOrphan(hash);
  });
  return [204, null];
}, { auth: true });

// v1.2 recipient fields. Every one is optional on POST; recipientWrap and recipientLabel need a recipient.
function recipientFields(b, owner, { need = false } = {}) {
  const { recipient = null, recipientWrap = null, recipientLabel = null, senderKey = null } = b;
  if (senderKey != null && !same(String(senderKey).toLowerCase(), owner)) fail(400, 'senderKey must be your own identity key.');
  if (recipient == null) {
    if (need) fail(400, 'recipient (an identity key) is required.');
    if (recipientWrap != null || recipientLabel != null) fail(400, 'recipientWrap and recipientLabel need a recipient.');
    return { recipient: null, recipientWrap: null, recipientLabel: null };
  }
  if (typeof recipient !== 'string' || !KEY.test(recipient.toLowerCase())) fail(400, 'recipient must be an identity key: 66 hex characters starting 02 or 03.');
  if (recipientWrap != null && (typeof recipientWrap !== 'string' || recipientWrap.length < 1 || recipientWrap.length > 1024 || !B64U.test(recipientWrap))) fail(400, 'recipientWrap must be base64url, 1 KB at most.');
  if (recipientLabel != null && (typeof recipientLabel !== 'string' || !LABEL.test(recipientLabel))) fail(400, 'recipientLabel must be a $handle or paymail.');
  return { recipient: recipient.toLowerCase(), recipientWrap, recipientLabel };
}

route('POST', /^\/v1\/links$/, async (req, owner) => {
  limit(req, 'link-new', 300, 3600_000, owner, 200);
  const b = await readJson(req);
  const { hash, ttl = null } = b;
  if (!HASH.test(String(hash)) || !S.files.get.get(owner, hash)) fail(404, 'No such file.');
  const max = LINK_DAYS * 86400;
  if (ttl != null && (!Number.isSafeInteger(ttl) || ttl < 60 || ttl > max)) fail(400, `ttl is seconds, from 60 up to ${LINK_DAYS} days.`);
  const r = recipientFields(b, owner);
  const id = newId(), t = now();
  const expiresAt = t + (ttl ?? max) * 1000;
  S.links.add.run(id, owner, hash, t, expiresAt, r.recipient, r.recipientWrap, r.recipientLabel);
  return [201, { id, createdAt: t, expiresAt, bound: !!r.recipient }];
}, { auth: true, share: true });

// Bind a link to one person, or put the wrap in place once the wallet has made it (it needs the link id).
// A link's recipient can be set once and never changed: for someone else, make a new link.
route('PUT', /^\/v1\/links\/([\w-]+)\/recipient$/, async (req, owner, [id]) => {
  limit(req, 'link-bind', 300, 3600_000, owner, 200);
  const l = ID.test(id) && S.links.get.get(id);
  if (!l || l.owner !== owner || l.revoked_at) fail(404, 'No such link.');
  if (l.expires_at && l.expires_at < now()) fail(410, 'This link has expired.');
  const r = recipientFields(await readJson(req), owner, { need: true });
  if (r.recipientWrap == null) fail(400, 'recipientWrap is required.');
  if (l.recipient && !same(l.recipient, r.recipient)) fail(409, 'This link is already for someone else. Make a new link.');
  S.links.bind.run(r.recipient, r.recipientWrap, r.recipientLabel ?? l.recipient_label ?? null, id, owner);
  return [204, null];
}, { auth: true, share: true });

route('DELETE', /^\/v1\/links\/([\w-]+)$/, async (req, owner, [id]) => {
  const l = ID.test(id) && S.links.get.get(id);
  if (!l || l.owner !== owner) fail(404, 'No such link.');
  S.links.revoke.run(now(), id, owner);
  return [204, null];
}, { auth: true });

function liveLink(id) {
  const l = ID.test(id) && S.links.get.get(id);
  if (l && S.reports.get.get(id)) fail(404, 'This link was switched off after a report.');
  if (!l || l.revoked_at) fail(404, 'This link was switched off or never existed.');
  if (l.expires_at && l.expires_at < now()) fail(410, 'This link has expired. Ask the sender for a new one.');
  return l;
}

const SOMEONE_ELSE = 'This file was sent to someone else.';
/** For a link sent to one person: is this request signed in as that person? */
async function asRecipient(req, l) {
  const s = await maybeSession(req);
  if (!s || !same(s.sub, l.recipient)) return null;
  limit(req, 'link-key', 240, 60_000, s.sub, 120);
  return s;
}

route('GET', /^\/v1\/s\/([\w-]+)$/, async (req, _o, [id]) => {
  limit(req, 'link', 240, 60_000);
  const l = liveLink(id);
  const f = S.files.get.get(l.owner, l.hash);
  if (!l.recipient) return [200, { id, size: f.size, meta: f.meta, createdAt: l.created_at, expiresAt: l.expires_at }];
  // Sent to one person: anyone else learns only that, who sent it, and the size and dates. Never the recipient.
  const view = { id, bound: true, to: null, from: l.owner, size: f.size, createdAt: l.created_at, expiresAt: l.expires_at };
  if (!(await asRecipient(req, l))) return [200, { ...view, forYou: false }];
  if (!l.recipient_wrap) fail(409, 'The sender hasn’t finished sending this yet. Try again in a minute.');
  return [200, { ...view, forYou: true, hash: l.hash, meta: f.meta, senderKey: l.owner, recipientWrap: l.recipient_wrap }];
}, { public: true });

route('GET', /^\/v1\/s\/([\w-]+)\/blob$/, async (req, _o, [id], res) => {
  limit(req, 'link-blob', 120, 60_000);
  const l = liveLink(id);
  if (l.recipient && !(await asRecipient(req, l))) fail(403, SOMEONE_ELSE);
  if (req.method === 'GET') {
    const f = S.files.get.get(l.owner, l.hash);
    const from = Number(/^bytes=(\d+)-/.exec(req.headers.range || '')?.[1] || 0);
    spend('egress', l.owner, Math.max(0, f.size - from), EGRESS_PER_DAY, 'This sender’s files have been downloaded a lot today. Try again tomorrow.');
    if (!from) S.links.hit.run(id);
  }
  await serveBlob(req, res, l.hash);
}, { public: true, head: true, raw: true });

// Anyone holding a link can report it, and it is switched off at once; the owner reviews reports by hand for now.
route('POST', /^\/v1\/s\/([\w-]+)\/report$/, async (req, _o, [id]) => {
  limit(req, 'report', 10, 3600_000);
  const l = ID.test(id) && S.links.get.get(id);
  if (!l) fail(404, 'No such link.');
  // Only the recipient can see what a bound link holds, so only they can report it (and nobody else can switch it off).
  if (l.recipient && !(await asRecipient(req, l))) fail(403, SOMEONE_ELSE);
  const { reason } = await readJson(req, 4096);
  S.reports.add.run(id, now(), String(reason || '').slice(0, 500), ip(req));
  console.warn(`[bdrivex] link ${id} reported and switched off (owner ${l.owner.slice(0, 12)}…, file ${l.hash.slice(0, 12)}…)`);
  return [204, null];
}, { public: true });

route('GET', /^\/health$/, async () => [200, { ok: true }], { public: true });

// ---------- server

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const path = url.pathname;
  const isPublic = path.startsWith('/v1/s/') || path === '/health';
  cors(req, res, isPublic);
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'access-control-allow-methods': 'GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS',
      'access-control-allow-headers': 'Authorization, Content-Type, Upload-Offset, Upload-Length, Range, X-Bdx-Meta',
      'access-control-max-age': '600',
    });
    return res.end();
  }
  try {
    for (const r of routes) {
      const m = r.pattern.exec(path);
      if (!m || !(r.method === req.method || (r.head && req.method === 'HEAD' && r.method === 'GET'))) continue;
      const owner = r.auth ? await auth(req, r) : null;
      const out = await r.fn(req, owner, m.slice(1), res);
      if (r.raw) return;
      const [status, body, headers] = out;
      return send(res, status, req.method === 'HEAD' ? null : body, headers);
    }
    fail(404, 'Not found.');
  } catch (e) {
    if (res.headersSent) return res.destroy();
    if (!(e instanceof HttpError)) console.error('[bdrivex]', req.method, path, e);
    const status = e instanceof HttpError ? e.status : 500;
    const body = !(e instanceof HttpError) ? { error: 'Something went wrong on our side.' } : e.code ? { error: e.code, message: e.message } : { error: e.message };
    send(res, status, body, e.headers);
    if (status !== 500) req.resume();
  }
});
server.requestTimeout = 0; // big chunks on slow links; headersTimeout still applies
server.listen(PORT, HOST, () => console.log(`[bdrivex] api on http://${HOST}:${PORT} · data ${DATA} · blobs ${blobs.describe()} · origins ${ORIGINS.join(' ')} · sign-up ${SIGNUP} · sharing ${SHARING}`));

setInterval(() => retryBlobDeletes().catch((e) => console.error('[bdrivex] blob delete retry', e)), BLOB_DELETE_RETRY_MS).unref();

// Abandoned uploads (no chunk for 2 days) are cleared out hourly.
setInterval(async () => {
  for (const { id } of S.uploads.stale.all(now() - 2 * 86400_000)) {
    if (busy.has(id)) continue;
    S.uploads.del.run(id);
    await rm(tmpPath(id), { force: true });
  }
  S.sessions.prune.run(now());
  windows.clear();
}, 3600_000).unref();

export { server };
