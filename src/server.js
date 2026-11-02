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
//   GET    /v1/files                                                    -> { files: [...links], usage }
//   DELETE /v1/files/:sha256
//   POST   /v1/links               { hash, ttl }  (seconds, default and max 30 days) -> { id, expiresAt }
//   DELETE /v1/links/:id                                                -> revoke
//   GET    /v1/s/:id               public                               -> { size, meta, createdAt, expiresAt }
//   GET    /v1/s/:id/blob          public, Range ok                     -> ciphertext
//   POST   /v1/s/:id/report        public { reason }                   -> the link is switched off at once
//
// Auth: Authorization: Bearer <token> from /v1/auth/verify: a 7-day session signed with SESSION_SECRET, carrying
// aud (the site it was signed for), sid (for revoking one) and gen (bumped by sign-out-everywhere).
import { createServer } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { createReadStream, createWriteStream, mkdirSync } from 'node:fs';
import { open, rename, rm, stat, truncate } from 'node:fs/promises';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import { createChallenge, signSession, verifySession, verifySignIn } from '@bwalletx/connect/server';
import { openDb } from './db.js';

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
// Who can sign in (CTO, 2 Nov 2026): SIGNUP=invite (default in production) admits only ALLOWED_KEYS, the owner, the
// team and invitees, until the Online Safety Act risk assessment, terms and takedown route are in place. SIGNUP=open
// admits any bWalletX. Local dev defaults to open.
const SIGNUP = env.SIGNUP || (PROD ? 'invite' : 'open');
if (!['open', 'invite'].includes(SIGNUP)) throw new Error('SIGNUP must be open or invite.');
const ALLOWED_KEYS = new Set((env.ALLOWED_KEYS || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean));
const TRUST_PROXY = env.TRUST_PROXY === '1';

let SECRET = env.SESSION_SECRET || '';
if (SECRET.length < 32) {
  if (PROD) throw new Error('SESSION_SECRET (32+ chars) is required in production.');
  SECRET = randomBytes(32).toString('hex');
  console.warn('[bdrivex] no SESSION_SECRET: using a random one, so sign-ins end when this process restarts.');
}

for (const d of ['blobs', 'tmp']) mkdirSync(join(DATA, d), { recursive: true });
const S = openDb(join(DATA, 'bdrivex.db'));
const blobPath = (h) => join(DATA, 'blobs', h.slice(0, 2), h.slice(2, 4), h);
const tmpPath = (id) => join(DATA, 'tmp', id);
const now = () => Date.now();
const HASH = /^[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9_-]{22}$/;
const newId = () => randomBytes(16).toString('base64url');

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

class HttpError extends Error {
  constructor(status, message, headers) { super(message); this.status = status; this.headers = headers; }
}
const fail = (status, message, headers) => { throw new HttpError(status, message, headers); };

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

const admitted = (key) => SIGNUP === 'open' || ALLOWED_KEYS.has(key);
const genOf = (owner) => S.sessions.gen.get(owner)?.gen ?? 0;
async function auth(req) {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  const s = m && (await verifySession(m[1], { secret: SECRET }));
  if (!s || typeof s.sid !== 'string' || S.sessions.isRevoked.get(s.sid) || s.gen !== genOf(s.sub)) fail(401, 'Sign in with bWalletX first.');
  if (!admitted(s.sub)) fail(403, 'bDriveX is invite-only for now, and this wallet is not on the list.');
  req.session = s;
  // A browser token works only on the site it was signed for. Agents and CLIs send no Origin.
  if (req.headers.origin && s.aud && req.headers.origin !== s.aud) fail(401, 'This sign-in belongs to another site.');
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

/** Move a finished tmp file into the blob store under its hash (identical ciphertext is stored once). */
async function store(tmp, hash) {
  const dest = blobPath(hash);
  mkdirSync(join(dest, '..'), { recursive: true });
  try { await stat(dest); await rm(tmp, { force: true }); } catch { await rename(tmp, dest); }
}

async function unlinkIfOrphan(hash) {
  if (S.files.refs.get(hash).n === 0) await rm(blobPath(hash), { force: true });
}

/** Stream a blob with Range support. Ciphertext only, never rendered by a browser. */
async function serveBlob(req, res, hash, extra = {}) {
  const path = blobPath(hash);
  let size;
  try { size = (await stat(path)).size; } catch { fail(404, 'That file is gone.'); }
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
  res.writeHead(status, headers);
  if (req.method === 'HEAD' || size === 0) return res.end();
  await pipeline(createReadStream(path, { start, end }), res);
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
  if (!admitted(key)) fail(403, 'bDriveX is invite-only for now, and this wallet is not on the list yet.');
  const maxAge = SESSION_DAYS * 86400;
  const token = await signSession({ sub: key, aud: origin, sid: newId(), gen: genOf(key) }, { secret: SECRET, maxAge });
  return [200, { token, identityKey: key, expiresAt: now() + maxAge * 1000 }];
});

route('POST', /^\/v1\/auth\/signout$/, async (req) => {
  S.sessions.revoke.run(req.session.sid, req.session.exp * 1000);
  return [204, null];
}, { auth: true });

route('POST', /^\/v1\/auth\/signout-all$/, async (req, owner) => {
  S.sessions.bump.run(owner);
  return [204, null];
}, { auth: true });

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
    await store(tmpPath(id), got);
    S.files.add.run(owner, got, u.size, meta ?? null, now());
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
  await store(tmp, hash);
  S.files.add.run(owner, hash, len, req.headers['x-bdx-meta'] || null, now());
  return [201, { hash, size: len }];
}, { auth: true });

route('GET', /^\/v1\/blobs\/([0-9a-f]{64})$/, async (req, owner, [hash], res) => {
  if (!S.files.get.get(owner, hash)) fail(404, 'No such file.');
  await serveBlob(req, res, hash);
}, { auth: true, head: true, raw: true });

const linkView = (l) => ({ id: l.id, createdAt: l.created_at, expiresAt: l.expires_at, revokedAt: l.revoked_at, downloads: l.downloads, reported: !!S.reports.get.get(l.id) });

route('GET', /^\/v1\/files$/, async (req, owner) => {
  const files = S.files.mine.all(owner).map((f) => ({
    hash: f.hash, size: f.size, meta: f.meta, createdAt: f.created_at,
    links: S.links.forFile.all(owner, f.hash).map(linkView),
  }));
  return [200, { files, usage: usage(owner) }];
}, { auth: true });

route('DELETE', /^\/v1\/files\/([0-9a-f]{64})$/, async (req, owner, [hash]) => {
  if (!S.files.get.get(owner, hash)) fail(404, 'No such file.');
  S.files.del.run(owner, hash); // its links go with it (ON DELETE CASCADE)
  await unlinkIfOrphan(hash);
  return [204, null];
}, { auth: true });

route('POST', /^\/v1\/links$/, async (req, owner) => {
  limit(req, 'link-new', 300, 3600_000, owner, 200);
  const { hash, ttl = null } = await readJson(req);
  if (!HASH.test(String(hash)) || !S.files.get.get(owner, hash)) fail(404, 'No such file.');
  const max = LINK_DAYS * 86400;
  if (ttl != null && (!Number.isSafeInteger(ttl) || ttl < 60 || ttl > max)) fail(400, `ttl is seconds, from 60 up to ${LINK_DAYS} days.`);
  const id = newId(), t = now();
  const expiresAt = t + (ttl ?? max) * 1000;
  S.links.add.run(id, owner, hash, t, expiresAt);
  return [201, { id, createdAt: t, expiresAt }];
}, { auth: true });

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

route('GET', /^\/v1\/s\/([\w-]+)$/, async (req, _o, [id]) => {
  limit(req, 'link', 240, 60_000);
  const l = liveLink(id);
  const f = S.files.get.get(l.owner, l.hash);
  return [200, { id, size: f.size, meta: f.meta, createdAt: l.created_at, expiresAt: l.expires_at }];
}, { public: true });

route('GET', /^\/v1\/s\/([\w-]+)\/blob$/, async (req, _o, [id], res) => {
  limit(req, 'link-blob', 120, 60_000);
  const l = liveLink(id);
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
      const owner = r.auth ? await auth(req) : null;
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
    send(res, status, { error: e instanceof HttpError ? e.message : 'Something went wrong on our side.' }, e.headers);
    if (status !== 500) req.resume();
  }
});
server.requestTimeout = 0; // big chunks on slow links; headersTimeout still applies
server.listen(PORT, HOST, () => console.log(`[bdrivex] api on http://${HOST}:${PORT} · data ${DATA} · origins ${ORIGINS.join(' ')} · sign-up ${SIGNUP}`));

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
