// A fake S3-compatible server for tests: path-style PUT, GET (with Range), HEAD, DELETE and ListObjectsV2, objects kept
// as plain files under <root>/<bucket>/<key> so a test can read or tamper with them. Like the real thing it checks
// every request's SigV4 signature (recomputed with the shared secret), refuses a PUT whose bytes do not match
// x-amz-content-sha256, and wants a Content-Length on PUT.
import { createServer } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { createReadStream, createWriteStream, mkdirSync, readdirSync, statSync } from 'node:fs';
import { rename, rm } from 'node:fs/promises';
import { dirname, join, relative, sep } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { signV4 } from '../src/s3.js';

const AUTH = /^AWS4-HMAC-SHA256 Credential=([^/]+)\/(\d{8})\/([^/]+)\/s3\/aws4_request, SignedHeaders=([a-z0-9;-]+), Signature=([0-9a-f]{64})$/;
const xml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/**
 * startFakeS3({ root, region, credentials: { accessKeyId: secret }, buckets: [...], pageSize })
 * Resolves with { endpoint, port, requests, authFailures, failNext(method, status, times), objectPath(bucket, key), close() }.
 */
export async function startFakeS3({ root, region = 'fsn1', credentials, buckets = [], pageSize = 1000 }) {
  for (const b of buckets) mkdirSync(join(root, b), { recursive: true });
  const requests = [];      // { method, bucket, key, query, signedHeaders, authorization }
  const authFailures = [];  // reasons
  const failures = [];      // injected: { method, status, times }

  const reply = (res, status, code, message, extra = {}) => {
    const body = code ? `<?xml version="1.0" encoding="UTF-8"?><Error><Code>${code}</Code><Message>${xml(message)}</Message></Error>` : '';
    res.writeHead(status, { 'content-type': 'application/xml', 'content-length': Buffer.byteLength(body), ...extra });
    res.end(body);
  };

  function checkAuth(req, url) {
    const m = AUTH.exec(req.headers.authorization || '');
    if (!m) return 'Authorization header is not AWS4-HMAC-SHA256 Credential=…, SignedHeaders=…, Signature=…';
    const [, akid, day, reg, signedHeaders] = m;
    const secret = credentials[akid];
    if (!secret) return `unknown access key ${akid}`;
    if (reg !== region) return `wrong region ${reg}`;
    const names = signedHeaders.split(';');
    for (const n of ['host', 'x-amz-content-sha256', 'x-amz-date']) if (!names.includes(n)) return `${n} is not signed`;
    const amz = req.headers['x-amz-date'] || '';
    if (!/^\d{8}T\d{6}Z$/.test(amz) || amz.slice(0, 8) !== day) return 'bad x-amz-date';
    const date = new Date(`${amz.slice(0, 4)}-${amz.slice(4, 6)}-${amz.slice(6, 8)}T${amz.slice(9, 11)}:${amz.slice(11, 13)}:${amz.slice(13, 15)}Z`);
    if (Math.abs(Date.now() - date) > 15 * 60e3) return 'request time too skewed';
    const headers = {};
    for (const n of names) if (!['host', 'x-amz-date', 'x-amz-content-sha256'].includes(n)) headers[n] = req.headers[n];
    const want = signV4({ method: req.method, url, headers, payloadHash: req.headers['x-amz-content-sha256'], region, accessKeyId: akid, secretAccessKey: secret, date }).authorization;
    if (want !== req.headers.authorization) return 'signature does not match';
    return null;
  }

  const listKeys = (dir) => {
    const out = [];
    const walk = (d) => { for (const e of readdirSync(d, { withFileTypes: true })) { const p = join(d, e.name); if (e.isDirectory()) walk(p); else if (!e.name.includes('.fake-part-')) out.push(p); } };
    walk(dir);
    return out.map((p) => relative(dir, p).split(sep).join('/')).sort();
  };

  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, `http://${req.headers.host}`);
      const [, bucket = '', ...rest] = url.pathname.split('/');
      const key = rest.map(decodeURIComponent).join('/');
      const why = checkAuth(req, url);
      requests.push({ method: req.method, bucket: decodeURIComponent(bucket), key, query: Object.fromEntries(url.searchParams), range: req.headers.range, authorization: req.headers.authorization });
      if (why) { authFailures.push(`${req.method} ${url.pathname}: ${why}`); req.resume(); return reply(res, 403, 'SignatureDoesNotMatch', why); }
      const f = failures.find((x) => x.method === req.method && x.times > 0);
      if (f) { f.times--; req.resume(); return reply(res, f.status, 'InjectedFailure', 'injected by the test'); }
      const bdir = join(root, decodeURIComponent(bucket));
      try { statSync(bdir); } catch { req.resume(); return reply(res, 404, 'NoSuchBucket', 'no such bucket'); }
      const file = join(bdir, ...key.split('/'));
      if (key && (key.split('/').some((s) => s === '..' || s === '') || !file.startsWith(bdir + sep))) { req.resume(); return reply(res, 400, 'InvalidKey', 'bad key'); }

      if (req.method === 'GET' && !key) {
        if (url.searchParams.get('list-type') !== '2') return reply(res, 400, 'NotImplemented', 'only ListObjectsV2');
        const prefix = url.searchParams.get('prefix') || '';
        const max = Math.min(Number(url.searchParams.get('max-keys') || 1000), pageSize);
        const after = url.searchParams.get('continuation-token') ? Buffer.from(url.searchParams.get('continuation-token'), 'base64url').toString() : '';
        const all = listKeys(bdir).filter((k) => k.startsWith(prefix) && k > after);
        const page = all.slice(0, max);
        const truncated = all.length > max;
        const body = `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>${xml(bucket)}</Name><Prefix>${xml(prefix)}</Prefix><KeyCount>${page.length}</KeyCount><MaxKeys>${max}</MaxKeys><IsTruncated>${truncated}</IsTruncated>`
          + page.map((k) => `<Contents><Key>${xml(k)}</Key><Size>${statSync(join(bdir, ...k.split('/'))).size}</Size><StorageClass>STANDARD</StorageClass></Contents>`).join('')
          + (truncated ? `<NextContinuationToken>${Buffer.from(page.at(-1)).toString('base64url')}</NextContinuationToken>` : '') + '</ListBucketResult>';
        res.writeHead(200, { 'content-type': 'application/xml', 'content-length': Buffer.byteLength(body) });
        return res.end(body);
      }
      if (!key) return reply(res, 405, 'MethodNotAllowed', 'bucket operations other than list are not faked');

      if (req.method === 'PUT') {
        const len = req.headers['content-length'];
        if (len == null) { req.resume(); return reply(res, 411, 'MissingContentLength', 'Content-Length is required'); }
        mkdirSync(dirname(file), { recursive: true });
        const part = `${file}.fake-part-${randomBytes(4).toString('hex')}`;
        const h = createHash('sha256');
        let n = 0;
        req.on('data', (c) => { h.update(c); n += c.length; });
        await pipeline(req, createWriteStream(part));
        const claimed = req.headers['x-amz-content-sha256'];
        const got = h.digest('hex');
        if (n !== Number(len)) { await rm(part, { force: true }); return reply(res, 400, 'IncompleteBody', 'body shorter than Content-Length'); }
        if (claimed !== 'UNSIGNED-PAYLOAD' && claimed !== got) { await rm(part, { force: true }); return reply(res, 400, 'XAmzContentSHA256Mismatch', 'The provided x-amz-content-sha256 header does not match what was computed.'); }
        await rename(part, file);
        res.writeHead(200, { etag: `"${createHash('md5').update(got).digest('hex')}"`, 'content-length': 0 });
        return res.end();
      }

      let size;
      try { size = statSync(file).size; } catch { size = null; }
      if (req.method === 'DELETE') { await rm(file, { force: true }); res.writeHead(204); return res.end(); }
      if (size == null) {
        if (req.method === 'HEAD') { res.writeHead(404); return res.end(); }
        return reply(res, 404, 'NoSuchKey', 'The specified key does not exist.');
      }
      if (req.method === 'HEAD') { res.writeHead(200, { 'content-length': size, 'accept-ranges': 'bytes' }); return res.end(); }
      if (req.method === 'GET') {
        let start = 0, end = size - 1, status = 200;
        const headers = { 'accept-ranges': 'bytes', 'content-type': 'application/octet-stream' };
        const r = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range || '');
        if (req.headers.range && !r) return reply(res, 400, 'InvalidRange', 'bad Range');
        if (r) {
          if (r[1]) { start = Number(r[1]); if (r[2]) end = Math.min(Number(r[2]), size - 1); } else start = Math.max(0, size - Number(r[2]));
          if (start > end || start >= size) return reply(res, 416, 'InvalidRange', 'The requested range is not satisfiable', { 'content-range': `bytes */${size}` });
          status = 206;
          headers['content-range'] = `bytes ${start}-${end}/${size}`;
        }
        headers['content-length'] = size ? end - start + 1 : 0;
        res.writeHead(status, headers);
        if (!size) return res.end();
        return await pipeline(createReadStream(file, { start, end }), res);
      }
      reply(res, 405, 'MethodNotAllowed', req.method);
    } catch (e) {
      if (!res.headersSent) reply(res, 500, 'InternalError', e.message); else res.destroy();
    }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  return {
    endpoint: `http://127.0.0.1:${port}`,
    port,
    requests,
    authFailures,
    /** The next `times` requests with this method get `status`. */
    failNext(method, status = 503, times = 1) { failures.push({ method, status, times }); },
    clearFailures() { failures.length = 0; },
    objectPath: (bucket, key) => join(root, bucket, ...key.split('/')),
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }),
  };
}
