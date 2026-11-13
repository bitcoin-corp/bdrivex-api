// A small S3 client for any S3-compatible service (Hetzner Object Storage, Backblaze B2, MinIO, AWS): AWS Signature
// Version 4 with node:crypto, requests with node:http(s). No dependencies. Path-style URLs only
// (https://<endpoint>/<bucket>/<key>), which every one of those services accepts.
//
// Object bodies are signed with their real SHA-256 (x-amz-content-sha256), and blobs here are named by that hash, so
// the service itself refuses a PUT whose bytes do not match the key.
import { createHash, createHmac } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';

export const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const HEX64 = /^[0-9a-f]{64}$/;

const sha256hex = (s) => createHash('sha256').update(s).digest('hex');
const hmac = (key, s) => createHmac('sha256', key).update(s).digest();
/** RFC 3986 encoding as SigV4 wants it: everything but A-Z a-z 0-9 - _ . ~ is %XX (uppercase). */
const enc = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
/** An object key as a URL path: each segment encoded, the slashes kept. */
export const encodeKey = (key) => key.split('/').map(enc).join('/');

/**
 * Sign a request with AWS SigV4. Every header passed in is signed (plus host). Returns the headers to send:
 * the ones given, host, x-amz-date, x-amz-content-sha256 and authorization.
 *   url: a URL whose pathname is already encoded (see encodeKey) and whose search params are the query.
 */
export function signV4({ method, url, headers = {}, payloadHash = EMPTY_SHA256, region, accessKeyId, secretAccessKey, service = 's3', date = new Date() }) {
  const u = url instanceof URL ? url : new URL(url);
  const amzDate = date.toISOString().replace(/[:-]|\.\d{3}/g, ''); // 20130524T000000Z
  const day = amzDate.slice(0, 8);
  const h = {};
  for (const [k, v] of Object.entries(headers)) if (v != null) h[k.toLowerCase()] = String(v).trim().replace(/\s+/g, ' ');
  h.host = u.host;
  h['x-amz-date'] = amzDate;
  h['x-amz-content-sha256'] = payloadHash;
  const names = Object.keys(h).sort();
  const query = [...u.searchParams].map(([k, v]) => [enc(k), enc(v)]).sort(([a, x], [b, y]) => (a < b ? -1 : a > b ? 1 : x < y ? -1 : x > y ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`).join('&');
  const canonical = [method, u.pathname || '/', query, names.map((n) => `${n}:${h[n]}\n`).join(''), names.join(';'), payloadHash].join('\n');
  const scope = `${day}/${region}/${service}/aws4_request`;
  const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256hex(canonical)].join('\n');
  const key = hmac(hmac(hmac(hmac('AWS4' + secretAccessKey, day), region), service), 'aws4_request');
  const signature = createHmac('sha256', key).update(toSign).digest('hex');
  h.authorization = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${names.join(';')}, Signature=${signature}`;
  return h;
}

export class S3Error extends Error {
  constructor(status, code, message) { super(`S3 ${status}${code ? ' ' + code : ''}: ${message}`); this.status = status; this.code = code; }
}

const xmlText = (s) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
const tag = (xml, name) => { const m = new RegExp(`<${name}>([\\s\\S]*?)</${name}>`).exec(xml); return m ? xmlText(m[1]) : null; };

async function readAll(stream, limit = 1 << 20) {
  const parts = [];
  let n = 0;
  for await (const c of stream) { n += c.length; if (n <= limit) parts.push(c); }
  return Buffer.concat(parts).toString('utf8');
}

/** S3 settings from env, under a prefix: S3_ENDPOINT, S3_REGION, ... or B2_ENDPOINT, B2_REGION, ... */
export function s3ConfigFromEnv(env, p = 'S3') {
  const cfg = {
    endpoint: env[`${p}_ENDPOINT`] || '', region: env[`${p}_REGION`] || '', bucket: env[`${p}_BUCKET`] || '',
    accessKeyId: env[`${p}_ACCESS_KEY_ID`] || '', secretAccessKey: env[`${p}_SECRET_ACCESS_KEY`] || '', prefix: env[`${p}_PREFIX`] || '',
  };
  const missing = ['endpoint', 'region', 'bucket', 'accessKeyId', 'secretAccessKey'].filter((k) => !cfg[k]);
  if (missing.length) {
    const names = { endpoint: 'ENDPOINT', region: 'REGION', bucket: 'BUCKET', accessKeyId: 'ACCESS_KEY_ID', secretAccessKey: 'SECRET_ACCESS_KEY' };
    throw new Error(`Missing ${missing.map((k) => `${p}_${names[k]}`).join(', ')}.`);
  }
  if (!/^https?:\/\/[^/]+\/?$/.test(cfg.endpoint)) throw new Error(`${p}_ENDPOINT must be like https://fsn1.your-objectstorage.com (no bucket, no path).`);
  if (cfg.prefix.startsWith('/')) throw new Error(`${p}_PREFIX must not start with /.`);
  return cfg;
}

/**
 * A client for one bucket.
 *   timeoutMs: how long a socket may sit idle before the request is abandoned (not a cap on the whole transfer).
 */
export function createS3Client({ endpoint, region, bucket, accessKeyId, secretAccessKey, timeoutMs = 120_000 }) {
  const base = new URL(endpoint.replace(/\/+$/, ''));
  const lib = base.protocol === 'http:' ? http : https;
  const agent = new lib.Agent({ keepAlive: true, maxSockets: 32 });

  /**
   * One signed request. Resolves with the response (a readable stream) for any status; the caller reads or drains it.
   *   key: object key ('' for the bucket itself). body: a Buffer, a Readable, or nothing.
   */
  function request(method, key, { query = {}, headers = {}, body = null, payloadHash = EMPTY_SHA256 } = {}) {
    const url = new URL(base);
    url.pathname = `/${enc(bucket)}${key ? '/' + encodeKey(key) : ''}`;
    for (const [k, v] of Object.entries(query)) if (v != null) url.searchParams.set(k, String(v));
    // URLSearchParams writes spaces as '+'; S3 wants %20 on the wire, matching the canonical query.
    const search = [...url.searchParams].map(([k, v]) => `${enc(k)}=${enc(v)}`).join('&');
    const signed = signV4({ method, url, headers, payloadHash, region, accessKeyId, secretAccessKey });
    return new Promise((resolve, reject) => {
      const req = lib.request({
        protocol: url.protocol, hostname: url.hostname, port: url.port || undefined, method, agent,
        path: url.pathname + (search ? '?' + search : ''), headers: signed,
      }, resolve);
      req.setTimeout(timeoutMs, () => req.destroy(new Error(`S3 ${method} ${key || '/'}: no data for ${timeoutMs / 1000}s`)));
      req.on('error', reject);
      if (body == null) req.end();
      else if (Buffer.isBuffer(body) || typeof body === 'string') req.end(body);
      else {
        body.on('error', (e) => req.destroy(e));
        body.pipe(req);
      }
    });
  }

  async function failWith(res, what) {
    const text = await readAll(res).catch(() => '');
    throw new S3Error(res.statusCode, tag(text, 'Code'), `${what}: ${tag(text, 'Message') || text.slice(0, 200) || res.statusMessage}`);
  }

  return {
    bucket,
    request,
    /** Size in bytes, or null if there is no such object. */
    async head(key) {
      const res = await request('HEAD', key);
      res.resume();
      if (res.statusCode === 404) return null;
      if (res.statusCode !== 200) throw new S3Error(res.statusCode, null, `HEAD ${key}`);
      return Number(res.headers['content-length']);
    },
    /** The object as a stream; with { start, end } (inclusive) only those bytes. Rejects with S3Error 404 if missing. */
    async get(key, { start, end } = {}) {
      const ranged = start != null;
      const res = await request('GET', key, { headers: ranged ? { range: `bytes=${start}-${end ?? ''}` } : {} });
      const want = ranged && end != null ? end - start + 1 : null;
      const len = Number(res.headers['content-length']);
      // A service may answer a range covering the whole object with 200: fine, if it is exactly the bytes asked for.
      const okStatus = res.statusCode === (ranged ? 206 : 200) || (ranged && res.statusCode === 200 && start === 0 && want != null && len === want);
      if (!okStatus) await failWith(res, `GET ${key}`);
      if (want != null && len !== want) { res.destroy(); throw new S3Error(502, 'BadRange', `GET ${key}: asked for ${want} bytes, got ${len}`); }
      return res;
    },
    /**
     * Upload with a known SHA-256 (hex) and size. body: a Buffer, a Readable, or a function returning one, so a failed
     * attempt can be tried again (up to `tries` times) with a fresh stream.
     */
    async put(key, { body, size, sha256, contentType = 'application/octet-stream', tries = 3 }) {
      if (!HEX64.test(sha256)) throw new Error('put needs the hex sha256 of the body.');
      if (!Number.isSafeInteger(size) || size < 0) throw new Error('put needs the size of the body.');
      for (let attempt = 1; ; attempt++) {
        let b = null;
        try {
          b = typeof body === 'function' ? await body() : body;
          const res = await request('PUT', key, { body: b, payloadHash: sha256, headers: { 'content-length': size, 'content-type': contentType } });
          if (res.statusCode === 200 || res.statusCode === 201) { res.resume(); return; }
          await failWith(res, `PUT ${key}`);
        } catch (e) {
          if (b && typeof b.destroy === 'function') b.destroy(); // don't leave a source stream (file, or another bucket) open
          // A body that does not match its hash will not match next time either; nor will bad credentials.
          const final = e instanceof S3Error && e.status >= 400 && e.status < 500;
          if (final || attempt >= tries || typeof body !== 'function') throw e;
          await new Promise((r) => setTimeout(r, 500 * 2 ** attempt));
        }
      }
    },
    async del(key) {
      const res = await request('DELETE', key);
      if (res.statusCode === 204 || res.statusCode === 200 || res.statusCode === 404) { res.resume(); return; }
      await failWith(res, `DELETE ${key}`);
    },
    /** Every object under `prefix`, as { key, size }, page by page (ListObjectsV2). */
    async *list(prefix = '', { pageSize = 1000 } = {}) {
      let token = null;
      do {
        const res = await request('GET', '', { query: { 'list-type': 2, prefix, 'max-keys': pageSize, 'continuation-token': token } });
        if (res.statusCode !== 200) await failWith(res, `LIST ${prefix}`);
        const xml = await readAll(res, 64 << 20);
        for (const m of xml.matchAll(/<Contents>([\s\S]*?)<\/Contents>/g)) yield { key: tag(m[1], 'Key'), size: Number(tag(m[1], 'Size')) };
        token = tag(xml, 'IsTruncated') === 'true' ? tag(xml, 'NextContinuationToken') : null;
      } while (token);
    },
    close() { agent.destroy(); },
  };
}
