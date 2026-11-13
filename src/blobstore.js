// Where finished blobs live. Blobs are opaque ciphertext named by the SHA-256 of their bytes, so identical uploads are
// stored once and a stored blob never changes.
//
//   BLOB_STORE=fs (default)  DATA_DIR/blobs/aa/bb/<sha256> on the local disk
//   BLOB_STORE=s3            <S3_PREFIX><sha256> in an S3-compatible bucket (Hetzner Object Storage, Backblaze B2, ...)
//
// Every store has the same five calls:
//   head(hash)                      -> size in bytes, or null if absent
//   get(hash, { start, end }?)      -> Readable of the blob, or of bytes start..end (inclusive)
//   put(hash, { body, size })       -> store a stream (or a function returning one) of known hash and size
//   adopt(hash, path)               -> move a finished local file (already hashed) into the store; the file is gone after
//   del(hash)                       -> remove it (callers check that nobody else holds it first)
import { createReadStream, createWriteStream, mkdirSync } from 'node:fs';
import { rename, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { randomBytes } from 'node:crypto';
import { createS3Client, s3ConfigFromEnv } from './s3.js';

export class BlobMissing extends Error {}

export function fsStore(dataDir) {
  const root = join(dataDir, 'blobs');
  mkdirSync(root, { recursive: true });
  const path = (h) => join(root, h.slice(0, 2), h.slice(2, 4), h);
  const head = async (h) => { try { return (await stat(path(h))).size; } catch { return null; } };
  return {
    kind: 'fs',
    describe: () => `fs ${root}`,
    path,
    head,
    async get(h, { start, end } = {}) {
      if ((await head(h)) == null) throw new BlobMissing(h);
      return createReadStream(path(h), start != null ? { start, end } : {});
    },
    async put(h, { body }) {
      if ((await head(h)) != null) return;
      const dest = path(h), tmp = `${dest}.${randomBytes(6).toString('hex')}.part`;
      mkdirSync(join(dest, '..'), { recursive: true });
      try { await pipeline(typeof body === 'function' ? await body() : body, createWriteStream(tmp)); await rename(tmp, dest); }
      finally { await rm(tmp, { force: true }); }
    },
    async adopt(h, file) {
      const dest = path(h);
      mkdirSync(join(dest, '..'), { recursive: true });
      try { await stat(dest); await rm(file, { force: true }); } catch { await rename(file, dest); }
    },
    async del(h) { await rm(path(h), { force: true }); },
    close() {},
  };
}

export function s3Store(cfg) {
  const c = createS3Client(cfg);
  const key = (h) => cfg.prefix + h;
  const self = {
    kind: 's3',
    describe: () => `s3 ${new URL(cfg.endpoint).host}/${cfg.bucket}/${cfg.prefix}`,
    key,
    client: c,
    head: (h) => c.head(key(h)),
    async get(h, range) {
      try { return await c.get(key(h), range); } catch (e) { if (e.status === 404) throw new BlobMissing(h); throw e; }
    },
    async put(h, { body, size }) {
      if ((await self.head(h)) === size) return; // content-addressed: already there means already right
      await c.put(key(h), { body, size, sha256: h });
    },
    async adopt(h, file) {
      const { size } = await stat(file);
      await self.put(h, { body: () => createReadStream(file), size });
      await rm(file, { force: true });
    },
    del: (h) => c.del(key(h)),
    close: () => c.close(),
  };
  return self;
}

/** The store chosen by BLOB_STORE (fs or s3). Throws on a bad setting, so the server will not start half-configured. */
export function blobStoreFromEnv(env, dataDir) {
  const kind = env.BLOB_STORE || 'fs';
  if (kind === 'fs') return fsStore(dataDir);
  if (kind === 's3') return s3Store(s3ConfigFromEnv(env, 'S3'));
  throw new Error('BLOB_STORE must be fs or s3.');
}
