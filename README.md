# bdrivex-api

Storage API behind bdrivex.com. It holds **opaque ciphertext only**: files are sealed in the browser and the key travels
in the share link's `#fragment`, which browsers never send to a server.

```sh
pnpm install
pnpm dev                          # http://127.0.0.1:8787, data in ./data, dev origins 127.0.0.1:5173, sign-up open
pnpm test [file]                  # end to end with the site's client code (sign in, upload, resume, link, download)
node scripts/dev-session.mjs      # a throwaway-key session for testing /send without a wallet
```

Node 22.13+ (`node:sqlite`), no native dependencies. Metadata in `DATA_DIR/bdrivex.db`, blobs in
`DATA_DIR/blobs/aa/bb/<sha256>`. Settings: `.env.example`.

## Auth

1. `POST /v1/auth/challenge {identityKey}` with an `Origin` on `ALLOWED_ORIGINS` returns `{nonce, message, protocolID, keyID, expiresAt}`.
2. The wallet signs `message`: `createSignature({protocolID, keyID, counterparty: 'anyone', data: utf8(message)})`.
   In a browser, `signInWithBwalletX` from `@bwalletx/connect` does steps 1 and 2.
3. `POST /v1/auth/verify {identityKey, nonce, signature}` (same Origin) returns `{token, identityKey, expiresAt}`.
4. Send `Authorization: Bearer <token>` on every authenticated call.

Tokens last 7 days and carry `aud` (the origin they were signed for: a request with a different `Origin` is refused),
`sid` (revoked by sign-out) and `gen` (bumped by sign-out-everywhere). Agents and CLIs send no `Origin`.
`SIGNUP=invite` (the production default) admits only `ALLOWED_KEYS`; `SIGNUP=open` admits any bWalletX.

## Routes

| Method | Path | Auth | Body / headers | Returns |
|---|---|---|---|---|
| POST | `/v1/auth/challenge` | Origin | `{identityKey}` | challenge |
| POST | `/v1/auth/verify` | Origin | `{identityKey, nonce, signature}` | `{token, identityKey, expiresAt}` |
| POST | `/v1/auth/signout` | yes | | 204, this token stops working |
| POST | `/v1/auth/signout-all` | yes | | 204, every token for this wallet stops working |
| GET | `/v1/me` | yes | | `{identityKey, usage: {bytes, files, pending, quota, maxFile}}` |
| POST | `/v1/uploads` | yes | `{size}` sealed bytes | 201 `{id, size, offset: 0, chunkMax}` |
| GET/HEAD | `/v1/uploads/:id` | yes | | `{id, size, offset}` + `Upload-Offset` |
| PATCH | `/v1/uploads/:id` | yes | `Upload-Offset: n`, body = the next bytes (at most 32 MB) | 204 + `Upload-Offset` |
| POST | `/v1/uploads/:id/complete` | yes | `{sha256, meta}` | `{hash, size}`; 422 if the server's hash differs |
| DELETE | `/v1/uploads/:id` | yes | | 204 |
| PUT | `/v1/blobs/:sha256` | yes | body (at most 64 MB), optional `X-Bdx-Meta` | 201 `{hash, size}`; 422 on mismatch |
| GET/HEAD | `/v1/blobs/:sha256` | yes (owner) | `Range` ok | ciphertext |
| GET | `/v1/files` | yes | | `{files: [{hash, size, meta, keyWrap, createdAt, links: [{id, createdAt, expiresAt, revokedAt, downloads, reported}]}], usage}` |
| PUT | `/v1/files/:sha256/key` | yes (owner) | `{keyWrap}` base64url, at most 1 KB; `null` clears | 204 |
| DELETE | `/v1/files/:sha256` | yes | | 204; its links go too, and the blob if nobody else holds it |
| POST | `/v1/links` | yes | `{hash, ttl?}` seconds, default and max 30 days | 201 `{id, createdAt, expiresAt}` |
| DELETE | `/v1/links/:id` | yes | | 204, switched off |
| GET | `/v1/s/:id` | public | | `{id, size, meta, createdAt, expiresAt}`; 404 off or reported, 410 expired |
| GET/HEAD | `/v1/s/:id/blob` | public | `Range` ok | ciphertext |
| POST | `/v1/s/:id/report` | public | `{reason}` | 204, the link is switched off at once |
| GET | `/health` | public | | `{ok: true}` |

Errors are `{error: "<sentence for a person>"}` with the HTTP status. 429 carries `Retry-After`.

## Limits (defaults, all set by env)

1 GB stored per wallet (`QUOTA_BYTES`, more for named wallets via `QUOTA_OVERRIDES`), 2 GB per file, links up to 30
days, 10 GB uploaded per wallet per day, 50 GB of link downloads per sender per day, and request limits per IP and per
wallet on sign-in, uploads, link creation, downloads and reports.

## BDX1 sealed format (for other clients)

Defined in `bdrivex-site/js/bdx-crypto.js`, with the client in `js/bdx-client.js`.

- 16-byte header: `BDX1` | version 1 | log2(segment size) = 20 | 3 zero bytes | 7-byte random prefix.
- Plaintext is cut into 1 MiB segments. The last segment may be short or empty, so an empty file has one segment.
- Each segment is sealed with AES-256-GCM. IV = prefix | u32 big-endian segment index | 1 for the last segment, else 0. AAD = the header.
- `meta` = base64url(header | AES-GCM of `{name, type, size}` JSON, padded to 256 bytes), with IV = prefix | ffffffff | 2.
- One random 256-bit key per file. The share link is `https://bdrivex.com/s/<linkId>#k=<base64url key>`.

## Wallet-wrapped file keys (v1.1)

So the owner can open their files from any device, the site asks the owner's wallet to wrap each file key to itself
and stores the wrap with `PUT /v1/files/:sha256/key`. It comes back only to the owner, in `GET /v1/files`, and never
appears on a share link.

- `keyWrap` = base64url of `wallet.encrypt({ plaintext: key (32 bytes), protocolID: [1, 'bdrivex file key'], keyID: <file sha256>, counterparty: 'self' })` (BRC-2).
- Open it with `wallet.decrypt` and the same arguments. Security level 1, so a wallet asks once per site, not once per file.
- `wrapKey`, `unwrapKey` and `saveKeyWrap` in `bdrivex-site/js/bdx-client.js` do this with any BRC-100 wallet.
- Like everything else here, the wrap is opaque to the server: only the owner's wallet can open it.

## Licence

Open BSV License version 4. See `LICENSE`.
