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
3. `POST /v1/auth/verify {identityKey, nonce, signature}` (same Origin) returns `{token, identityKey, expiresAt, scope}`.
4. Send `Authorization: Bearer <token>` on every authenticated call.

Tokens last 7 days and carry `aud` (the origin they were signed for: a request with a different `Origin` is refused),
`sid` (revoked by sign-out) and `gen` (bumped by sign-out-everywhere). Agents and CLIs send no `Origin`.
`SIGNUP=invite` (the production default) admits only `ALLOWED_KEYS`; `SIGNUP=open` admits any bWalletX.
A wallet that isn't admitted but is the recipient of a live link (v1.2) gets a **recipient session** instead
(`scope: 'recipient'`, 1 day, rate-limited): it can read links addressed to it and sign out, nothing else.

## Routes

| Method | Path | Auth | Body / headers | Returns |
|---|---|---|---|---|
| POST | `/v1/auth/challenge` | Origin | `{identityKey}` | challenge |
| POST | `/v1/auth/verify` | Origin | `{identityKey, nonce, signature}` | `{token, identityKey, expiresAt}` |
| POST | `/v1/auth/signout` | yes (also recipient) | | 204, this token stops working |
| POST | `/v1/auth/signout-all` | yes (also recipient) | | 204, every token for this wallet stops working |
| GET | `/v1/me` | yes | | `{identityKey, usage: {bytes, files, pending, quota, maxFile}}` |
| POST | `/v1/uploads` | yes | `{size}` sealed bytes | 201 `{id, size, offset: 0, chunkMax}` |
| GET/HEAD | `/v1/uploads/:id` | yes | | `{id, size, offset}` + `Upload-Offset` |
| PATCH | `/v1/uploads/:id` | yes | `Upload-Offset: n`, body = the next bytes (at most 32 MB) | 204 + `Upload-Offset` |
| POST | `/v1/uploads/:id/complete` | yes | `{sha256, meta}` | `{hash, size}`; 422 if the server's hash differs |
| DELETE | `/v1/uploads/:id` | yes | | 204 |
| PUT | `/v1/blobs/:sha256` | yes | body (at most 64 MB), optional `X-Bdx-Meta` | 201 `{hash, size}`; 422 on mismatch |
| GET/HEAD | `/v1/blobs/:sha256` | yes (owner) | `Range` ok | ciphertext |
| GET | `/v1/files` | yes | | `{files: [{hash, size, meta, keyWrap, createdAt, links: [{id, createdAt, expiresAt, revokedAt, downloads, reported, bound, recipient, recipientLabel, ready}]}], usage}` |
| PUT | `/v1/files/:sha256/key` | yes (owner) | `{keyWrap}` base64url, at most 1 KB; `null` clears | 204 |
| DELETE | `/v1/files/:sha256` | yes | | 204; its links go too, and the blob if nobody else holds it |
| POST | `/v1/links` | yes | `{hash, ttl?, recipient?, recipientLabel?, recipientWrap?, senderKey?}` ttl in seconds, default and max 30 days | 201 `{id, createdAt, expiresAt, bound}` |
| PUT | `/v1/links/:id/recipient` | yes (owner) | `{recipient, recipientWrap, recipientLabel?}` | 204; 409 if the link is already for someone else |
| DELETE | `/v1/links/:id` | yes | | 204, switched off |
| GET | `/v1/s/:id` | public | optional session | `{id, size, meta, createdAt, expiresAt}`; bound links: see below; 404 off or reported, 410 expired |
| GET/HEAD | `/v1/s/:id/blob` | public; bound: recipient only | `Range` ok | ciphertext; bound links 403 to anyone but the recipient |
| POST | `/v1/s/:id/report` | public; bound: recipient only | `{reason}` | 204, the link is switched off at once |
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

## Links sent to one person (v1.2)

A link can be bound to one wallet. Its URL has no `#k`: the file key travels wrapped for the recipient instead.

- `recipient`: the recipient's identity key (66 hex, `02`/`03`). The site finds it with paymail `pki` in the browser
  (pay.bwallet.space for `@bwalletx.com`, the paymail's own `.well-known/bsvalias` otherwise), never through this server.
- `recipientWrap` = base64url of the **sender's** `wallet.encrypt({ plaintext: key, protocolID: [2, 'bdrivex share'], keyID: '<file sha256>.<link id>', counterparty: <recipient identity key> })`.
  The recipient opens it with `wallet.decrypt({ ciphertext, protocolID: [2, 'bdrivex share'], keyID, counterparty: <sender identity key> })`
  and checks it is 32 bytes. Security level 2: the derivation is bound to the counterparty.
- Since the key ID needs the link id: `POST /v1/links {hash, ttl, recipient}` first, then `PUT /v1/links/:id/recipient {recipient, recipientWrap}`.
  Until the wrap is in place the recipient gets 409. A link's recipient is set once and can't be changed.
- `recipientLabel` (the `$handle` or paymail the sender typed) is shown only to the sender, in `GET /v1/files`.
- The sender is always the link's owner (`senderKey`, if sent, must be the owner's own key).
- `GET /v1/s/:id` for anyone but the recipient: `{id, bound: true, forYou: false, to: null, from: <sender key>, size, createdAt, expiresAt}`:
  no meta, no wrap, no hash, nothing about the recipient. Signed in as the recipient it adds `{forYou: true, hash, meta, senderKey, recipientWrap}`.
- The blob and the report route need the recipient's session (identity keys compared in constant time); the owner
  keeps owner access through `/v1/blobs/:sha256` only. Revoking or expiring the link ends the recipient's access, and
  a recipient who isn't invited can then no longer sign in.
- `makeLink`, `openBoundLink`, `wrapForRecipient` and `unwrapFromSender` in `bdrivex-site/js/bdx-client.js` do this.

## Licence

Open BSV License version 4. See `LICENSE`.
