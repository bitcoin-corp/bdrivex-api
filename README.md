# bdrivex-api

Storage API behind bdrivex.com. It holds **opaque ciphertext only**: files are sealed in the browser and the key travels
in the share link's `#fragment`, which browsers never send to a server.

```sh
pnpm install
pnpm dev                          # http://127.0.0.1:8787, data in ./data, dev origins 127.0.0.1:5173, sign-up open
                                  # (sharing is invite-only unless .env.local has SHARING=open or your key in ALLOWED_KEYS)
pnpm test [file]                  # end to end with the site's client code (sign in, upload, resume, link, download)
pnpm test:s3                      # S3 store, SigV4, migration, B2 mirror, orphans against a fake S3, then the e2e on it
node scripts/dev-session.mjs      # a throwaway-key session for testing /send without a wallet
```

Node 22.13+ (`node:sqlite`), no native dependencies. Metadata in `DATA_DIR/bdrivex.db`, blobs in
`DATA_DIR/blobs/aa/bb/<sha256>` or an S3-compatible bucket (see Blob stores). Settings: `.env.example`.
The tests need the site's client code: set `SITE_DIR=/path/to/bdrivex-site` if it isn't at `../bdrivex-site`.

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

Sharing has its own switch, so sign-up can open for private storage first. `SHARING=invited` (the default, in every
environment) lets only `ALLOWED_KEYS` make or bind links (`POST /v1/links`, `PUT /v1/links/:id/recipient`), even with
`SIGNUP=open`; anyone else gets 403 `{error: "sharing_invite_only", message: "Sharing links are invite-only for now.
Your storage works as normal."}`. `SHARING=open` lets any signed-in wallet make links. Links that already exist keep
opening, and their owner can still switch them off, whichever way it is set.

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
| POST | `/v1/links` | yes (sharing) | `{hash, ttl?, recipient?, recipientLabel?, recipientWrap?, senderKey?}` ttl in seconds, default and max 30 days | 201 `{id, createdAt, expiresAt, bound}` |
| PUT | `/v1/links/:id/recipient` | yes (owner, sharing) | `{recipient, recipientWrap, recipientLabel?}` | 204; 409 if the link is already for someone else |
| DELETE | `/v1/links/:id` | yes | | 204, switched off |
| GET | `/v1/s/:id` | public | optional session | `{id, size, meta, createdAt, expiresAt}`; bound links: see below; 404 off or reported, 410 expired |
| GET/HEAD | `/v1/s/:id/blob` | public; bound: recipient only | `Range` ok | ciphertext; bound links 403 to anyone but the recipient |
| POST | `/v1/s/:id/report` | public; bound: recipient only | `{reason}` | 204, the link is switched off at once |
| GET | `/health` | public | | `{ok: true}` |

Errors are `{error: "<sentence for a person>"}` with the HTTP status. 429 carries `Retry-After`. A refusal a client
should tell apart comes as `{error: "<code>", message: "<sentence>"}`: so far only `sharing_invite_only` (403).

## Limits (defaults, all set by env)

1 GB stored per wallet (`QUOTA_BYTES`, more for named wallets via `QUOTA_OVERRIDES`), 2 GB per file, links up to 30
days, 10 GB uploaded per wallet per day, 50 GB of link downloads per sender per day, and request limits per IP and per
wallet on sign-in, uploads, link creation, downloads and reports.

## Blob stores

Blobs are opaque ciphertext named by the SHA-256 of their bytes, so identical uploads are stored once and a stored
blob never changes. A file row points at a hash; a blob is deleted only when no file row holds it any more.

- `BLOB_STORE=fs` (the default): `DATA_DIR/blobs/aa/bb/<sha256>` on the server's disk.
- `BLOB_STORE=s3`: `<S3_PREFIX><sha256>` in any S3-compatible bucket (Hetzner Object Storage is the target; Backblaze
  B2, MinIO and AWS work the same). Path-style URLs, AWS SigV4 signed with `node:crypto`, no extra dependencies.
  `S3_ENDPOINT` (e.g. `https://fsn1.your-objectstorage.com`, no bucket in it), `S3_REGION` (`fsn1`), `S3_BUCKET`,
  `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, optional `S3_PREFIX` (e.g. `blobs/`). The server won't start with
  any of these missing.

Uploads are staged in `DATA_DIR/tmp` either way (32 MB PATCH chunks; the server re-hashes on `/complete`). With s3,
`/complete` then uploads the finished blob in one streamed PUT (files are at most 2 GB; S3's single-PUT limit is
5 GB) signed with its SHA-256, so the bucket itself refuses bytes that don't match, and removes the staged file. If the
bucket doesn't answer, `/complete` returns 503 with `Retry-After` and keeps the upload, so it can be finished again.
`GET /v1/blobs/:sha256` and `/v1/s/:id/blob` check the size with HEAD and pass `Range` through to the bucket: the
same 200/206/416 and `Content-Range` as the fs store. Mind the disk: a 2 GB upload still needs 2 GB in `tmp`.

**Run the API as one process: pm2 fork mode (`exec_mode: 'fork'`, `instances: 1`), never cluster mode.** Storing a
blob and recording its file row, and deleting a row and then the blob if nobody else holds it, are serialised per hash
by an in-process lock. Two processes would not see each other's lock, and a delete in one could remove a blob that an
upload in the other has just found already stored. (The rate limits and the upload `busy` set are per process too.)

**The deletion log.** When a user's delete removes the last file row for a blob, the server writes
`erased_blobs(hash, erased_at, reason, b2_pruned_at)` in the same step as the store delete, whether that delete
succeeds or is left to the retry. Uploading the same bytes again removes the row, so a blob that is live again is never
pruned from the backup. This log is the only thing the B2 mirror deletes by (see below).

**Failed deletes.** When the last file row for a blob goes, the user's delete succeeds even if the bucket refuses the
blob delete. The blob is recorded in the `blob_deletes` table and the server tries again every 10 minutes
(`BLOB_DELETE_RETRY_MS`), first checking that nobody holds the blob again.

**Orphans.** `scripts/orphan-blobs.mjs` compares the bucket with the database. With `--delete` it is **the only path
that deletes from the primary without a user's action**, a deliberate operator tool. It never touches B2 and writes
no deletion-log rows, so whatever it removes stays in the B2 backup. The mirror reports those copies as "unreferenced"
and never prunes them. (An orphan left by a user's failed delete already has its log row, so once it is gone from the
primary, the mirror prunes it like any other user delete.)

```sh
node --env-file=/srv/bdrivex/.env scripts/orphan-blobs.mjs            # report: orphans, rows with no blob, failed deletes
node --env-file=/srv/bdrivex/.env scripts/orphan-blobs.mjs --delete   # delete the orphans it reports
```

Reporting is the default; it deletes only with `--delete`. Blobs younger than `--min-age-hours` (24) are never
orphans, since an upload stores its blob just before its row. Only `<S3_PREFIX><sha256>` keys are touched. `--delete`
refuses if the database has no file rows but the bucket has blobs (a wrong `DATA_DIR`), or if it would delete more than
10% of the bucket's blobs and more than 25 objects, unless `--force`. It checks each orphan's rows again just before
deleting it, but it shares no lock with the server, so run `--delete` while the API is quiet.

**Moving an existing server to s3** (`scripts/migrate-blobs-to-s3.mjs`; it copies, checks, and deletes nothing):

```sh
cd /srv/bdrivex/api
node --env-file=/srv/bdrivex/.env scripts/migrate-blobs-to-s3.mjs --dry-run   # what it would upload
node --env-file=/srv/bdrivex/.env scripts/migrate-blobs-to-s3.mjs             # copy; each copy HEAD-sized and re-hashed
# set BLOB_STORE=s3 in the env, restart the API, then run the migration once more for blobs that came in meanwhile
# keep DATA_DIR/blobs until downloads have been checked; remove it by hand later
```

It skips blobs already in the bucket at the right size (`--verify-existing` re-hashes those too), refuses a local
file whose bytes don't match its name, reports file rows that have no blob anywhere, and exits 1 if any blob failed.

**Second copy in Backblaze B2** (`scripts/mirror-to-b2.mjs`): lists the primary bucket and copies every object B2
doesn't have, streaming bucket to bucket, signed with the blob's SHA-256. Content-addressed, so a key B2 already has at
the same size is the same blob; a size mismatch is reported and left alone. Env: the `S3_*` above plus `B2_ENDPOINT`
(e.g. `https://s3.eu-central-003.backblazeb2.com`), `B2_REGION` (`eu-central-003`), `B2_BUCKET`, `B2_ACCESS_KEY_ID`,
`B2_SECRET_ACCESS_KEY`, optional `B2_PREFIX` (defaults to `S3_PREFIX`).

With `--prune` it also deletes from B2 the blobs users deliberately deleted, and nothing else. A blob is pruned
only if it is in the deletion log, not yet pruned, gone from the primary, and held by no file row (checked again just
before each delete). It is then marked `b2_pruned_at`, so each erasure is pruned once and can be audited, and the
key, erasure time and reason are logged. **It never deletes a blob just because the primary lacks it.** A loss on the
primary side (a bad migration, a bucket mishap) leaves the backup alone. It needs the API database
(`DATA_DIR/bdrivex.db`), which it opens read-only except to write `b2_pruned_at`. It refuses, deleting nothing, if:

- either listing failed or came back cut short (truncated with no continuation token);
- the primary listing is empty while the database has file rows (a wrong bucket, prefix or key);
- it would delete more than 10% of B2's blobs and more than 25 objects (`--max-delete-share`, `--max-delete-floor`),
  unless `--force`;
- the database is missing, or predates the deletion log (exit 2).

A refused prune exits 1. A blob erased while the primary still has it (its delete is being retried) waits for a
later run. `--dry-run` copies and deletes nothing and prints what it would do. One summary line, plus a line per key
deleted; exit 1 on any failure.

The nightly timer runs with `--prune`: erasure requests and the privacy policy need deletions to reach the backup, and
a prune someone has to remember to run won't happen. Since it deletes only what the deletion log names, a primary-side
mistake can't spread to the backup.

**Lost blobs and restoring them.** Every run also counts B2 blobs the primary lacks: *lost* (a file row still needs
it), *erased* (in the deletion log, not pruned yet) or *unreferenced* (no row and no log entry, e.g. removed with
`orphan-blobs --delete`). A lost blob makes the nightly run exit 1, so it shows as a failed run.

```sh
node --env-file=/srv/bdrivex/.env scripts/mirror-to-b2.mjs --restorable         # list them; copies and deletes nothing
node --env-file=/srv/bdrivex/.env scripts/mirror-to-b2.mjs --restore --dry-run  # what it would copy back
node --env-file=/srv/bdrivex/.env scripts/mirror-to-b2.mjs --restore            # copy the lost ones back from B2
```

`--restore` copies only *lost* blobs back to the primary, signed with their SHA-256 (so a damaged B2 copy is
refused), and never erased ones. Unreferenced blobs aren't needed by any file; if one must come back, copy it by hand
from `B2_BUCKET/<B2_PREFIX><sha256>` to `S3_BUCKET/<S3_PREFIX><sha256>`.

**B2 keeps old versions by default.** A delete through the S3 API only hides the file. For deletions to be real,
set the bucket's lifecycle to "Keep only the last version of the file" (or a rule with `daysFromHidingToDeleting: 1`).
Hetzner Object Storage has versioning off unless you turn it on.

Nightly, as a systemd timer (an example: nothing installs it):

```ini
# /etc/systemd/system/bdrivex-mirror.service
[Unit]
Description=bDriveX: copy new blobs to Backblaze B2 and prune user-deleted ones (deletion log)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=bdrivex
WorkingDirectory=/srv/bdrivex/api
ExecStart=/usr/bin/node --env-file=/srv/bdrivex/.env scripts/mirror-to-b2.mjs --prune

# /etc/systemd/system/bdrivex-mirror.timer
[Unit]
Description=bDriveX B2 mirror, nightly

[Timer]
OnCalendar=*-*-* 03:15:00
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
```

`systemctl enable --now bdrivex-mirror.timer`; results in `journalctl -u bdrivex-mirror`; a failed run shows in
`systemctl --failed` (a refused prune or a lost blob counts as failed, so someone looks). The env file must set
`DATA_DIR`, and the service user must be able to write the database (for `b2_pruned_at`), so run it as the API's user. Before enabling it, run it once by hand
with `--prune --dry-run` and read what it would delete. Or with cron:

```cron
15 3 * * * cd /srv/bdrivex/api && /usr/bin/node --env-file=/srv/bdrivex/.env scripts/mirror-to-b2.mjs --prune >> /var/log/bdrivex-mirror.log 2>&1
```

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
