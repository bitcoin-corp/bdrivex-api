# bdrivex-api

Storage API behind bdrivex.com and bstorex.com (`files.bdrivex.com`). It holds **opaque ciphertext only**: files are sealed in the browser and the key travels
in the share link's `#fragment`, which browsers never send to a server.

```sh
pnpm install
pnpm dev                          # http://127.0.0.1:8787, data in ./data, dev origins 127.0.0.1:5173, sign-up open
                                  # (sharing is invite-only unless .env.local has SHARING=open or your key in ALLOWED_KEYS)
pnpm test [file]                  # end to end with the site's client code (sign in, upload, resume, link, download)
pnpm test:s3                      # S3 store, SigV4, migration, B2 mirror, orphans against a fake S3, then the e2e on it
pnpm test:mail                    # report emails against a fake SMTP server (needs openssl for its certificate)
node scripts/dev-session.mjs      # a throwaway-key session for testing /send without a wallet
scripts/deploy-s3.sh              # from your Mac: move the live server onto Hetzner Object Storage (see Going live)
```

Paths on the server: this README writes `<app dir>` (the checkout pm2 runs) and `<env file>` (the file the API's
`node --env-file` loads). Nothing here guesses them: `scripts/deploy-s3.sh` finds the real ones from pm2 and prints
them, and so does `scripts/deploy-s3.sh --check-logs`.

Node 22.13+ (`node:sqlite`), no native dependencies. Metadata in `DATA_DIR/bdrivex.db`, blobs in
`DATA_DIR/blobs/aa/bb/<sha256>` or an S3-compatible bucket (see Blob stores). Settings: `.env.example`.
The tests need the site's client code: set `SITE_DIR=/path/to/bdrivex-site` if it isn't at `../bdrivex-site`.

## Auth

1. `POST /v1/auth/challenge {identityKey}` with an `Origin` on `ALLOWED_ORIGINS` (production default:
   `https://bdrivex.com`, `https://www.bdrivex.com`, `https://bstorex.com`, `https://www.bstorex.com`) returns `{nonce, message, protocolID, keyID, expiresAt}`.
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
| GET | `/v1/files` | yes | | `{files: [{hash, size, meta, keyWrap, createdAt, held, links: [{id, createdAt, expiresAt, revokedAt, downloads, reported, bound, recipient, recipientLabel, ready, scrubbedAt}]}], usage}` |
| PUT | `/v1/files/:sha256/key` | yes (owner) | `{keyWrap}` base64url, at most 1 KB; `null` clears | 204 |
| DELETE | `/v1/files/:sha256` | yes | | 204; its links go too, and the blob if nobody else holds it; 423 `legal_hold` if the file is on hold |
| POST | `/v1/links` | yes (sharing) | `{hash, ttl?, recipient?, recipientLabel?, recipientWrap?, senderKey?}` ttl in seconds, default and max 30 days | 201 `{id, createdAt, expiresAt, bound}` |
| PUT | `/v1/links/:id/recipient` | yes (owner, sharing) | `{recipient, recipientWrap, recipientLabel?}` | 204; 409 if the link is already for someone else |
| DELETE | `/v1/links/:id` | yes | | 204, switched off |
| GET | `/v1/s/:id` | public | optional session | `{id, size, meta, createdAt, expiresAt}`; bound links: see below; 404 off or reported, 410 expired |
| GET/HEAD | `/v1/s/:id/blob` | public; bound: recipient only | `Range` ok | ciphertext; bound links 403 to anyone but the recipient |
| POST | `/v1/s/:id/report` | public; bound: recipient only | `{reason}` | 204, the link is switched off at once and the file is put on legal hold |
| GET | `/health` | public | | `{ok: true}` |

## Errors

Errors are `{error: "<sentence for a person>"}` with the HTTP status. A refusal a client should tell apart also carries
a machine-readable `code`: `{error: "<sentence>", code: "<code>", message: "<sentence>"}`. **Read `code`, show
`message`.** The one exception is `sharing_invite_only`, which came first as `{error: "<code>", message}` and keeps
`error` = the code (the site checks it); it has `code` too. 429 and 503 carry `Retry-After`, and `Retry-After` is in
`Access-Control-Expose-Headers` so a browser page can read it.

| Status | `code` | When |
|---|---|---|
| 401 | `signin_required` | no session, or a stale / signed-out one |
| 401 | `account_closed` | a token issued before the account was closed (scripts/close-account.mjs) |
| 401 | `wrong_site` | a token signed for one site sent from another `Origin` |
| 401 | `bad_signature` | `/v1/auth/verify` did not accept the signature |
| 403 | `origin_not_allowed` | sign-in from an `Origin` not on `ALLOWED_ORIGINS` |
| 403 | `not_invited` | `SIGNUP=invite` and the wallet is not on `ALLOWED_KEYS` (sign-in, or any authenticated route) |
| 403 | `sharing_invite_only` | `SHARING=invited` and the wallet may not make or bind links |
| 403 | `recipient_only` | a recipient session tried something other than opening what was sent to it |
| 403 | `not_recipient` | a link sent to one person, asked for by someone else |
| 404 | `link_off` / `link_reported` | the link was switched off (or never existed) / switched off after a report |
| 410 | `link_expired` | the link's time is up |
| 409 | `not_ready` | a link for one person whose wrap the sender hasn't put in place yet |
| 413 | `quota_exceeded` / `file_too_large` | over the storage allowance / over the per-file limit |
| 423 | `legal_hold` | deleting a file that is on legal hold |
| 429 | `rate_limited` | too many requests, or a daily byte allowance used up; `Retry-After` says when to try again |
| 503 | `storage_unavailable` | the blob store did not answer; `Retry-After` |
| 500 | `server_error` | a bug on our side |

Other refusals (bad input, 404 for a missing file or upload) are `{error}` only.

## Reports, legal hold and retention

Owner decisions, Nov 2026: report records are kept 3 years; support email is kept 3 years (outside this API).

- **A report switches the link off at once and puts the file on legal hold.** Anyone holding an anyone-link can report
  it; a link sent to one person can be reported only by that person. The owner sees `held: true` on the file, and
  `DELETE /v1/files/:sha256` answers 423 `{code: "legal_hold"}` with the file and its blob left in place, until an
  admin releases the hold. `scripts/close-account.mjs` won't remove a held file either. (So a holder of an anyone-link
  can stop its owner deleting that file until we look; that is the point of a hold.)
- **Holds are managed by hand**, on the server: `node --env-file=<env file> scripts/legal-hold.mjs list` (active holds,
  recent releases, reports), `... release <identityKey> <sha256> --note "why" --yes` (the owner can delete it again;
  nothing is deleted), `... place <identityKey> <sha256> --note "why" --yes` (a hold without a report, e.g. a request
  from the police). Without `--yes`, release and place only say what they would do.
- **Report records** (`reports`: link id, time, reason, reporter IP, owner, file hash) keep the owner and hash, so they
  outlive the link and the file. The server deletes them 3 years after the report (`REPORT_KEEP_DAYS`, 1096). The
  reporter IP is replaced after 30 days (`REPORT_IP_HASH_DAYS`) by `h:` + an HMAC-SHA256 of it keyed with
  `SESSION_SECRET`, so repeat reports from one address can still be matched but the address is gone. (Rotating
  `SESSION_SECRET` makes old and new hashes unmatchable; nothing else breaks.) Released holds go 3 years after release;
  an active hold is never aged out. Reports made before these columns existed are filled in from their links on the
  first start of this version, and their files are held.
- **Links sent to one person** lose `recipient`, `recipient_wrap` and `recipient_label` 7 days (`LINK_SCRUB_DAYS`) after
  they were revoked or expired, as the terms promise. `recipient_scrubbed_at` records when, so the owner's list still
  shows the link was for one person (`bound: true, recipient: null, scrubbedAt`). Not while the file is on legal hold
  (the report is about what was sent to whom); the first run after the hold is released scrubs it.
- These run inside the API process every hour (`HOUSEKEEPING_MS`), and a minute after start, like the failed-delete
  retry, and log one `[bdrivex] retention:` line when they changed something.
- **Notification.** Every report writes one line to the pm2 log,
  `[bdrivex] REPORT link <id> switched off, file held (owner …, file …, <time>). For support@bwalletx.com: …`, and
  emails support@bwalletx.com (owner, Nov 2026: one mailbox, on Fasthosts; no separate reports address).

## Report emails

`src/mail.js` is a small SMTP client (`node:net`/`node:tls`, no dependency) and an in-process queue.

- **What is sent.** Subject `Report: link <link id> (file <first 12 hex of the hash>)` (the mailbox's REPORTS filter
  keys on `Report:`). Body, and nothing else: `Link: <id>`, `File: <12 hex>`, `Reason: <the reporter's reason, one
  line, control characters blanked, 500 characters at most>`, `Time: <UTC ISO>`. Never file content, names or meta,
  the full hash, the reporter's IP, an identity key or any file key. The body goes base64-encoded (UTF-8), so a reason
  can't add headers.
- **Never in the way.** The report answers 204 straight away; the email is queued in memory and sent in the
  background, retried with backoff (1 min doubling, up to an hour, 8 tries), then dropped with a log line. A restart
  drops unsent emails; the REPORT log line and `scripts/legal-hold.mjs list` still have every report.
- **Capped.** At most `REPORT_MAIL_PER_HOUR` (30) emails an hour. Reports past that are counted, and when the hour
  ends one summary goes out: `Report: <n> more reports not mailed one by one`, with counts and first/last times only.
- **Settings** (in the env file; `scripts/deploy-s3.sh` asks for them, with the password typed hidden on the server,
  and you can skip): `SMTP_HOST`, `SMTP_PORT` (465 = TLS from the start; anything else = STARTTLS, which is required:
  the password is never sent unencrypted; `SMTP_SECURE=1` for TLS on another port), `SMTP_USER`, `SMTP_PASS`,
  `SMTP_FROM` (default `SMTP_USER`), `REPORT_MAIL_TO` (default support@bwalletx.com). The server certificate is
  checked against the system CAs. No `SMTP_HOST`: mail is off and reports are only logged. A half-done setting (host
  without user or password, a bad address) is logged at start and mail stays off; the API still starts. The start line
  says `report mail to … via host:port` or `report mail off`.
- **Check it:** `cd <app dir> && node --env-file=<env file> scripts/report-mail-test.mjs` sends one
  `Report: test from bdrivex-api` email (exit 0 sent, 1 failed, 2 not configured). The deploy script offers to run it.

## Closing an account

The user emails support@bwalletx.com with their identity key; we confirm it is theirs; then, on the server:

```sh
cd <app dir>
node --env-file=<env file> scripts/close-account.mjs <identityKey>         # dry run: what it would delete and keep
node --env-file=<env file> scripts/close-account.mjs <identityKey> --yes   # do it
```

It deletes the account's files and every blob nobody else holds (through the blob store, fs or s3, each written to the
deletion log so the nightly `mirror-to-b2.mjs --prune` removes the B2 copy too), its share links, unfinished uploads
(rows and staged bytes), the key wraps (they live on the file rows), sign-in nonces and the sign-out counter
(`generations`). It writes sha256 of the key (not the key) to `closed_accounts` for 8 days, so every token issued
before the close stops working (401 `account_closed`); after that every such token has expired and the row goes. There
is no account table: those rows are the account. The wallet can sign up again later and starts empty.

It keeps report records about the account's files (3 years) and links other people sent *to* that wallet (they belong
to their senders and are scrubbed 7 days after they end). If any file is on legal hold, `--yes` refuses and deletes
nothing; release the hold first, or add `--keep-held` to close everything else and keep the held files as they are.
A blob delete the store refuses is queued in `blob_deletes` for the running server's retry. Prints a summary; exit 0
done or dry run, 1 refused or failed, 2 bad arguments.

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
node --env-file=<env file> scripts/orphan-blobs.mjs            # report: orphans, rows with no blob, failed deletes
node --env-file=<env file> scripts/orphan-blobs.mjs --delete   # delete the orphans it reports
```

Reporting is the default; it deletes only with `--delete`. Blobs younger than `--min-age-hours` (24) are never
orphans, since an upload stores its blob just before its row. Only `<S3_PREFIX><sha256>` keys are touched. `--delete`
refuses if the database has no file rows but the bucket has blobs (a wrong `DATA_DIR`), or if it would delete more than
10% of the bucket's blobs and more than 25 objects, unless `--force`. It checks each orphan's rows again just before
deleting it, but it shares no lock with the server, so run `--delete` while the API is quiet.

**Moving an existing server to s3** (`scripts/migrate-blobs-to-s3.mjs`; it copies, checks, and deletes nothing).
`scripts/deploy-s3.sh` does all of this for the live server (see Going live); by hand it is:

```sh
cd <app dir>
node --env-file=<env file> scripts/migrate-blobs-to-s3.mjs --dry-run   # what it would upload
node --env-file=<env file> scripts/migrate-blobs-to-s3.mjs             # copy; each copy HEAD-sized and re-hashed
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
node --env-file=<env file> scripts/mirror-to-b2.mjs --restorable         # list them; copies and deletes nothing
node --env-file=<env file> scripts/mirror-to-b2.mjs --restore --dry-run  # what it would copy back
node --env-file=<env file> scripts/mirror-to-b2.mjs --restore            # copy the lost ones back from B2
```

`--restore` copies only *lost* blobs back to the primary, signed with their SHA-256 (so a damaged B2 copy is
refused), and never erased ones. Unreferenced blobs aren't needed by any file; if one must come back, copy it by hand
from `B2_BUCKET/<B2_PREFIX><sha256>` to `S3_BUCKET/<S3_PREFIX><sha256>`.

**B2 keeps old versions by default.** A delete through the S3 API only hides the file. For deletions to be real,
set the bucket's lifecycle to "Keep only the last version of the file" (or a rule with `daysFromHidingToDeleting: 1`).
Hetzner Object Storage has versioning off unless you turn it on.

Nightly, as a systemd timer (an example: nothing installs it; put the real `<app dir>` and `<env file>` in, which
`scripts/deploy-s3.sh` prints):

```ini
# /etc/systemd/system/bdrivex-mirror.service
[Unit]
Description=bDriveX: copy new blobs to Backblaze B2 and prune user-deleted ones (deletion log)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=bdrivex
WorkingDirectory=<app dir>
ExecStart=/usr/bin/node --env-file=<env file> scripts/mirror-to-b2.mjs --prune

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
15 3 * * * cd <app dir> && /usr/bin/node --env-file=<env file> scripts/mirror-to-b2.mjs --prune >> /var/log/bdrivex-mirror.log 2>&1
```

## Going live on Hetzner Object Storage

The bucket is `bcorp-bdrivex-files` at `https://fsn1.your-objectstorage.com` (region `fsn1`), private; the keys are in
the owner's password manager. From the Mac, in this repo, with everything committed:

```sh
scripts/deploy-s3.sh                # the whole switch, with a typed "yes" before anything live changes
scripts/deploy-s3.sh --check-logs   # read-only: access logs nginx/caddy/pm2 keep for files.bdrivex.com (privacy page)
```

It finds the one pm2 app whose cwd contains `bdrivex-api` on `ssh hetzner` (it stops if there are none or several),
works out the env file pm2 loads (`--env-file` in node_args, or the package.json script pm2 runs; read-only), and
stops if it can't tell, if pm2's own env sets `BLOB_STORE`/`S3_*` (that would override the file), if the app isn't
fork mode × 1, or if node is older than 22.13. Then it backs up the env file (`<env file>.bak-<time>`, mode 600),
stages the committed code beside the app (the live dir is untouched), asks **on the server** for `S3_ACCESS_KEY_ID`
and `S3_SECRET_ACCESS_KEY` with hidden input (never echoed, never on a command line, never sent back) and writes them
with `S3_ENDPOINT`, `S3_REGION`, `S3_BUCKET` and `S3_PREFIX=blobs/` into the env file (mode 600), runs the three test
suites in the staging dir, checks the keys (list, write, read and delete a probe under `_deploy-check/`) and runs
`migrate-blobs-to-s3.mjs --dry-run`. **Then it stops and asks for a typed `yes`.** After that: copy every blob to the
bucket (checked), back up the code it replaces (`<app dir>.code-bak-<time>`), copy the new code in, set
`BLOB_STORE=s3` (and add the bstorex origins if `ALLOWED_ORIGINS` is set without them), `pm2 restart` (fork mode, 1
instance), wait until `/health` answers and the new start line says `blobs s3`, copy any blob that arrived meanwhile,
show the legal holds, and print a rollback command. Step 4 also offers (skippable) to set up report emails: SMTP host
(suggested `smtp.livemail.co.uk`, Fasthosts' outgoing server; check it), port, user (support@bwalletx.com) and the
password, typed hidden on the server like the S3 keys; step 6 then offers to send one test email. The old `DATA_DIR/blobs` stays until you remove it by hand.

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
