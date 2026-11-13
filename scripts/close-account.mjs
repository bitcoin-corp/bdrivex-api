// Close one account, after the user has asked by email (support@bwalletx.com) with their identity key and we have
// confirmed it is theirs. Looks only unless --yes is given.
//
//   cd <app dir> && node --env-file=<env file> scripts/close-account.mjs <identityKey>             # what it would do
//   cd <app dir> && node --env-file=<env file> scripts/close-account.mjs <identityKey> --yes       # do it
//        [--keep-held]  close everything except files under legal hold (otherwise a held file refuses the close)
//
// Env: DATA_DIR (the database is DATA_DIR/bdrivex.db; default ./data), BLOB_STORE and, for s3, the S3_* settings: the
// same env file the API runs with. scripts/deploy-s3.sh prints where that is.
//
// Deletes: the account's files and every blob nobody else holds (through the blob store; each one goes in the deletion
// log, erased_blobs, so the nightly `mirror-to-b2.mjs --prune` removes the B2 copy too), its share links, unfinished
// uploads (rows and staged bytes), the key wraps (they live on the file rows), sign-in nonces and the sign-out counter
// (generations). Records sha256 of the key in closed_accounts for 8 days, so tokens issued before now stop working;
// the key itself is not kept there. There is no account table: those rows are the account.
// Keeps: report records about the account's files (3 years, then the server deletes them), files under legal hold
// (release them first with scripts/legal-hold.mjs, or pass --keep-held), and links other people sent TO this wallet
// (they belong to their senders; they lose the recipient key 7 days after they expire or are revoked).
// A blob delete the store refuses is queued in blob_deletes and the running server retries it.
// Exit: 0 done (or dry run), 1 refused or failed, 2 bad arguments or setup.
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { openDb } from '../src/db.js';
import { blobStoreFromEnv } from '../src/blobstore.js';
import { closePlan, closeAccount, KEY } from '../src/admin.js';

const TAG = '[close-account]';
const argv = process.argv.slice(2);
const flags = new Set(argv.filter((a) => a.startsWith('--')));
const keys = argv.filter((a) => !a.startsWith('--'));
for (const f of flags) if (!['--yes', '--dry-run', '--keep-held'].includes(f)) { console.error(`${TAG} unknown option ${f}`); process.exit(2); }
if (keys.length !== 1) { console.error(`${TAG} usage: close-account.mjs <identityKey> [--yes] [--keep-held]`); process.exit(2); }
const key = keys[0].toLowerCase();
if (!KEY.test(key)) { console.error(`${TAG} not an identity key (66 hex characters starting 02 or 03): ${keys[0]}`); process.exit(2); }
const APPLY = flags.has('--yes') && !flags.has('--dry-run');
const KEEP_HELD = flags.has('--keep-held');

const DATA = process.env.DATA_DIR || join(process.cwd(), 'data');
const dbFile = join(DATA, 'bdrivex.db');
if (!existsSync(dbFile)) { console.error(`${TAG} no database at ${dbFile}: set DATA_DIR (run with the API's env file)`); process.exit(2); }

const short = (k) => `${k.slice(0, 12)}…`;
const mb = (n) => `${(n / 2 ** 20).toFixed(1)} MB`;
function describe(p) {
  console.log(`${TAG} account ${key}`);
  console.log(`${TAG}   files: ${p.files} (${mb(p.bytes)}) · to delete ${p.toDelete.length} · under legal hold ${p.held.length}`);
  console.log(`${TAG}   blobs other wallets also hold (kept): ${p.sharedBlobs} · key wraps: ${p.keyWraps}`);
  console.log(`${TAG}   share links owned: ${p.links} (all deleted) · links sent TO this wallet by others: ${p.inboundLinks} (left to their senders)`);
  console.log(`${TAG}   unfinished uploads: ${p.uploads.length} · sign-out counter: ${p.signOutCounter ? 'yes' : 'none'} · report records about it (kept): ${p.reports}`);
  if (p.alreadyClosed) console.log(`${TAG}   already closed at ${new Date(p.alreadyClosed).toISOString()} (closing again is safe)`);
  for (const f of p.held) console.log(`${TAG}   HELD ${f.hash} (${f.size} bytes): see scripts/legal-hold.mjs list`);
}

if (!APPLY) {
  const db = new DatabaseSync(dbFile, { readOnly: true });
  try {
    if (!db.prepare("SELECT 1 AS n FROM sqlite_master WHERE type = 'table' AND name = 'files'").get()) { console.error(`${TAG} ${dbFile} is not a bdrivex database`); process.exit(2); }
    const p = closePlan(db, key);
    describe(p);
    if (p.held.length && !KEEP_HELD) console.log(`${TAG} --yes would REFUSE: ${p.held.length} file(s) on legal hold. Release them (scripts/legal-hold.mjs) or add --keep-held.`);
    console.log(`${TAG} dry run: nothing changed. Add --yes to close this account.`);
  } finally { db.close(); }
  process.exit(0);
}

const S = openDb(dbFile);
let store;
try { store = blobStoreFromEnv(process.env, DATA); } catch (e) { console.error(`${TAG} ${e.message}`); S.db.close(); process.exit(2); }
let code = 0;
try {
  const r = await closeAccount({ S, store, tmpDir: join(DATA, 'tmp'), key, keepHeld: KEEP_HELD, log: (m) => console.log(`${TAG} ${m}`) });
  describe(r.plan);
  if (r.refused) {
    console.error(`${TAG} REFUSED: ${r.refused}. Nothing deleted. Release the hold (scripts/legal-hold.mjs) or run with --keep-held.`);
    code = 1;
  } else {
    console.log(`${TAG} closed ${short(key)} (${store.describe()}): ${r.filesDeleted} files, ${r.linksDeleted} links, ${r.uploadsDeleted} uploads deleted · blobs deleted ${r.blobsDeleted}, kept (shared) ${r.blobsKeptShared}, queued for the server's retry ${r.blobDeletesQueued}${r.races ? ` · RACES ${r.races} (see above)` : ''} · kept: ${r.plan.held.length} held files, ${r.plan.reports} report records · tokens issued before now no longer work`);
    if (r.races) code = 1;
  }
} catch (e) {
  console.error(`${TAG} FAILED: ${e.message}`);
  code = 1;
} finally { store.close?.(); S.db.close(); }
process.exit(code);
