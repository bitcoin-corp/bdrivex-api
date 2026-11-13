// Legal holds on files, and the reports behind them. A report puts the reported file on hold: its owner can't delete
// it (DELETE /v1/files/:sha256 answers 423 legal_hold) and close-account.mjs won't remove it, until it is released here.
//
//   cd <app dir> && node --env-file=<env file> scripts/legal-hold.mjs list                                # read-only
//   cd <app dir> && node --env-file=<env file> scripts/legal-hold.mjs release <identityKey> <sha256> --note "why" [--yes]
//   cd <app dir> && node --env-file=<env file> scripts/legal-hold.mjs place   <identityKey> <sha256> --note "why" [--yes]
//
// release and place look only unless --yes is given. Releasing lets the owner delete the file again; it does not delete
// anything. Released holds are kept 3 years after release (the server then deletes them), like report records.
// Env: DATA_DIR (the database is DATA_DIR/bdrivex.db; default ./data). Exit 0 ok, 1 nothing to do, 2 bad arguments.
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { openDb } from '../src/db.js';
import { holdsReport, KEY, HASH } from '../src/admin.js';

const TAG = '[legal-hold]';
const argv = process.argv.slice(2);
const noteAt = argv.indexOf('--note');
const note = noteAt >= 0 ? argv[noteAt + 1] : null;
const rest = noteAt < 0 ? argv : argv.filter((_a, i) => i !== noteAt && i !== noteAt + 1);
const [cmd, ...pos] = rest.filter((a) => !a.startsWith('--'));
const APPLY = rest.includes('--yes');
for (const a of rest) if (a.startsWith('--') && a !== '--yes') { console.error(`${TAG} unknown option ${a}`); process.exit(2); }

const DATA = process.env.DATA_DIR || join(process.cwd(), 'data');
const dbFile = join(DATA, 'bdrivex.db');
if (!existsSync(dbFile)) { console.error(`${TAG} no database at ${dbFile}: set DATA_DIR (run with the API's env file)`); process.exit(2); }
const iso = (t) => (t ? new Date(t).toISOString() : '-');

if (cmd === 'list' || !cmd) {
  const db = new DatabaseSync(dbFile, { readOnly: true });
  const r = holdsReport(db, { releasedSince: Date.now() - 90 * 86400_000 });
  db.close();
  console.log(`${TAG} active holds: ${r.active.length}`);
  for (const h of r.active) console.log(`  HOLD owner ${h.owner} file ${h.hash} · since ${iso(h.placed_at)} · ${h.reason ?? ''}${h.link_id ? ` · link ${h.link_id}` : ''}${h.file_exists ? '' : ' · (file row gone)'}`);
  console.log(`${TAG} released in the last 90 days: ${r.released.length}`);
  for (const h of r.released) console.log(`  released ${iso(h.released_at)} owner ${h.owner} file ${h.hash} · ${h.released_note ?? ''}`);
  console.log(`${TAG} reports (newest 200, kept 3 years): ${r.reports.length}`);
  for (const x of r.reports) console.log(`  ${iso(x.at)} link ${x.link_id} owner ${x.owner ?? '?'} file ${x.hash ?? '?'} · reporter IP ${x.ip_hashed ? 'hashed' : 'kept (under 30 days)'} · "${String(x.reason ?? '').replace(/\s+/g, ' ').slice(0, 120)}"`);
  process.exit(0);
}

if (!['release', 'place'].includes(cmd) || pos.length !== 2) {
  console.error(`${TAG} usage: legal-hold.mjs list | release <identityKey> <sha256> --note "why" [--yes] | place <identityKey> <sha256> --note "why" [--yes]`);
  process.exit(2);
}
const [owner, hash] = [pos[0].toLowerCase(), pos[1].toLowerCase()];
if (!KEY.test(owner) || !HASH.test(hash)) { console.error(`${TAG} need an identity key (66 hex, 02/03) and a sha256 (64 hex)`); process.exit(2); }
if (!note) { console.error(`${TAG} --note "why" is required (it is kept with the hold)`); process.exit(2); }

const S = openDb(dbFile);
const db = S.db;
try {
  const active = db.prepare('SELECT id FROM holds WHERE owner = ? AND hash = ? AND released_at IS NULL').all(owner, hash);
  const hasFile = !!S.files.get.get(owner, hash);
  if (cmd === 'release') {
    if (!active.length) { console.log(`${TAG} no active hold on ${owner} / ${hash}`); process.exit(1); }
    if (!APPLY) { console.log(`${TAG} would release ${active.length} hold(s) on ${owner} / ${hash}${hasFile ? '' : ' (file row already gone)'}. Add --yes.`); process.exit(0); }
    const n = db.prepare('UPDATE holds SET released_at = ?, released_note = ? WHERE owner = ? AND hash = ? AND released_at IS NULL').run(Date.now(), note, owner, hash).changes;
    console.log(`${TAG} released ${n} hold(s) on ${owner} / ${hash}: the owner can delete it again`);
  } else {
    if (!hasFile) { console.log(`${TAG} ${owner} holds no file ${hash}`); process.exit(1); }
    if (active.length) { console.log(`${TAG} already on hold`); process.exit(0); }
    if (!APPLY) { console.log(`${TAG} would place a hold on ${owner} / ${hash}. Add --yes.`); process.exit(0); }
    S.holds.place.run(owner, hash, null, Date.now(), `admin: ${note}`);
    console.log(`${TAG} placed a hold on ${owner} / ${hash}`);
  }
} finally { db.close(); }
