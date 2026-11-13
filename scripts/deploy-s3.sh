#!/usr/bin/env bash
# Move files.bdrivex.com (bdrivex-api) onto Hetzner Object Storage. Run it from your Mac, in this repo:
#
#   scripts/deploy-s3.sh                 # inspect, stage, ask for the S3 keys, test, dry run, then ask "yes" to go live
#   scripts/deploy-s3.sh --check-logs    # read-only: what access logs nginx/caddy/pm2 keep for files.bdrivex.com
#
# Options: --host <ssh host> (default hetzner) · --env-file <path on the server> (only if it can't be found, and pm2
#          must already load that file) · --site-dir <bdrivex-site checkout, for the tests> (default
#          /Volumes/2026/Projects/bdrivex-site)
#
# What it does, in order. Nothing on the live app changes before you type "yes", except that the env file gains the
# S3 settings (the running API ignores them while BLOB_STORE is fs) and a backup of it is made first.
#   1. Finds the pm2 app on the server whose cwd contains bdrivex-api (exactly one, or it stops), and works out which
#      env file it loads (pm2 node_args --env-file, or the package.json script pm2 runs). Read-only. It stops if it
#      can't tell, if pm2 itself sets BLOB_STORE or S3_* (that would override the file), if the app isn't pm2 fork
#      mode with 1 instance, or if node is older than 22.13.
#   2. Backs up the env file (<env file>.bak-<time>, mode 600).
#   3. Copies this repo's tracked files (committed state; a dirty tree is refused) to a staging dir beside the app,
#      plus bdrivex-site/js for the tests. The live app dir is not touched.
#   4. Asks, on the server, for S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY (hidden input over ssh -t; they are never
#      echoed, never on a command line, never sent back) and writes them, with S3_ENDPOINT, S3_REGION, S3_BUCKET and
#      S3_PREFIX, into the env file, mode 600. Then, if you want (skippable), the SMTP settings for report emails to
#      support@bwalletx.com, with SMTP_PASS typed the same hidden way; you can send one test email.
#   5. Runs the three test suites in the staging dir on the server.
#   6. Checks the keys against the bucket (list, then write/read/delete one probe object under _deploy-check/) and
#      runs migrate-blobs-to-s3.mjs --dry-run against the live data. Shows the result.
#   7. STOPS and asks you to type yes. Then: copies every blob to the bucket (migrate, checked), backs up the code it
#      will replace, copies the new code into the app dir, sets BLOB_STORE=s3 (and adds the bstorex origins if
#      ALLOWED_ORIGINS is set without them), restarts the pm2 app (fork mode, 1 instance), health-checks it, runs the
#      migration once more for blobs that arrived meanwhile, and prints a rollback command.
# Every remote step is this same file run on the server with --remote (piped over ssh, or from the staging copy).
set -euo pipefail

# The bucket (owner, Nov 2026). DEPLOY_S3_* override these only for a local rehearsal against a fake bucket.
S3_ENDPOINT_VALUE=${DEPLOY_S3_ENDPOINT:-https://fsn1.your-objectstorage.com}
S3_REGION_VALUE=${DEPLOY_S3_REGION:-fsn1}
S3_BUCKET_VALUE=${DEPLOY_S3_BUCKET:-bcorp-bdrivex-files}
S3_PREFIX_VALUE=${DEPLOY_S3_PREFIX:-blobs/}
# Report emails (owner, Nov 2026): one mailbox, support@bwalletx.com on Fasthosts. The host is a suggestion you can
# change at the prompt (Fasthosts' outgoing server; check it in the Fasthosts control panel). DEPLOY_SMTP_HOST overrides.
SMTP_HOST_DEFAULT=${DEPLOY_SMTP_HOST:-smtp.livemail.co.uk}
REPORT_MAIL_TO_VALUE='support@bwalletx.com'
BSTOREX_ORIGINS='https://bstorex.com,https://www.bstorex.com'
TEST_PORTS='8782 8792 8793 8794 8795 8796 8798 8799'

say() { printf '%s\n' "$*"; }
die() { printf 'STOP: %s\n' "$*" >&2; exit 1; }

# ============================================================== remote side (runs on the server)

# Inspect the pm2 app. Prints KEY<TAB>value lines; never prints env values other than DATA_DIR, PORT, HOST, NODE_ENV,
# BLOB_STORE and ALLOWED_ORIGINS (none of them secret), and only the NAMES of S3 settings.
remote_inspect() {
  local want_env=${1:-}
  command -v pm2 >/dev/null || { printf 'ERROR\tpm2 is not on PATH for this ssh user\n'; return 0; }
  command -v node >/dev/null || { printf 'ERROR\tnode is not on PATH for this ssh user\n'; return 0; }
  pm2 jlist </dev/null 2>/dev/null | WANT_ENV="$want_env" node -e '
const fs = require("fs"), path = require("path"), cp = require("child_process");
const out = (k, v) => console.log(k + "\t" + String(v ?? "").replace(/[\t\r\n]+/g, " "));
const raw = fs.readFileSync(0, "utf8");
let list;
try { list = JSON.parse(raw.slice(raw.indexOf("["))); } catch (e) { out("ERROR", "could not read `pm2 jlist`: " + e.message); process.exit(0); }
const apps = list.filter((p) => (p.name === "bdrivex-api" || String(p.pm2_env?.pm_cwd || "").includes("bdrivex-api")));
out("COUNT", apps.length);
for (const p of apps) out("CANDIDATE", `pm2 id ${p.pm_id} · ${p.name} · cwd ${p.pm2_env.pm_cwd} · ${p.pm2_env.status}`);
if (apps.length !== 1) process.exit(0);
const p = apps[0], e = p.pm2_env, cwd = e.pm_cwd;
out("NAME", p.name); out("PM_ID", p.pm_id); out("CWD", cwd); out("CWD_HAS_SERVER", fs.existsSync(path.join(cwd, "src/server.js")) ? "yes" : "no"); out("SCRIPT", e.pm_exec_path); out("STATUS", e.status);
out("EXEC_MODE", e.exec_mode); out("INSTANCES", e.instances); out("INTERPRETER", e.exec_interpreter);
const words = (v) => [].concat(v || []).flatMap((a) => String(a).split(/\s+/)).filter(Boolean);
const nodeArgs = [...words(e.node_args), ...words(e.interpreter_args)], args = words(e.args);
out("NODE_ARGS", nodeArgs.join(" ")); out("ARGS", args.join(" "));
const envFileIn = (l) => { for (let i = 0; i < l.length; i++) { const m = /^--env-file(?:-if-exists)?(?:=(.+))?$/.exec(l[i]); if (m) return m[1] || l[i + 1]; } return null; };
let envFile = envFileIn(nodeArgs), source = envFile ? "pm2 node_args" : "";
if (!envFile && envFileIn(args)) { envFile = envFileIn(args); source = "pm2 args"; }
if (!envFile && /(^|\/)(pnpm|npm|yarn)(\.c?js)?$/.test(String(e.pm_exec_path))) {
  const name = args[0] === "run" ? args[1] : args[0];
  try {
    const sc = JSON.parse(fs.readFileSync(path.join(cwd, "package.json"), "utf8")).scripts?.[name];
    const f = sc && envFileIn(sc.split(/\s+/));
    if (f) { envFile = f; source = `package.json script "${name}" (pm2 runs it with ${path.basename(e.pm_exec_path)})`; }
    else out("NOTE", `pm2 runs the package.json script "${name}": ${sc || "(not found)"}, which loads no env file`);
  } catch (err) { out("NOTE", "could not read package.json: " + err.message); }
}
const eco = [];
for (const n of ["ecosystem.config.js", "ecosystem.config.cjs", "ecosystem.config.json", "pm2.config.js", "pm2.config.cjs"]) {
  const fp = path.join(cwd, n);
  if (!fs.existsSync(fp)) continue;
  out("ECOSYSTEM", fp);
  const t = fs.readFileSync(fp, "utf8");
  for (const m of t.matchAll(/--env-file(?:-if-exists)?[= ]([^\s"'"'"'`,\]]+)/g)) { eco.push(path.resolve(cwd, m[1])); out("ECOSYSTEM_ENV_FILE", path.resolve(cwd, m[1])); }
  if (/env_file|dotenv/.test(t)) out("NOTE", `${n} mentions env_file or dotenv: read it by hand`);
}
for (const n of [".env.local", ".env", ".env.production"]) if (fs.existsSync(path.join(cwd, n))) out("CWD_ENV_FILE", path.join(cwd, n));
const want = process.env.WANT_ENV;
if (want) {
  const abs = path.resolve(cwd, want);
  if (envFile && path.resolve(cwd, envFile) !== abs) out("ERROR", `--env-file ${abs} is not the file pm2 loads (${path.resolve(cwd, envFile)})`);
  else if (!envFile && !eco.includes(abs)) out("ERROR", `--env-file ${abs}: nothing shows pm2 loading it (no --env-file in node_args, package.json or an ecosystem file), so BLOB_STORE written there would not take effect`);
  else { envFile = abs; source = source || "--env-file, named in the ecosystem file"; }
}
if (envFile) {
  const abs = path.resolve(cwd, envFile);
  out("ENV_FILE", abs); out("ENV_SOURCE", source);
  try {
    const st = fs.statSync(abs);
    out("ENV_MODE", (st.mode & 0o777).toString(8)); out("ENV_OWNER_UID", st.uid); out("MY_UID", process.getuid());
    try { fs.accessSync(abs, fs.constants.W_OK); out("ENV_WRITABLE", "yes"); } catch { out("ENV_WRITABLE", "no"); }
    const kv = {};
    for (const line of fs.readFileSync(abs, "utf8").split(/\r?\n/)) { const m = /^(?:export\s+)?([A-Z0-9_]+)=(.*)$/.exec(line); if (m) kv[m[1]] = m[2].replace(/^(["'"'"'])(.*)\1$/, "$2"); }
    for (const k of ["DATA_DIR", "PORT", "HOST", "NODE_ENV", "BLOB_STORE", "ALLOWED_ORIGINS"]) if (k in kv) out("FILE_" + k, kv[k]);
    out("FILE_S3_SET", Object.keys(kv).filter((k) => k.startsWith("S3_")).join(" "));
    out("FILE_SMTP_SET", Object.keys(kv).filter((k) => k.startsWith("SMTP_") || k === "REPORT_MAIL_TO").join(" "));
    for (const k of ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "REPORT_MAIL_TO"]) if (k in kv) out("FILE_" + k, kv[k]);
  } catch (err) { out("ERROR", `env file ${abs}: ${err.message}`); }
}
const penv = { ...e, ...(e.env || {}) };
const overrides = ["BLOB_STORE", "S3_ENDPOINT", "S3_REGION", "S3_BUCKET", "S3_PREFIX", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY",
  "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "SMTP_FROM", "REPORT_MAIL_TO"].filter((k) => k in penv);
out("PM2_OVERRIDES", overrides.join(" "));
for (const k of ["DATA_DIR", "PORT", "HOST", "NODE_ENV", "ALLOWED_ORIGINS"]) if (k in penv && penv[k] !== undefined && penv[k] !== "") out("PM2_" + k, penv[k]);
for (const d of ["@bsv/sdk", "@bwalletx/connect"]) { try { out("DEP", `${d} ${JSON.parse(fs.readFileSync(path.join(cwd, "node_modules", d, "package.json"), "utf8")).version}`); } catch { out("DEP_MISSING", d); } }
const interp = e.exec_interpreter && e.exec_interpreter !== "none" ? e.exec_interpreter : "node";
try { out("NODE_VERSION", cp.execFileSync(interp === "node" ? process.execPath : interp, ["-v"]).toString().trim()); } catch { out("NODE_VERSION", process.version); }
out("PATH_NODE_VERSION", process.version); out("PATH_NODE", process.execPath);
out("OUT_LOG", e.pm_out_log_path); out("ERR_LOG", e.pm_err_log_path);
'
}

# Write KEY='value' pairs into an env file, replacing any existing lines for those keys. Pure bash builtins for the
# values (printf), so no value ever appears on a command line; the temp file is mode 600 and goes at the end.
write_env() {
  local file=$1; shift
  local -a keys=() vals=()
  while [ $# -gt 0 ]; do keys+=("$1"); vals+=("$2"); shift 2; done
  local tmp line k skip i
  tmp=$(umask 077 && mktemp "$file.tmp.XXXXXX") || return 1
  {
    while IFS= read -r line || [ -n "$line" ]; do
      skip=0
      for k in "${keys[@]}"; do case "$line" in "$k="* | "export $k="*) skip=1 ;; esac; done
      [ "$skip" = 1 ] || printf '%s\n' "$line"
    done <"$file"
    for i in "${!keys[@]}"; do printf "%s='%s'\n" "${keys[$i]}" "${vals[$i]}"; done
  } >"$tmp" || { rm -f "$tmp"; return 1; }
  cat "$tmp" >"$file" && chmod 600 "$file"
  local rc=$?
  rm -f "$tmp"
  return $rc
}

remote_backup_env() {
  local file=$1 ts=$2
  [ -f "$file" ] || { say "no env file at $file"; return 1; }
  (umask 077 && cp -p "$file" "$file.bak-$ts") && chmod 600 "$file.bak-$ts" && say "backed up the env file to $file.bak-$ts (mode 600)"
}

remote_prepare_stage() {
  local app=$1 stage=$2
  [ -d "$app/node_modules" ] || { say "no $app/node_modules: install the app's dependencies there first"; return 1; }
  ln -sfn "$app/node_modules" "$stage/node_modules"
  say "staging dir $stage uses $app/node_modules"
}

# Interactive (ssh -t): ask for the two keys with hidden input and write the S3 settings into the env file.
remote_set_keys() {
  [ -t 0 ] || { say "set-keys needs a terminal (ssh -t)"; return 1; }
  remote_set_s3_keys "$1" || return 1
  remote_set_smtp "$1"
}

remote_set_s3_keys() {
  local file=$1 ak='' sk='' tries=0 has_ak has_sk answer keyre='^[A-Za-z0-9._/+=-]{8,255}$'
  has_ak=$(grep -cE '^(export )?S3_ACCESS_KEY_ID=.+' "$file" || true)
  has_sk=$(grep -cE '^(export )?S3_SECRET_ACCESS_KEY=.+' "$file" || true)
  if [ "$has_ak" != 0 ] && [ "$has_sk" != 0 ]; then
    read -r -p "S3 keys are already in $file. Replace them? [y/N] " answer
    if [ "$answer" != y ] && [ "$answer" != Y ]; then
      write_env "$file" S3_ENDPOINT "$S3_ENDPOINT_VALUE" S3_REGION "$S3_REGION_VALUE" S3_BUCKET "$S3_BUCKET_VALUE" S3_PREFIX "$S3_PREFIX_VALUE"
      say "kept the keys already there; endpoint, region, bucket and prefix written."
      return 0
    fi
  fi
  say "Paste the Hetzner Object Storage keys for bucket $S3_BUCKET_VALUE (from your password manager). Nothing is shown as you type."
  while :; do
    tries=$((tries + 1))
    IFS= read -r -s -p "S3_ACCESS_KEY_ID: " ak; printf '\n'
    IFS= read -r -s -p "S3_SECRET_ACCESS_KEY: " sk; printf '\n'
    if [[ "$ak" =~ $keyre ]] && [[ "$sk" =~ $keyre ]]; then break; fi
    say "That doesn't look like a key pair (letters, digits and ._/+=- only, 8 to 255 characters). Not shown."
    [ "$tries" -lt 3 ] || { ak=''; sk=''; say "giving up after 3 tries; nothing written"; return 1; }
  done
  write_env "$file" S3_ENDPOINT "$S3_ENDPOINT_VALUE" S3_REGION "$S3_REGION_VALUE" S3_BUCKET "$S3_BUCKET_VALUE" S3_PREFIX "$S3_PREFIX_VALUE" \
    S3_ACCESS_KEY_ID "$ak" S3_SECRET_ACCESS_KEY "$sk"
  ak=''; sk=''
  say "wrote S3_ENDPOINT, S3_REGION, S3_BUCKET, S3_PREFIX and the two keys to $file (mode 600)."
}

# Optional: SMTP for report emails. Host, port and user are shown as you type (not secret); the password is hidden.
# Skipping leaves report mail as it is (off if never set: the API then only logs reports).
remote_set_smtp() {
  local file=$1 answer host port user pass='' have
  have=$(grep -cE '^(export )?SMTP_PASS=.+' "$file" || true)
  if [ "$have" != 0 ]; then read -r -p "Report email (SMTP) is already set up in $file. Change it? [y/N] " answer
  else read -r -p "Set up report emails to $REPORT_MAIL_TO_VALUE now (SMTP; you can skip)? [y/N] " answer; fi
  if [ "$answer" != y ] && [ "$answer" != Y ]; then say "report email: skipped (left as it was)."; return 0; fi
  read -r -p "SMTP host [$SMTP_HOST_DEFAULT]: " host; host=${host:-$SMTP_HOST_DEFAULT}
  read -r -p "SMTP port, 465 = TLS, 587 = STARTTLS [465]: " port; port=${port:-465}
  read -r -p "SMTP user [$REPORT_MAIL_TO_VALUE]: " user; user=${user:-$REPORT_MAIL_TO_VALUE}
  if ! [[ "$host" =~ ^[A-Za-z0-9.-]+$ ]] || ! [[ "$port" =~ ^[0-9]{2,5}$ ]] || ! [[ "$user" =~ ^[^[:space:]\'\"@]+@[A-Za-z0-9.-]+$ ]]; then
    say "that host, port or user doesn't look right; report email skipped, nothing written."; return 0
  fi
  IFS= read -r -s -p "SMTP password for $user (hidden; empty skips): " pass; printf '\n'
  if [ -z "$pass" ]; then say "report email: skipped, nothing written."; return 0; fi
  case $pass in *"'"* | *$'\n'* | *$'\r'*) pass=''; say "a password with a single quote or line break can't be written safely; skipped, nothing written."; return 0 ;; esac
  write_env "$file" SMTP_HOST "$host" SMTP_PORT "$port" SMTP_USER "$user" SMTP_PASS "$pass" SMTP_FROM "$user" REPORT_MAIL_TO "$REPORT_MAIL_TO_VALUE"
  pass=''
  say "wrote SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM and REPORT_MAIL_TO to $file (mode 600). Used after the restart."
}

port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

remote_test() {
  local stage=$1 p rc=0 name
  for p in $TEST_PORTS; do if port_busy "$p"; then say "port $p is in use on this server; the tests need $TEST_PORTS free. Not running them."; return 1; fi; done
  command -v openssl >/dev/null || { say "the tests need openssl on this server (the fake SMTP server's certificate)."; return 1; }
  cd "$stage" && mkdir -p .test-logs
  for name in e2e-fs s3 mail e2e-s3; do
    case $name in
      mail) node test/mail.mjs </dev/null >".test-logs/$name.log" 2>&1 ;;
      e2e-fs) SITE_DIR="$stage/.test-site" node test/e2e.mjs </dev/null >".test-logs/$name.log" 2>&1 ;;
      s3) node test/s3.mjs </dev/null >".test-logs/$name.log" 2>&1 ;;
      e2e-s3) SITE_DIR="$stage/.test-site" BLOB_STORE=s3 node test/e2e.mjs </dev/null >".test-logs/$name.log" 2>&1 ;;
    esac && say "  $name: $(grep -c '^  ok ' ".test-logs/$name.log") ok · $(tail -1 ".test-logs/$name.log")" || {
      rc=1
      say "  $name: FAILED ($stage/.test-logs/$name.log)"
      grep -E 'FAIL|Error' ".test-logs/$name.log" | head -20 || true
      tail -15 ".test-logs/$name.log"
    }
  done
  return $rc
}

# Run a node script from the staging dir against the live data dir, with the app's env file.
live_node() {
  local app=$1 envf=$2 datadir=$3; shift 3
  if [ -n "$datadir" ]; then (cd "$app" && DATA_DIR="$datadir" node --env-file="$envf" "$@" </dev/null)
  else (cd "$app" && node --env-file="$envf" "$@" </dev/null); fi
}

remote_bucket_check() {
  local app=$1 stage=$2 envf=$3 datadir=$4
  live_node "$app" "$envf" "$datadir" --input-type=module -e '
const { createS3Client, s3ConfigFromEnv } = await import(process.argv[1]);
const { createHash, randomBytes } = await import("node:crypto");
const cfg = s3ConfigFromEnv(process.env, "S3");
const c = createS3Client(cfg);
const where = `${new URL(cfg.endpoint).host}/${cfg.bucket}/${cfg.prefix}`;
try {
  let n = 0;
  for await (const o of c.list(cfg.prefix)) { void o; if (++n >= 1000) break; }
  console.log(`[bucket] ${where}: the keys can list it; ${n >= 1000 ? "1000+" : n} objects under the prefix`);
  const body = randomBytes(64), sha = createHash("sha256").update(body).digest("hex"), key = `_deploy-check/${Date.now()}-${sha.slice(0, 12)}`;
  await c.put(key, { body, size: body.length, sha256: sha });
  const size = await c.head(key);
  await c.del(key);
  const gone = (await c.head(key)) == null;
  if (size !== 64 || !gone) throw new Error(`probe object: size ${size}, deleted ${gone}`);
  console.log(`[bucket] write, read and delete work (probe ${cfg.bucket}/${key}, removed)`);
} catch (e) { console.error(`[bucket] FAILED: ${e.message}`); process.exitCode = 1; } finally { c.close(); }
' "$stage/src/s3.js"
}

remote_dryrun() {
  local app=$1 stage=$2 envf=$3 datadir=$4
  remote_bucket_check "$app" "$stage" "$envf" "$datadir" || return 1
  live_node "$app" "$envf" "$datadir" "$stage/scripts/migrate-blobs-to-s3.mjs" --dry-run
}

remote_mailtest() {
  local app=$1 stage=$2 envf=$3 datadir=$4
  live_node "$app" "$envf" "$datadir" "$stage/scripts/report-mail-test.mjs"
}

remote_golive() {
  local app=$1 stage=$2 envf=$3 datadir=$4 pmid=$5 ts=$6 health=$7 add_origins=$8
  local bak="$app.code-bak-$ts" i line
  say "1/7 copying every blob to the bucket (checked; nothing switched yet)"
  live_node "$app" "$envf" "$datadir" "$stage/scripts/migrate-blobs-to-s3.mjs" || { say "migration failed: nothing switched. The app runs as before."; return 1; }
  say "2/7 backing up the code it will replace to $bak"
  mkdir -p "$bak"
  local f
  while IFS= read -r f; do [ -e "$app/$f" ] && printf '%s\n' "$f"; done <"$stage/.deploy-files" >"$stage/.backup-files" || true
  rsync -a --files-from="$stage/.backup-files" "$app/" "$bak/"
  say "3/7 copying the new code into $app"
  rsync -a --files-from="$stage/.deploy-files" "$stage/" "$app/"
  say "4/7 setting BLOB_STORE=s3 in $envf"
  if [ -n "$add_origins" ]; then
    write_env "$envf" BLOB_STORE s3 ALLOWED_ORIGINS "$add_origins"
    say "    and ALLOWED_ORIGINS=$add_origins"
  else write_env "$envf" BLOB_STORE s3; fi
  say "5/7 restarting pm2 app $pmid (fork mode, 1 instance)"
  pm2 restart "$pmid" </dev/null >/dev/null
  # Healthy means: /health answers AND the newest start line in the pm2 log says "blobs s3" (so it is the new process
  # with the new env answering, not an old one that never went away).
  local ok=''
  for i in $(seq 1 40); do
    line=$(pm2 logs "$pmid" --nostream --lines 200 </dev/null 2>/dev/null | grep 'api on http' | tail -1 || true)
    case $line in *"blobs s3 "*)
      if node -e 'fetch(process.argv[1]).then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))' "$health" </dev/null; then ok=1; break; fi ;;
    esac
    sleep 1
  done
  if [ -z "$ok" ]; then
    say "HEALTH CHECK FAILED: after 40s the API at $health is not up on s3. Newest start line: ${line:-none}"
    say "See: pm2 logs $pmid --lines 50. Roll back (command below)."
    return 1
  fi
  say "6/7 healthy at $health · ${line#*\[bdrivex\] }"
  say "7/7 copying blobs that arrived during the switch"
  live_node "$app" "$envf" "$datadir" "$stage/scripts/migrate-blobs-to-s3.mjs" || say "WARNING: the second migration pass failed; run it again (command below)."
  say "legal holds now on record (reports from before holds existed are held too):"
  live_node "$app" "$envf" "$datadir" "$app/scripts/legal-hold.mjs" list | head -30 || true
}

remote_check_logs() {
  local f c
  say "== who serves files.bdrivex.com on this box"
  if command -v nginx >/dev/null || [ -d /etc/nginx ]; then
    say "-- nginx: config files naming files.bdrivex.com"
    for f in $(grep -rlE 'files\.bdrivex\.com' /etc/nginx 2>/dev/null || true); do
      say "   $f"; grep -nE 'server_name|access_log|error_log|log_format|proxy_pass' "$f" 2>/dev/null | sed 's/^/     /' || true
    done
    say "-- nginx: global log settings (/etc/nginx/nginx.conf)"; grep -nE 'access_log|error_log|log_format' /etc/nginx/nginx.conf 2>/dev/null | sed 's/^/     /' || say "     (none or unreadable)"
    say "-- logrotate for nginx"; grep -nE 'rotate|daily|weekly|monthly|maxage|compress|/var/log' /etc/logrotate.d/nginx 2>/dev/null | sed 's/^/     /' || say "     (no /etc/logrotate.d/nginx)"
    say "-- /var/log/nginx (names, sizes, dates)"; ls -la /var/log/nginx 2>/dev/null | sed 's/^/     /' || say "     (unreadable)"
  else say "-- nginx: not installed on the host"; fi
  if command -v caddy >/dev/null || [ -d /etc/caddy ]; then
    say "-- caddy: /etc/caddy/Caddyfile, the files.bdrivex.com block and log settings"
    grep -nE 'files\.bdrivex\.com|log|output|roll_|format' /etc/caddy/Caddyfile 2>/dev/null | sed 's/^/     /' || say "     (no Caddyfile or unreadable)"
  else say "-- caddy: not installed on the host"; fi
  if command -v docker >/dev/null && docker ps >/dev/null 2>&1 </dev/null; then
    say "-- proxies in docker"
    docker ps --format '{{.Names}} {{.Image}}' </dev/null | grep -iE 'nginx|caddy|traefik|proxy' | sed 's/^/     /' || say "     (none)"
    for c in $(docker ps --format '{{.Names}} {{.Image}}' </dev/null | grep -iE 'nginx|caddy|traefik|proxy' | awk '{print $1}'); do
      say "   $c: config naming files.bdrivex.com"
      docker exec "$c" sh -c 'grep -rnE "files\.bdrivex\.com|access_log|accesslog|log \{|output|roll_" /etc/nginx /etc/caddy /etc/traefik 2>/dev/null | head -40' </dev/null | sed 's/^/     /' || true
      say "   $c: docker log driver $(docker inspect -f '{{.HostConfig.LogConfig.Type}} {{json .HostConfig.LogConfig.Config}}' "$c" </dev/null 2>/dev/null)"
    done
  else say "-- docker: not available to this user"; fi
  say "-- journald retention (if a proxy logs to the journal)"
  grep -nE '^(SystemMaxUse|MaxRetentionSec|MaxFileSec)' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null | sed 's/^/     /' || say "     (defaults: no MaxRetentionSec, size-capped)"
  journalctl --disk-usage 2>/dev/null </dev/null | sed 's/^/     /' || true
  say "== pm2 (the API's own logs)"
  pm2 jlist </dev/null 2>/dev/null | node -e '
const fs = require("fs"); const raw = fs.readFileSync(0, "utf8");
let list = []; try { list = JSON.parse(raw.slice(raw.indexOf("["))); } catch {}
for (const p of list.filter((x) => (x.name === "bdrivex-api" || String(x.pm2_env?.pm_cwd || "").includes("bdrivex-api")))) {
  for (const f of [p.pm2_env.pm_out_log_path, p.pm2_env.pm_err_log_path]) {
    try { const s = fs.statSync(f); const t = fs.readFileSync(f, "utf8"); const ips = (t.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).filter((x) => x !== "127.0.0.1").length;
      console.log(`   ${f}: ${(s.size / 1048576).toFixed(1)} MB, modified ${s.mtime.toISOString()}, IPv4-looking strings other than 127.0.0.1: ${ips}`);
    } catch (e) { console.log(`   ${f}: ${e.message}`); }
  }
}
const mods = list.filter((x) => x.name === "pm2-logrotate");
console.log(mods.length ? "   pm2-logrotate is installed" : "   pm2-logrotate is NOT installed: pm2 logs grow until someone empties them (pm2 flush)");
'
  if [ -f "$HOME/.pm2/module_conf.json" ]; then
    say "   pm2-logrotate settings: $(node -e 'const c = require(process.argv[1])["pm2-logrotate"] || {}; console.log(JSON.stringify({ retain: c.retain, max_size: c.max_size, rotateInterval: c.rotateInterval, compress: c.compress }))' "$HOME/.pm2/module_conf.json" </dev/null 2>/dev/null)"
  fi
  say "== the API itself writes no client IPs to its logs (it keeps reporter IPs only in the reports table, hashed after 30 days)."
}

remote_main() {
  local cmd=$1; shift
  case $cmd in
    inspect) remote_inspect "$@" ;;
    backup-env) remote_backup_env "$@" ;;
    prepare-stage) remote_prepare_stage "$@" ;;
    set-keys) remote_set_keys "$@" ;;
    test) remote_test "$@" ;;
    dryrun) remote_dryrun "$@" ;;
    mailtest) remote_mailtest "$@" ;;
    golive) remote_golive "$@" ;;
    check-logs) remote_check_logs "$@" ;;
    *) say "unknown remote command $cmd"; return 2 ;;
  esac
}

# ============================================================== local side (runs on the Mac)

HOST=hetzner
ENV_OVERRIDE=''
SITE_DIR=/Volumes/2026/Projects/bdrivex-site
MODE=deploy
SELF="${BASH_SOURCE[0]:-$0}"

q() { printf '%q' "$1"; }
# Run a remote command by piping this file to bash on the server (non-interactive).
remote() { ssh -o BatchMode=yes "$HOST" "bash -s -- --remote $(for a in "$@"; do printf '%q ' "$a"; done)" <"$SELF"; }

local_main() {
  while [ $# -gt 0 ]; do
    case $1 in
      --host) HOST=$2; shift 2 ;;
      --env-file) ENV_OVERRIDE=$2; shift 2 ;;
      --site-dir) SITE_DIR=$2; shift 2 ;;
      --check-logs) MODE=check-logs; shift ;;
      -h | --help) sed -n '2,30p' "$SELF"; exit 0 ;;
      *) die "unknown option $1 (see --help)" ;;
    esac
  done

  if [ "$MODE" = check-logs ]; then
    say "Read-only: access logs for files.bdrivex.com on $HOST"
    remote check-logs
    say "== DNS from here: files.bdrivex.com -> $(dig +short files.bdrivex.com 2>/dev/null | tr '\n' ' ') (if that is a CDN such as Cloudflare, its logs are separate)"
    exit 0
  fi

  local repo; repo=$(cd "$(dirname "$SELF")/.." && pwd)
  [ -f "$repo/src/server.js" ] && [ -f "$repo/package.json" ] || die "run this from the bdrivex-api repo"
  [ -z "$(git -C "$repo" status --porcelain --untracked-files=no)" ] || die "the repo has uncommitted changes to tracked files; commit or stash them so what is deployed is a commit"
  [ -f "$SITE_DIR/js/bdx-client.js" ] || die "no bdrivex-site at $SITE_DIR (needed for the tests); pass --site-dir"
  local head; head=$(git -C "$repo" log --oneline -1)
  say "bdrivex-api to Hetzner Object Storage · code $head · server $HOST"

  # ---- 1. inspect
  say ""; say "== 1. the pm2 app (read-only)"
  local info; info=$(remote inspect "$ENV_OVERRIDE") || die "could not reach $HOST over ssh"
  get() { printf '%s\n' "$info" | awk -F'\t' -v k="$1" '$1 == k && !seen++ { sub(/^[^\t]*\t/, ""); print }'; }
  getall() { printf '%s\n' "$info" | awk -F'\t' -v k="$1" '$1 == k { sub(/^[^\t]*\t/, ""); print }'; }
  local err; err=$(getall ERROR)
  local count; count=$(get COUNT)
  getall CANDIDATE | sed 's/^/   found: /'
  [ -z "$err" ] || { printf '%s\n' "$err" | sed 's/^/   /'; die "inspection failed (above)"; }
  [ "$count" = 1 ] || die "expected exactly one pm2 app named bdrivex-api (or with bdrivex-api in its cwd), found ${count:-0}"
  local name pmid cwd mode inst envf envsrc overrides nodev datadir port
  name=$(get NAME); pmid=$(get PM_ID); cwd=$(get CWD); mode=$(get EXEC_MODE); inst=$(get INSTANCES)
  envf=$(get ENV_FILE); envsrc=$(get ENV_SOURCE); overrides=$(get PM2_OVERRIDES); nodev=$(get NODE_VERSION)
  say "   app:       $name (pm2 id $pmid), $(get STATUS), $mode × $inst"
  say "   cwd:       $cwd"
  say "   started:   $(get SCRIPT) $(get ARGS)   node args: $(get NODE_ARGS)"
  say "   node:      $nodev (ssh PATH node $(get PATH_NODE_VERSION))"
  say "   deps:      $(getall DEP | tr '\n' ' ')$(getall DEP_MISSING | sed 's/^/MISSING /' | tr '\n' ' ')"
  getall ECOSYSTEM | sed 's/^/   ecosystem: /'
  getall CWD_ENV_FILE | sed 's/^/   env file in cwd: /'
  getall NOTE | sed 's/^/   note: /'
  [ -n "$envf" ] || die "could not tell which env file pm2 loads. Look at how the app is started (above). If pm2 loads a file via an ecosystem file, rerun with --env-file <path>; if its env lives only in pm2, move it to a file loaded with node --env-file first."
  say "   env file:  $envf  (found from: $envsrc; mode $(get ENV_MODE), writable by the ssh user: $(get ENV_WRITABLE))"
  say "   in it now: BLOB_STORE=$(get FILE_BLOB_STORE) · DATA_DIR=$(get FILE_DATA_DIR) · PORT=$(get FILE_PORT) · S3 settings present: $(get FILE_S3_SET)"
  if [ -n "$(get FILE_SMTP_HOST)" ]; then say "   report email: $(get FILE_SMTP_HOST):$(get FILE_SMTP_PORT) as $(get FILE_SMTP_USER) to $(get FILE_REPORT_MAIL_TO) (names present: $(get FILE_SMTP_SET))"
  else say "   report email: off (no SMTP_HOST in the env file); step 4 offers to set it up"; fi
  say "   ALLOWED_ORIGINS: file '$(get FILE_ALLOWED_ORIGINS)' · pm2 '$(get PM2_ALLOWED_ORIGINS)'"
  [ "$(get CWD_HAS_SERVER)" = yes ] || die "$cwd has no src/server.js: is that really the bdrivex-api checkout?"
  [ "$(get ENV_WRITABLE)" = yes ] || die "the ssh user can't write $envf"
  case "$cwd$envf" in *"'"*) die "a path contains a single quote; this script won't quote it safely" ;; esac
  [ -z "$overrides" ] || die "pm2's own env sets $overrides, which would override the env file. Remove them from the pm2 app (ecosystem env block) first."
  [ "$mode" = fork_mode ] && [ "$inst" = 1 ] || die "the app runs as $mode × $inst; it must be pm2 fork mode with 1 instance (README). Convert it first: pm2 delete $name, then start it again with -i 1 and no cluster mode."
  [ -z "$(getall DEP_MISSING)" ] || die "the app dir has no node_modules for $(getall DEP_MISSING | tr '\n' ' ')"
  local v; for v in "$nodev" "$(get PATH_NODE_VERSION)"; do
    node -e 'const [a, b] = process.argv[1].replace(/^v/, "").split(".").map(Number); process.exit(a > 22 || (a === 22 && b >= 13) ? 0 : 1)' "$v" || die "node $v on the server (the app's, then the ssh PATH's, which runs tests and scripts); bdrivex-api needs 22.13+"
  done
  datadir=$(get PM2_DATA_DIR)   # pm2's own DATA_DIR wins over the file; empty = the file's, or <cwd>/data
  port=$(get PM2_PORT); port=${port:-$(get FILE_PORT)}; port=${port:-8787}
  local hhost; hhost=$(get PM2_HOST); hhost=${hhost:-$(get FILE_HOST)}
  case "$hhost" in '' | 0.0.0.0 | '::' | localhost) hhost=127.0.0.1 ;; esac
  local health="http://$hhost:$port/health"
  local datashow; datashow=${datadir:-$(get FILE_DATA_DIR)}; datashow=${datashow:-$cwd/data}
  local add_origins='' cur_origins; cur_origins=$(get PM2_ALLOWED_ORIGINS); cur_origins=${cur_origins:-$(get FILE_ALLOWED_ORIGINS)}
  if [ -n "$(get PM2_ALLOWED_ORIGINS)" ] && [[ "$(get PM2_ALLOWED_ORIGINS)" != *bstorex.com* ]]; then
    say "   note: pm2's env sets ALLOWED_ORIGINS without bstorex.com; this script can't change pm2's env. bstorex.com sign-in will need it."
  elif [ -n "$(get FILE_ALLOWED_ORIGINS)" ] && [[ "$(get FILE_ALLOWED_ORIGINS)" != *bstorex.com* ]]; then
    add_origins="$(get FILE_ALLOWED_ORIGINS),$BSTOREX_ORIGINS"
    say "   ALLOWED_ORIGINS in the env file lacks bstorex.com: after 'yes' it becomes $add_origins"
  fi

  local ts; ts=$(date +%Y%m%d-%H%M%S)
  local stage; stage="$(dirname "$cwd")/.bdrivex-api-stage-$ts"

  # ---- 2. back up the env file
  say ""; say "== 2. backing up the env file"
  remote backup-env "$envf" "$ts" || die "could not back up $envf"

  # ---- 3. stage the code
  say ""; say "== 3. staging the code in $stage (the live app dir is not touched)"
  local list; list=$(mktemp)
  git -C "$repo" ls-files >"$list"
  ssh -n -o BatchMode=yes "$HOST" "mkdir -p $(q "$stage/.test-site")"
  rsync -a --files-from="$list" "$repo/" "$HOST:$stage/"
  rsync -a "$list" "$HOST:$stage/.deploy-files"
  git -C "$SITE_DIR" ls-files js >"$list.site"
  rsync -a --files-from="$list.site" "$SITE_DIR/" "$HOST:$stage/.test-site/"
  rm -f "$list" "$list.site"
  remote prepare-stage "$cwd" "$stage" || die "could not prepare the staging dir"

  # ---- 4. the keys, typed on the server
  say ""; say "== 4. S3 keys (typed on the server, hidden)"
  ssh -t "$HOST" "bash $(q "$stage/scripts/deploy-s3.sh") --remote set-keys $(q "$envf")" || die "the keys were not written"

  # ---- 5. tests on the server
  say ""; say "== 5. tests on the server (staging dir)"
  remote test "$stage" || die "tests failed on the server; nothing switched. Logs: $stage/.test-logs"

  # ---- 6. bucket check and dry run
  say ""; say "== 6. bucket check and migration dry run (live data, read-only except the probe object)"
  remote dryrun "$cwd" "$stage" "$envf" "$datadir" || die "the bucket check or dry run failed; nothing switched"
  if ssh -n -o BatchMode=yes "$HOST" "grep -qE '^(export )?SMTP_HOST=.+' $(q "$envf")"; then
    local mt; read -r -p "Send one test email (subject 'Report: test from bdrivex-api') to $REPORT_MAIL_TO_VALUE now? [y/N] " mt
    if [ "$mt" = y ] || [ "$mt" = Y ]; then remote mailtest "$cwd" "$stage" "$envf" "$datadir" || say "   the test email failed (above). Going live still works; reports are then only logged until SMTP is fixed."; fi
  fi

  # ---- 7. go live
  local rollback="ssh $HOST 'cp -p $envf.bak-$ts $envf && rsync -a $cwd.code-bak-$ts/ $cwd/ && pm2 restart $pmid'"
  say ""; say "== 7. ready to switch $name to the bucket $S3_BUCKET_VALUE"
  say "   After 'yes': copy blobs, back up the code to $cwd.code-bak-$ts, copy the new code, set BLOB_STORE=s3, restart, health check, copy stragglers."
  local answer; read -r -p "Type yes to go live (anything else stops here): " answer
  if [ "$answer" != yes ]; then
    say "Stopped. The app runs as before (BLOB_STORE unchanged). The env file now holds the S3 settings; backup: $envf.bak-$ts"
    say "Staging dir left at $HOST:$stage (remove it with: ssh $HOST 'rm -rf $stage')"
    exit 0
  fi
  remote golive "$cwd" "$stage" "$envf" "$datadir" "$pmid" "$ts" "$health" "$add_origins" || { say "Go-live step failed. Roll back with:"; say "  $rollback"; exit 1; }
  say ""
  if curl -fsS --max-time 10 https://files.bdrivex.com/health >/dev/null 2>&1; then say "https://files.bdrivex.com/health answers ok from here."
  else say "WARNING: https://files.bdrivex.com/health did not answer ok from here. Check nginx/caddy and: ssh $HOST pm2 logs $pmid"; fi
  say ""
  say "Done. Rollback (env file and code back to before; blobs uploaded since the switch stay only in the bucket):"
  say "  $rollback"
  say "Run the migration again any time:  ssh $HOST 'cd $cwd && ${datadir:+DATA_DIR=$datadir }node --env-file=$envf scripts/migrate-blobs-to-s3.mjs'"
  say "Keep $datashow/blobs until downloads are checked; remove it by hand later. Staging dir (safe to remove): $stage"
}

if [ "${1:-}" = --remote ]; then shift; remote_main "$@"; exit $?; fi
local_main "$@"
