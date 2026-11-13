// Report emails: the SMTP client against a fake SMTP server (TLS and STARTTLS, a self-signed certificate made with
// openssl), the message shape (nothing but link ID, hash prefix, reason, time), retries, and the hourly cap.
//   node test/mail.mjs
import { smtpConfigFromEnv, sendMail, reportMail, createReportMailer } from '../src/mail.js';
import { startFakeSmtp } from './fake-smtp.mjs';

let failures = 0;
const ok = (cond, what) => { console.log(`${cond ? '  ok ' : '  FAIL'} ${what}`); if (!cond) failures++; };
const rejects = async (p, re, what) => { try { await p; ok(false, `${what} (did not fail)`); } catch (e) { ok(re.test(e.message), `${what}: ${e.message}`); } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (fn, ms = 4000) => { for (let i = 0; i < ms / 50 && !fn(); i++) await sleep(50); return fn(); };
const quiet = { log() {}, error() {} };

console.log('config');
ok(smtpConfigFromEnv({}) === null, 'no SMTP_HOST: mail is off');
const env = (port, extra = {}) => ({ SMTP_HOST: '127.0.0.1', SMTP_PORT: String(port), SMTP_USER: 'support@bwalletx.com', SMTP_PASS: 'test-pass', SMTP_TLS_SERVERNAME: 'localhost', ...extra });
let c = smtpConfigFromEnv(env(465, { SMTP_CA_FILE: undefined }));
ok(c.to === 'support@bwalletx.com' && c.from === 'support@bwalletx.com' && c.secure === true, 'defaults: to support@bwalletx.com, from SMTP_USER, port 465 is TLS');
ok(smtpConfigFromEnv(env(587)).secure === false, 'port 587: STARTTLS');
await rejects((async () => smtpConfigFromEnv({ SMTP_HOST: 'x', SMTP_USER: 'a@b.co' }))(), /SMTP_PASS/, 'a host without a password is refused');
await rejects((async () => smtpConfigFromEnv(env(465, { REPORT_MAIL_TO: 'x@y.com\r\nBcc: z@w.com' })))(), /REPORT_MAIL_TO/, 'an address with a line break is refused');

console.log('message shape');
const r = { linkId: 'AbCdEfGhIjKlMnOpQrStUv', hash: 'deadbeefcafe' + '0'.repeat(52), reason: 'illegal\r\nBcc: evil@example.com\u0000', at: Date.UTC(2026, 10, 13, 18, 0, 0) };
const m = reportMail(r);
ok(m.subject === 'Report: link AbCdEfGhIjKlMnOpQrStUv (file deadbeefcafe)', `subject: ${m.subject}`);
ok(m.text === 'Link: AbCdEfGhIjKlMnOpQrStUv\nFile: deadbeefcafe\nReason: illegal  Bcc: evil@example.com \nTime: 2026-11-13T18:00:00.000Z\n', 'body: link, 12-hex file prefix, reason (control characters blanked), UTC time, nothing else');
ok(!m.text.includes('0'.repeat(52)), 'never the full hash');

for (const mode of ['tls', 'starttls']) {
  console.log(`SMTP over ${mode}`);
  const s = await startFakeSmtp({ mode, users: { 'support@bwalletx.com': 'test-pass' } });
  const cfg = smtpConfigFromEnv(env(mode === 'tls' ? 465 : 2525, { SMTP_PORT: String(s.port), SMTP_SECURE: mode === 'tls' ? '1' : '0', SMTP_CA_FILE: s.caFile }));
  await sendMail(cfg, m);
  const got = s.messages[0];
  ok(got && got.secure && got.auth === 'support@bwalletx.com', `delivered over TLS after AUTH (${mode})`);
  ok(got.from === 'support@bwalletx.com' && got.to.length === 1 && got.to[0] === 'support@bwalletx.com', 'from and to support@bwalletx.com, one recipient');
  ok(got.subject.startsWith('Report:') && got.subject === m.subject && got.text.replace(/\r\n/g, '\n') === m.text, 'subject and body arrive as built');
  ok(!/^bcc:/im.test(got.raw.split('\r\n\r\n')[0]) && !got.headers.bcc, 'a line break in the reason cannot add a header');
  ok(!s.sessions.some((x) => x.lines.some((l) => l.includes('test-pass'))), 'the password never shows in the clear in the session');
  await rejects(sendMail({ ...cfg, pass: 'wrong' }, m), /AUTH/, 'bad credentials are an error');
  await s.close();
}
{
  const s = await startFakeSmtp({ mode: 'plain', users: { 'support@bwalletx.com': 'test-pass' } });
  await rejects(sendMail(smtpConfigFromEnv(env(2525, { SMTP_PORT: String(s.port) })), m), /no STARTTLS/, 'a server without STARTTLS on a non-TLS port is refused before AUTH');
  ok(!s.sessions.some((x) => x.lines.some((l) => /^AUTH/.test(l))), 'and no AUTH was sent');
  await s.close();
}
{
  const s = await startFakeSmtp({ mode: 'tls', users: {} });
  await rejects(sendMail({ ...smtpConfigFromEnv(env(465, { SMTP_PORT: String(s.port), SMTP_SECURE: '1', SMTP_TLS_SERVERNAME: 'localhost' })) }, m), /certificate|self.signed/i, 'a certificate it cannot verify is refused');
  await s.close();
}

console.log('queue: retries, never blocks');
{
  const s = await startFakeSmtp({ mode: 'tls', users: { 'support@bwalletx.com': 'test-pass' } });
  const cfg = smtpConfigFromEnv(env(465, { SMTP_PORT: String(s.port), SMTP_SECURE: '1', SMTP_CA_FILE: s.caFile }));
  const mailer = createReportMailer({ cfg, retryMs: 100, log: quiet });
  s.failNext('MAIL', 451, 2);
  const t0 = performance.now();
  mailer.report(r);
  ok(performance.now() - t0 < 20, 'report() returns at once');
  await until(() => s.messages.length === 1);
  ok(s.messages.length === 1 && mailer.stats.sent === 1, 'two temporary failures, then delivered by the retry');
  s.down(true);
  mailer.report({ ...r, linkId: 'B'.repeat(22) });
  await sleep(400);
  ok(mailer.queue.length === 1 && s.messages.length === 1, 'server down: the mail waits in the queue');
  s.down(false);
  await until(() => s.messages.length === 2, 8000);
  ok(s.messages.length === 2 && mailer.queue.length === 0, 'and goes when the server is back');
  mailer.stop();
  const gave = createReportMailer({ cfg: { ...cfg, pass: 'wrong' }, retryMs: 20, tries: 3, log: quiet });
  gave.report(r);
  await until(() => gave.stats.failed === 1);
  ok(gave.stats.failed === 1 && gave.queue.length === 0, 'it gives up after `tries` and drops the mail (the log line stays)');
  gave.stop();
  const off = createReportMailer({ cfg: null, log: quiet });
  off.report(r);
  ok(!off.enabled && off.queue.length === 0 && /off/.test(off.describe()), 'no SMTP settings: report() does nothing');

  console.log('queue: hourly cap and summary');
  const capped = createReportMailer({ cfg, perHour: 3, windowMs: 600, retryMs: 50, log: quiet });
  const before = s.messages.length;
  for (let i = 0; i < 7; i++) capped.report({ ...r, linkId: String(i).repeat(22), at: Date.now() });
  await until(() => s.messages.length === before + 3);
  await sleep(200);
  ok(s.messages.length === before + 3, '7 reports with a cap of 3: 3 emails in the window');
  await until(() => s.messages.length === before + 4, 3000);
  const sum = s.messages.at(-1);
  ok(s.messages.length === before + 4 && /^Report: 4 more reports not mailed one by one$/.test(sum.subject) && /More reports: 4/.test(sum.text), `then one summary when the window ends: ${sum?.subject}`);
  ok(!/0{22}|1{22}/.test(sum.text) && !/Reason/.test(sum.text), 'the summary has counts and times only');
  capped.stop();
  await s.close();
}

console.log(failures ? `\n${failures} FAILED` : '\nall passed');
process.exit(failures ? 1 : 0);
