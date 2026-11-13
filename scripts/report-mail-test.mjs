// Send one test report email with the API's SMTP settings, to check them (and the "Report:" mail filter).
//   cd <app dir> && node --env-file=<env file> scripts/report-mail-test.mjs
// It goes to REPORT_MAIL_TO (default support@bwalletx.com), subject "Report: test from bdrivex-api". Never prints the
// password. Exit 0 sent, 1 failed, 2 SMTP not configured.
import { smtpConfigFromEnv, sendMail } from '../src/mail.js';

let cfg;
try { cfg = smtpConfigFromEnv(process.env); } catch (e) { console.error(`[report-mail-test] ${e.message}`); process.exit(2); }
if (!cfg) { console.error('[report-mail-test] no SMTP_HOST in the env: report mail is off'); process.exit(2); }
try {
  await sendMail(cfg, {
    subject: 'Report: test from bdrivex-api',
    text: `Link: (test)\nFile: (test)\nReason: a test from scripts/report-mail-test.mjs\nTime: ${new Date().toISOString()}\n`,
  });
  console.log(`[report-mail-test] sent to ${cfg.to} via ${cfg.host}:${cfg.port} as ${cfg.user}`);
} catch (e) {
  console.error(`[report-mail-test] FAILED via ${cfg.host}:${cfg.port}: ${e.message}`);
  process.exit(1);
}
