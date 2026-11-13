// Report emails: a minimal SMTP client (node:net / node:tls, no dependencies) and an in-process queue that tells
// support@bwalletx.com when a link is reported. Owner, Nov 2026: one mailbox, support@bwalletx.com (Fasthosts); the
// subject starts "Report:" (the REPORTS filter keys on it); the body is ONLY the link ID, the file hash prefix
// (12 hex), the reason and the time (UTC ISO). Never file content, names, the reporter's IP, or any key.
//
// Env: SMTP_HOST, SMTP_PORT (465 = TLS from the start; anything else = STARTTLS, required), SMTP_USER, SMTP_PASS,
// SMTP_FROM (default SMTP_USER), REPORT_MAIL_TO (default support@bwalletx.com), REPORT_MAIL_PER_HOUR (30),
// SMTP_CA_FILE and SMTP_TLS_SERVERNAME (a private CA and the name on its certificate: for tests). No SMTP_HOST: mail is off and the server only logs.
import net from 'node:net';
import tls from 'node:tls';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { hostname } from 'node:os';

const ADDR = /^[^\s<>"',;:\\@]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;

/** SMTP settings from env: null when SMTP_HOST is unset; throws on a half-done setting (the caller logs it). */
export function smtpConfigFromEnv(env) {
  if (!env.SMTP_HOST) return null;
  const port = Number(env.SMTP_PORT || 465);
  const cfg = {
    host: env.SMTP_HOST, port, secure: port === 465 || env.SMTP_SECURE === '1',
    user: env.SMTP_USER || '', pass: env.SMTP_PASS || '',
    from: env.SMTP_FROM || env.SMTP_USER || '', to: env.REPORT_MAIL_TO || 'support@bwalletx.com',
    ca: env.SMTP_CA_FILE ? readFileSync(env.SMTP_CA_FILE) : undefined,
    servername: env.SMTP_TLS_SERVERNAME || env.SMTP_HOST,
    timeoutMs: Number(env.SMTP_TIMEOUT_MS || 20_000),
  };
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('SMTP_PORT must be a port number.');
  if (!cfg.user || !cfg.pass) throw new Error('SMTP_USER and SMTP_PASS are required with SMTP_HOST.');
  if (!ADDR.test(cfg.from)) throw new Error('SMTP_FROM (or SMTP_USER) must be an email address.');
  if (!ADDR.test(cfg.to)) throw new Error('REPORT_MAIL_TO must be an email address.');
  return cfg;
}

/** Send one plain-text email. Resolves when the server has accepted it (250 after DATA); rejects otherwise. */
export function sendMail(cfg, { subject, text, date = new Date() }) {
  if (/[\r\n]/.test(subject)) return Promise.reject(new Error('subject has a line break'));
  return new Promise((resolve, reject) => {
    let sock, buf = '', waiter = null, done = false;
    const finish = (err) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock?.removeAllListeners('data');
      if (err) sock?.destroy(); else sock?.end();
      err ? reject(err) : resolve();
    };
    const timer = setTimeout(() => finish(new Error(`SMTP timed out after ${cfg.timeoutMs} ms`)), cfg.timeoutMs);
    const onData = (d) => {
      buf += d.toString('latin1');
      // A reply is complete when a line has "NNN " (a space, not "-") after the code.
      const m = /(?:^|\r\n)(\d{3}) [^\r\n]*\r\n$/.exec(buf);
      if (!m || !waiter) return;
      const reply = { code: Number(m[1]), text: buf };
      buf = '';
      const w = waiter; waiter = null; w(reply);
    };
    const attach = (s) => {
      sock = s;
      s.on('data', onData);
      s.on('error', (e) => finish(new Error(`SMTP ${cfg.host}:${cfg.port}: ${e.message}`)));
      s.on('close', () => finish(new Error('SMTP connection closed early')));
    };
    const read = () => new Promise((r) => { waiter = r; if (buf) onData(Buffer.alloc(0)); });
    const cmd = async (line, want, label = line.split(' ')[0]) => {
      if (line != null) sock.write(line + '\r\n');
      const r = await read();
      if (!want.includes(r.code)) throw new Error(`SMTP ${label}: ${r.text.trim().split('\r\n').at(-1).slice(0, 200)}`);
      return r;
    };
    const tlsOpts = { servername: cfg.servername || cfg.host, ca: cfg.ca, minVersion: 'TLSv1.2' };
    const helo = `bdrivex-api.${hostname().replace(/[^A-Za-z0-9.-]/g, '') || 'localhost'}`;
    (async () => {
      attach(cfg.secure ? tls.connect({ host: cfg.host, port: cfg.port, ...tlsOpts }) : net.connect({ host: cfg.host, port: cfg.port }));
      await cmd(null, [220], 'greeting');
      let ehlo = await cmd(`EHLO ${helo}`, [250]);
      if (!cfg.secure) {
        // Never send the password in the clear: STARTTLS is required on a non-TLS port.
        if (!/[\r\n-]STARTTLS\b/i.test('\n' + ehlo.text)) throw new Error('SMTP server offers no STARTTLS on a non-TLS port; refusing to send the password in the clear');
        await cmd('STARTTLS', [220]);
        sock.removeAllListeners('data'); sock.removeAllListeners('error'); sock.removeAllListeners('close');
        const plain = sock;
        await new Promise((ok, no) => { const t = tls.connect({ socket: plain, ...tlsOpts }, ok); t.once('error', no); attach(t); });
        ehlo = await cmd(`EHLO ${helo}`, [250]);
      }
      if (/AUTH[ =][^\r\n]*\bPLAIN\b/i.test(ehlo.text)) {
        await cmd(`AUTH PLAIN ${Buffer.from(`\0${cfg.user}\0${cfg.pass}`).toString('base64')}`, [235], 'AUTH');
      } else {
        await cmd('AUTH LOGIN', [334], 'AUTH');
        await cmd(Buffer.from(cfg.user).toString('base64'), [334], 'AUTH');
        await cmd(Buffer.from(cfg.pass).toString('base64'), [235], 'AUTH');
      }
      await cmd(`MAIL FROM:<${cfg.from}>`, [250]);
      await cmd(`RCPT TO:<${cfg.to}>`, [250, 251]);
      await cmd('DATA', [354]);
      const domain = cfg.from.split('@')[1];
      const body = Buffer.from(text.replace(/\r?\n/g, '\r\n'), 'utf8').toString('base64').replace(/.{76}/g, '$&\r\n');
      const msg = [
        `From: bDriveX reports <${cfg.from}>`, `To: <${cfg.to}>`, `Subject: ${subject}`, `Date: ${date.toUTCString().replace('GMT', '+0000')}`,
        `Message-ID: <${randomBytes(12).toString('hex')}@${domain}>`, 'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: base64', '', body,
      ].join('\r\n');
      // base64 lines never start with ".", so no dot-stuffing is needed; the terminator follows.
      await cmd(`${msg}\r\n.`, [250], 'DATA');
      sock.write('QUIT\r\n');
      finish();
    })().catch(finish);
  });
}

// One line: control characters (line breaks too) become spaces, so a reason can't add lines that look like fields.
const clean = (s, n) => String(s ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, n);

/** The email for one report. Only these four facts, by design. */
export function reportMail({ linkId, hash, reason, at }) {
  const h12 = String(hash).slice(0, 12);
  return {
    subject: `Report: link ${linkId} (file ${h12})`,
    text: `Link: ${linkId}\nFile: ${h12}\nReason: ${clean(reason, 500) || '(none given)'}\nTime: ${new Date(at).toISOString()}\n`,
  };
}

/**
 * The queue. report() never throws and never waits: mail goes out in the background, retried with backoff
 * (retryMs, doubling, up to an hour, `tries` attempts). At most perHour report emails per window; the rest are counted
 * and one summary email follows when the window ends. Held in memory: a restart drops unsent mail (the REPORT log
 * line and scripts/legal-hold.mjs list still have every report).
 */
export function createReportMailer({ cfg, perHour = 30, windowMs = 3600_000, retryMs = 60_000, tries = 8, maxQueue = 500, send = sendMail, log = console }) {
  const queue = [];
  let win = { start: Date.now(), sent: 0, held: 0, first: null, last: null };
  let busy = false;
  const stats = { sent: 0, failed: 0, dropped: 0, summarised: 0 };
  const push = (mail) => {
    if (queue.length >= maxQueue) { stats.dropped++; log.error(`[bdrivex] report mail queue full (${maxQueue}); dropped: ${mail.subject}`); return; }
    queue.push({ ...mail, attempt: 0, nextAt: 0 });
  };
  const roll = (t) => {
    if (t - win.start < windowMs) return;
    if (win.held) {
      stats.summarised += win.held;
      push({
        subject: `Report: ${win.held} more report${win.held === 1 ? '' : 's'} not mailed one by one`,
        text: `More reports: ${win.held}\nFirst: ${new Date(win.first).toISOString()}\nLast: ${new Date(win.last).toISOString()}\nMailed one by one this hour: ${win.sent} (limit ${perHour})\nAll of them: scripts/legal-hold.mjs list\n`,
      });
      win = { start: t, sent: 1, held: 0, first: null, last: null };
    } else win = { start: t, sent: 0, held: 0, first: null, last: null };
  };
  async function pump() {
    if (busy || !cfg) return;
    busy = true;
    try {
      roll(Date.now());
      for (const m of [...queue]) {
        if (m.nextAt > Date.now()) continue;
        try {
          await send(cfg, m);
          queue.splice(queue.indexOf(m), 1);
          stats.sent++;
          log.log(`[bdrivex] report mail sent to ${cfg.to}: ${m.subject}`);
        } catch (e) {
          m.attempt++;
          if (m.attempt >= tries) {
            queue.splice(queue.indexOf(m), 1);
            stats.failed++;
            log.error(`[bdrivex] report mail GAVE UP after ${tries} tries (${e.message}): ${m.subject}`);
          } else {
            m.nextAt = Date.now() + Math.min(retryMs * 2 ** (m.attempt - 1), 3600_000);
            log.error(`[bdrivex] report mail failed (try ${m.attempt} of ${tries}, again later): ${e.message}`);
          }
        }
      }
    } finally { busy = false; }
  }
  const timer = cfg ? setInterval(() => pump().catch(() => {}), Math.min(retryMs, windowMs, 60_000)) : null;
  timer?.unref();
  return {
    enabled: !!cfg,
    describe: () => (cfg ? `report mail to ${cfg.to} via ${cfg.host}:${cfg.port}` : 'report mail off (no SMTP_HOST)'),
    stats, queue,
    report(r) {
      if (!cfg) return;
      try {
        const t = Date.now();
        roll(t);
        if (win.sent < perHour) { win.sent++; push(reportMail(r)); }
        else { win.held++; win.first ??= r.at; win.last = r.at; }
        setImmediate(() => pump().catch(() => {}));
      } catch (e) { log.error(`[bdrivex] report mail: ${e.message}`); }
    },
    pump,
    stop: () => timer && clearInterval(timer),
  };
}
