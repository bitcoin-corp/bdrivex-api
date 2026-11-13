// A small fake SMTP server for the tests: TLS from the start (like port 465) or STARTTLS (like 587), AUTH PLAIN and
// LOGIN, a self-signed certificate made with openssl, scripted failures. It records every message it accepts.
//   const s = await startFakeSmtp({ mode: 'tls' | 'starttls' | 'plain', users: { user: 'pass' } })
//   -> { port, caFile, messages, sessions, failNext(stage, code, times), down(bool), close() }
import net from 'node:net';
import tls from 'node:tls';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export function makeCert() {
  const dir = mkdtempSync(join(tmpdir(), 'bdrivex-smtp-cert-'));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem'),
    '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' });
  return { dir, key: readFileSync(join(dir, 'key.pem')), cert: readFileSync(join(dir, 'cert.pem')), caFile: join(dir, 'cert.pem') };
}

export async function startFakeSmtp({ mode = 'tls', users = {} } = {}) {
  const cert = makeCert();
  const messages = [], sessions = [], fails = [];
  let isDown = false;
  const failFor = (stage) => {
    const f = fails.find((x) => x.stage === stage && x.times > 0);
    if (!f) return null;
    f.times--;
    return f.code;
  };
  function serve(sock, secure) {
    const sess = { secure, auth: null, from: null, to: [], lines: [] };
    sessions.push(sess);
    let buf = '', inData = false, data = [], authStep = null, authUser = '';
    const say = (s) => sock.write(s + '\r\n');
    const onLine = (line) => {
      if (inData) {
        if (line === '.') {
          inData = false;
          const raw = data.join('\r\n');
          const code = failFor('DATA');
          if (code) return say(`${code} not now`);
          const [head, ...rest] = raw.split('\r\n\r\n');
          const headers = Object.fromEntries(head.split('\r\n').map((h) => [h.slice(0, h.indexOf(':')).toLowerCase(), h.slice(h.indexOf(':') + 1).trim()]));
          const body = rest.join('\r\n\r\n');
          const text = /base64/i.test(headers['content-transfer-encoding'] || '') ? Buffer.from(body.replace(/\s+/g, ''), 'base64').toString('utf8') : body;
          messages.push({ from: sess.from, to: [...sess.to], auth: sess.auth, secure: sess.secure, raw, headers, subject: headers.subject, text });
          return say('250 queued');
        }
        data.push(line.startsWith('..') ? line.slice(1) : line);
        return;
      }
      sess.lines.push(line.startsWith('AUTH PLAIN') ? 'AUTH PLAIN …' : line);
      if (authStep === 'user') { authUser = Buffer.from(line, 'base64').toString(); authStep = 'pass'; return say('334 UGFzc3dvcmQ6'); }
      if (authStep === 'pass') {
        authStep = null;
        const pass = Buffer.from(line, 'base64').toString();
        if (users[authUser] === pass && !failFor('AUTH')) { sess.auth = authUser; return say('235 ok'); }
        return say('535 bad credentials');
      }
      const verb = line.split(' ')[0].toUpperCase();
      if (verb === 'EHLO') {
        const caps = ['250-fake.smtp', ...(mode === 'starttls' && !sess.secure ? ['250-STARTTLS'] : []), '250-AUTH PLAIN LOGIN', '250 8BITMIME'];
        return sock.write(caps.join('\r\n') + '\r\n');
      }
      if (verb === 'STARTTLS' && mode === 'starttls' && !sess.secure) {
        say('220 go ahead');
        sock.removeAllListeners('data');
        const t = new tls.TLSSocket(sock, { isServer: true, key: cert.key, cert: cert.cert });
        sessions.pop();
        serve(t, true);
        return;
      }
      if (verb === 'AUTH') {
        if (!sess.secure) return say('538 encryption required');
        const [, mech, arg] = line.split(' ');
        if (/^PLAIN$/i.test(mech)) {
          const [, u, p] = Buffer.from(arg || '', 'base64').toString().split('\0');
          if (users[u] === p && !failFor('AUTH')) { sess.auth = u; return say('235 ok'); }
          return say('535 bad credentials');
        }
        if (/^LOGIN$/i.test(mech)) { authStep = 'user'; return say('334 VXNlcm5hbWU6'); }
        return say('504 no such mechanism');
      }
      if (verb === 'MAIL') { if (!sess.auth) return say('530 auth first'); const c = failFor('MAIL'); if (c) return say(`${c} try later`); sess.from = /<([^>]*)>/.exec(line)?.[1]; return say('250 ok'); }
      if (verb === 'RCPT') { sess.to.push(/<([^>]*)>/.exec(line)?.[1]); return say('250 ok'); }
      if (verb === 'DATA') { inData = true; data = []; return say('354 go'); }
      if (verb === 'QUIT') { say('221 bye'); return sock.end(); }
      return say('502 unknown');
    };
    sock.on('data', (d) => {
      buf += d.toString('utf8');
      let i;
      while ((i = buf.indexOf('\r\n')) >= 0) { const line = buf.slice(0, i); buf = buf.slice(i + 2); onLine(line); }
    });
    sock.on('error', () => {});
    if (!secure || mode === 'tls') say('220 fake.smtp ready');
  }
  const onConn = (sock, secure) => { if (isDown) return sock.destroy(); serve(sock, secure); };
  const server = mode === 'tls'
    ? tls.createServer({ key: cert.key, cert: cert.cert }, (s) => onConn(s, true))
    : net.createServer((s) => onConn(s, false));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return {
    port: server.address().port, caFile: cert.caFile, messages, sessions,
    failNext: (stage, code, times = 1) => fails.push({ stage, code, times }),
    down: (v) => { isDown = v; },
    close: () => new Promise((r) => { server.close(() => r()); rmSync(cert.dir, { recursive: true, force: true }); }),
  };
}
