// Dev only: sign in to a local API with a throwaway key, as a page on ORIGIN would, and print the session JSON
// (for localStorage 'bdx:session' when testing /send without a wallet to hand).
//   node scripts/dev-session.mjs [api] [origin]
import { PrivateKey, ProtoWallet } from '@bsv/sdk';

const [api = 'http://127.0.0.1:8787', origin = 'http://127.0.0.1:5173'] = process.argv.slice(2);
const w = new ProtoWallet(PrivateKey.fromRandom());
const { publicKey: identityKey } = await w.getPublicKey({ identityKey: true });
const post = async (p, b) => {
  const r = await fetch(api + p, { method: 'POST', headers: { 'content-type': 'application/json', origin }, body: JSON.stringify(b) });
  if (!r.ok) throw new Error(`${p}: ${r.status} ${await r.text()}`);
  return r.json();
};
const ch = await post('/v1/auth/challenge', { identityKey });
const { signature } = await w.createSignature({ protocolID: ch.protocolID, keyID: ch.keyID, counterparty: 'anyone', data: Array.from(new TextEncoder().encode(ch.message)) });
console.log(JSON.stringify(await post('/v1/auth/verify', { identityKey, nonce: ch.nonce, signature: Array.from(signature) })));
