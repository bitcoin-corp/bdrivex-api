# bdrivex-api

Storage API behind bdrivex.com. It holds **opaque ciphertext only**: files are sealed in the browser (BDX1 format,
`bdrivex-site/js/bdx-crypto.js`: AES-256-GCM in 1 MiB segments, one random key per file) and the key travels in the
share link's `#fragment`, which browsers never send to a server.

- **Sign in with bWalletX**: `@bwalletx/connect` challenge, signed by the wallet's identity key, verified here, traded
  for a 30-day bearer token bound to the page's origin. No passwords.
- **Resumable uploads** (tus-style offsets, chunks up to 32 MB), re-hashed on completion and stored under the
  sha256 of the ciphertext. `PUT /v1/blobs/:sha256` for small blobs (bPhotosX).
- **Share links**: random ids, optional expiry, revocable, public ciphertext download with Range support.
- Metadata in SQLite (`node:sqlite`, Node 22.13+), blobs as files in `DATA_DIR/blobs/aa/bb/<sha256>`.

The route list is at the top of `src/server.js`.

```sh
pnpm install
pnpm dev                          # http://127.0.0.1:8787, data in ./data, dev origins 127.0.0.1:5173
pnpm test [file]                  # end to end with the site's client code (sign in, upload, resume, link, download)
node scripts/dev-session.mjs      # a throwaway-key session for testing /send without a wallet
```
