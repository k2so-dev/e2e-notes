# e2e-notes

Browser-only encrypted notes. No server, no storage, no external requests. The build is a single self-contained `index.html`.

## Stack

Vite, Tailwind CSS 4, Alpine.js (CSP build), mlkem-wasm, Bun.

## Usage

```sh
bun install
bun run dev
bun run build     # dist/index.html
bun run preview
bun test
```

Serve `dist/index.html` over https or from localhost. WebCrypto is unavailable on plain http, and the app refuses to run in a frame.

## Offline

**Save offline copy** downloads the untouched markup, which runs from `file://` with no server. Do not use the browser's own *Save page as*: it serialises the live DOM, leaving expanded markup next to emptied `<template x-if>` elements, and the reopened file throws `Cannot set properties of null` instead of starting.

## Verify

Every tagged release ships `e2e-notes.html` and its `SHA256SUMS`. The build is reproducible, so a deployment built from the same commit serves the same bytes:

```sh
curl -sL https://example.com/ | sha256sum
```

The offline copy is re-serialised by the browser and hashes differently, even though it is the same code.

## Flow

1. Generate a key pair and share the public key. Compare fingerprints over a trusted channel.
2. **Encrypt**: paste the recipient public key, write the note, copy the result.
3. **Decrypt**: paste the sender public key and the encrypted note.

Export writes the private keys to `e2e-identity.json`. With a passphrase set, the file is encrypted with PBKDF2-SHA256 (600k iterations) and AES-256-GCM; without one, the keys are written in the clear.

## Crypto

Hybrid ECIES: post-quantum confidentiality, classical authentication. The message key is derived from an ML-KEM-768 secret, an ephemeral X25519 secret and a static sender-recipient X25519 secret, so a note decrypts only for that pair of keys and stays confidential if either X25519 or ML-KEM falls.

```
pub        = x25519Public[32] | mlkemPublic[1184]
epk        = generateKey(X25519)
ct, ssK    = ML-KEM-768.Encaps(recipientMlkemPublic)
ssE        = ECDH(epkPrivate, recipientX25519Public)
ssS        = ECDH(senderX25519Private, recipientX25519Public)
key        = HKDF-SHA256(ssK | ssE | ssS | epkPublic | senderX25519Public | recipientX25519Public, salt, info="e2e-note-v3")
header     = "E2E3" | epkPublic[32] | ct[1088] | salt[16] | iv[12]
padded     = plaintext | 0x80 | 0x00… to a multiple of 256 bytes
ciphertext = AES-256-GCM(key, iv, padded, aad = header | senderPublic | recipientPublic)
payload    = base64(header | ciphertext)
```

The recipient decapsulates `ct` and derives the same key from `ECDH(recipientPrivate, epkPublic)` and `ECDH(recipientPrivate, senderPublic)`. Padding hides the note length up to 256-byte blocks.

Public keys are raw 1216 bytes in base64; the fingerprint is the first 16 bytes of their SHA-256. Non-canonical X25519 encodings are rejected, ML-KEM keys are validated on encapsulation. Payloads must be canonical base64. Identity files are trusted for the private material only: both public keys are re-derived on import. Notes and identities from earlier versions are not readable.

ML-KEM comes from [mlkem-wasm](https://github.com/dchest/mlkem-wasm), a WebAssembly build of mlkem-native; everything else is WebCrypto.

## Security notes

- The private key lives in memory only and is lost on reload. Export it to keep it.
- Authentication is only as strong as the key exchange: verify fingerprints over a trusted channel.
- Authentication is deniable. The recipient can forge any note addressed to them, so it proves authorship to the recipient, not to a third party.
- Authentication is classical. A quantum adversary could forge new notes, but cannot read captured ones.
- The sender cannot read a note back after sending it: the ephemeral key is discarded.
- Replay is not prevented. A captured note stays decryptable and can be resent.
- The inline CSP allows only the bundled script by SHA-256 hash and `wasm-unsafe-eval` for ML-KEM; `connect-src 'none'` blocks exfiltration. `frame-ancestors` cannot be set from a meta tag, so framing is refused in script instead.
- Requires X25519 in WebCrypto: Chrome 133+, Firefox 132+, Safari 17.4+.
