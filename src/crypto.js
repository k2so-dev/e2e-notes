import mlkem from 'mlkem-wasm'

const ALG = { name: 'X25519' }
const KEM = 'ML-KEM-768'
const MAGIC = new Uint8Array([0x45, 0x32, 0x45, 0x33])
const INFO = new TextEncoder().encode('e2e-note-v3')
const X_PUB_LEN = 32
const KEM_PUB_LEN = 1184
const KEM_CT_LEN = 1088
const KEM_SEED_LEN = 64
const PUB_LEN = X_PUB_LEN + KEM_PUB_LEN
const SALT_LEN = 16
const IV_LEN = 12
const TAG_LEN = 16
const BLOCK_LEN = 256
const FINGERPRINT_LEN = 16
const HEADER_LEN = MAGIC.length + X_PUB_LEN + KEM_CT_LEN + SALT_LEN + IV_LEN
const KDF_ITERATIONS = 600000
const KDF_MAX_ITERATIONS = 10000000

const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true })

export function toBase64(bytes) {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}

export function normalizeBase64(text) {
  const normalized = String(text)
    .replace(/\s+/g, '')
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .replace(/=+$/, '')
  if (!normalized || normalized.length % 4 === 1 || !/^[A-Za-z0-9+/]+$/.test(normalized)) {
    throw new Error('Invalid base64')
  }
  return normalized + '='.repeat((4 - (normalized.length % 4)) % 4)
}

export function fromBase64(text) {
  const s = atob(normalizeBase64(text))
  const bytes = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i)
  return bytes
}

export function environment() {
  if (window.top !== window.self) return 'framed'
  if (!window.isSecureContext || !window.crypto?.subtle) return 'insecure'
  return 'ok'
}

export async function isSupported() {
  try {
    await crypto.subtle.generateKey(ALG, true, ['deriveBits'])
    await mlkem.generateKey(KEM, true, ['encapsulateBits', 'decapsulateBits'])
    return true
  } catch {
    return false
  }
}

export async function generateIdentity() {
  const pair = await crypto.subtle.generateKey(ALG, true, ['deriveBits'])
  const kemPair = await mlkem.generateKey(KEM, true, ['encapsulateBits', 'decapsulateBits'])
  return buildIdentity(pair.privateKey, kemPair.privateKey)
}

export async function exportIdentity(identity, passphrase) {
  const key = {
    x: await crypto.subtle.exportKey('jwk', identity.privateKey),
    kem: toBase64(new Uint8Array(await mlkem.exportKey('raw-seed', identity.kemPrivateKey)))
  }
  if (!passphrase) return { v: 3, alg: 'X25519+ML-KEM-768', key }

  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN))
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN))
  const aes = await passphraseKey(passphrase, salt, KDF_ITERATIONS)
  const data = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aes, encoder.encode(JSON.stringify(key)))
  )
  return {
    v: 3,
    alg: 'X25519+ML-KEM-768',
    kdf: 'PBKDF2-SHA256',
    iterations: KDF_ITERATIONS,
    salt: toBase64(salt),
    iv: toBase64(iv),
    data: toBase64(data)
  }
}

export function isEncryptedIdentity(data) {
  return Boolean(data && typeof data === 'object' && data.data)
}

export async function importIdentity(data, passphrase) {
  if (!data || data.alg !== 'X25519+ML-KEM-768') throw new Error('Invalid identity file')

  let key = data.key
  if (isEncryptedIdentity(data)) {
    if (!passphrase) throw new Error('Passphrase required')
    const iterations = Number(data.iterations)
    if (!Number.isInteger(iterations) || iterations < 1 || iterations > KDF_MAX_ITERATIONS) {
      throw new Error('Invalid identity file')
    }
    try {
      const aes = await passphraseKey(passphrase, fromBase64(data.salt), iterations)
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: fromBase64(data.iv) },
        aes,
        fromBase64(data.data)
      )
      key = JSON.parse(decoder.decode(plaintext))
    } catch {
      throw new Error('Wrong passphrase')
    }
  }
  if (!key || typeof key !== 'object') throw new Error('Invalid identity file')

  let privateKey, kemPrivateKey
  try {
    privateKey = await crypto.subtle.importKey('jwk', key.x, ALG, true, ['deriveBits'])
    const seed = fromBase64(key.kem)
    if (seed.length !== KEM_SEED_LEN) throw new Error()
    kemPrivateKey = await mlkem.importKey('raw-seed', seed, KEM, true, ['decapsulateBits'])
  } catch {
    throw new Error('Invalid identity file')
  }
  return buildIdentity(privateKey, kemPrivateKey)
}

export async function fingerprint(publicKey) {
  return formatFingerprint(parsePublicKey(publicKey, 'Invalid public key'))
}

export async function encrypt(identity, recipientPublicKey, message) {
  const plaintext = encodeText(message)
  const recipientBytes = parsePublicKey(recipientPublicKey, 'Invalid recipient key')
  const recipient = await importPublicKey(recipientBytes, 'Invalid recipient key')
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN))
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN))

  let ephemeral, ephemeralPublic
  try {
    ephemeral = await crypto.subtle.generateKey(ALG, true, ['deriveBits'])
    ephemeralPublic = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey))
  } catch {
    throw new Error('Encryption failed')
  }

  let key, kemCiphertext
  try {
    const encapsulated = await mlkem.encapsulateBits(KEM, recipient.kem)
    kemCiphertext = new Uint8Array(encapsulated.ciphertext)
    key = await deriveKey(
      [
        new Uint8Array(encapsulated.sharedKey),
        await agree(ephemeral.privateKey, recipient.x),
        await agree(identity.privateKey, recipient.x),
        ephemeralPublic,
        identity.publicKeyBytes.subarray(0, X_PUB_LEN),
        recipientBytes.subarray(0, X_PUB_LEN)
      ],
      salt
    )
  } catch {
    throw new Error('Invalid recipient key')
  }

  const header = concat(MAGIC, ephemeralPublic, kemCiphertext, salt, iv)
  try {
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv,
          additionalData: concat(header, identity.publicKeyBytes, recipientBytes)
        },
        key,
        pad(plaintext)
      )
    )
    return toBase64(concat(header, ciphertext))
  } catch {
    throw new Error('Encryption failed')
  }
}

export async function decrypt(identity, senderPublicKey, payloadBase64) {
  const senderBytes = parsePublicKey(senderPublicKey, 'Invalid sender key')

  let payload
  try {
    const canonical = normalizeBase64(payloadBase64)
    payload = fromBase64(canonical)
    if (toBase64(payload) !== canonical) throw new Error('Malformed message')
  } catch {
    throw new Error('Malformed message')
  }
  const body = payload.length - HEADER_LEN - TAG_LEN
  if (body < BLOCK_LEN || body % BLOCK_LEN !== 0 || !MAGIC.every((b, i) => payload[i] === b)) {
    throw new Error('Malformed message')
  }

  const header = payload.subarray(0, HEADER_LEN)
  let offset = MAGIC.length
  const ephemeralPublic = payload.subarray(offset, (offset += X_PUB_LEN))
  const kemCiphertext = payload.subarray(offset, (offset += KEM_CT_LEN))
  const salt = payload.subarray(offset, (offset += SALT_LEN))
  const iv = payload.subarray(offset, HEADER_LEN)
  const ciphertext = payload.subarray(HEADER_LEN)

  try {
    const ephemeral = await crypto.subtle.importKey('raw', ephemeralPublic, ALG, false, [])
    const sender = await crypto.subtle.importKey('raw', senderBytes.subarray(0, X_PUB_LEN), ALG, false, [])
    const key = await deriveKey(
      [
        new Uint8Array(await mlkem.decapsulateBits(KEM, identity.kemPrivateKey, kemCiphertext)),
        await agree(identity.privateKey, ephemeral),
        await agree(identity.privateKey, sender),
        ephemeralPublic,
        senderBytes.subarray(0, X_PUB_LEN),
        identity.publicKeyBytes.subarray(0, X_PUB_LEN)
      ],
      salt
    )
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: concat(header, senderBytes, identity.publicKeyBytes)
      },
      key,
      ciphertext
    )
    return decoder.decode(unpad(new Uint8Array(plaintext)))
  } catch {
    throw new Error('Decryption failed')
  }
}

function pad(bytes) {
  const out = new Uint8Array(Math.ceil((bytes.length + 1) / BLOCK_LEN) * BLOCK_LEN)
  out.set(bytes)
  out[bytes.length] = 0x80
  return out
}

function unpad(bytes) {
  let end = bytes.length
  while (end > 0 && bytes[end - 1] === 0) end--
  if (end === 0 || bytes[end - 1] !== 0x80) throw new Error('Decryption failed')
  return bytes.subarray(0, end - 1)
}

function encodeText(text) {
  if (typeof text.isWellFormed === 'function' && !text.isWellFormed()) {
    throw new Error('Message contains unpaired surrogates')
  }
  return encoder.encode(text)
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

function parsePublicKey(text, message) {
  let bytes
  try {
    bytes = fromBase64(text)
  } catch {
    throw new Error(message)
  }
  if (bytes.length !== PUB_LEN || (bytes[X_PUB_LEN - 1] & 0x80) !== 0) throw new Error(message)
  return bytes
}

async function importPublicKey(bytes, message) {
  try {
    return {
      x: await crypto.subtle.importKey('raw', bytes.subarray(0, X_PUB_LEN), ALG, false, []),
      kem: await mlkem.importKey('raw-public', bytes.subarray(X_PUB_LEN), KEM, true, ['encapsulateBits'])
    }
  } catch {
    throw new Error(message)
  }
}

async function buildIdentity(privateKey, kemPrivateKey) {
  const jwk = await crypto.subtle.exportKey('jwk', privateKey)
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
    ALG,
    true,
    []
  )
  const kemPublicKey = await mlkem.getPublicKey(kemPrivateKey, ['encapsulateBits'])
  const publicKeyBytes = concat(
    new Uint8Array(await crypto.subtle.exportKey('raw', publicKey)),
    new Uint8Array(await mlkem.exportKey('raw-public', kemPublicKey))
  )
  return {
    privateKey,
    kemPrivateKey,
    publicKeyBytes,
    publicKeyBase64: toBase64(publicKeyBytes),
    fingerprint: await formatFingerprint(publicKeyBytes)
  }
}

async function formatFingerprint(publicKeyBytes) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', publicKeyBytes))
  const hex = [...digest.subarray(0, FINGERPRINT_LEN)].map((b) => b.toString(16).padStart(2, '0')).join('')
  return hex.match(/.{4}/g).join(' ')
}

async function passphraseKey(passphrase, salt, iterations) {
  const base = await crypto.subtle.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, [
    'deriveKey'
  ])
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

async function agree(privateKey, publicKey) {
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: publicKey }, privateKey, 256))
}

async function deriveKey(parts, salt) {
  const hkdf = await crypto.subtle.importKey('raw', concat(...parts), 'HKDF', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: INFO },
    hkdf,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}
