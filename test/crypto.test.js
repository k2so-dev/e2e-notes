import { beforeAll, describe, expect, test } from 'bun:test'
import {
  decrypt,
  encrypt,
  exportIdentity,
  fingerprint,
  fromBase64,
  generateIdentity,
  importIdentity,
  isEncryptedIdentity,
  toBase64
} from '../src/crypto.js'

let alice, bob, eve, note

const flip = (payload, index, mask = 0x01) => {
  const bytes = fromBase64(payload)
  bytes[index] ^= mask
  return toBase64(bytes)
}

beforeAll(async () => {
  alice = await generateIdentity()
  bob = await generateIdentity()
  eve = await generateIdentity()
  note = await encrypt(alice, bob.publicKeyBase64, 'hello')
})

describe('identity', () => {
  test('public key is x25519 and ml-kem in canonical base64', () => {
    expect(alice.publicKeyBase64).toHaveLength(1624)
    expect(alice.publicKeyBytes).toHaveLength(1216)
    expect(alice.publicKeyBytes[31] & 0x80).toBe(0)
  })

  test('every identity is distinct', () => {
    expect(alice.publicKeyBase64).not.toBe(bob.publicKeyBase64)
    expect(alice.fingerprint).not.toBe(bob.fingerprint)
  })

  test('the fingerprint is the truncated sha-256 of the public key', async () => {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', alice.publicKeyBytes))
    const hex = [...digest.subarray(0, 16)].map((b) => b.toString(16).padStart(2, '0')).join('')
    expect(alice.fingerprint).toMatch(/^([0-9a-f]{4} ){7}[0-9a-f]{4}$/)
    expect(alice.fingerprint.replace(/ /g, '')).toBe(hex)
    expect(await fingerprint(alice.publicKeyBase64)).toBe(alice.fingerprint)
    await expect(fingerprint('AAAA')).rejects.toThrow('Invalid public key')
  })
})

describe('round trip', () => {
  test.each([
    ['ascii', 'hello world'],
    ['unicode', 'секрет — 🔒 日本語'],
    ['empty', ''],
    ['leading BOM', '﻿bom'],
    ['newlines', 'line one\nline two\n'],
    ['long', 'x'.repeat(100000)]
  ])('%s', async (_name, message) => {
    const payload = await encrypt(alice, bob.publicKeyBase64, message)
    expect(await decrypt(bob, alice.publicKeyBase64, payload)).toBe(message)
  })

  test('the same note encrypts differently every time', async () => {
    const first = await encrypt(alice, bob.publicKeyBase64, 'hello')
    const second = await encrypt(alice, bob.publicKeyBase64, 'hello')
    expect(first).not.toBe(second)
    expect(await decrypt(bob, alice.publicKeyBase64, first)).toBe('hello')
    expect(await decrypt(bob, alice.publicKeyBase64, second)).toBe('hello')
  })

  test('the length of short notes is hidden', async () => {
    const size = async (message) => fromBase64(await encrypt(alice, bob.publicKeyBase64, message)).length
    expect(await size('')).toBe(await size('x'.repeat(255)))
    expect(await size('x'.repeat(256))).toBe((await size('')) + 256)
  })

  test('unpaired surrogates are refused', async () => {
    await expect(encrypt(alice, bob.publicKeyBase64, 'a\uD83Db')).rejects.toThrow(
      'Message contains unpaired surrogates'
    )
  })
})

describe('authentication', () => {
  test('a wrong sender key does not decrypt', async () => {
    await expect(decrypt(bob, eve.publicKeyBase64, note)).rejects.toThrow('Decryption failed')
  })

  test('a third party holding the sender key does not decrypt', async () => {
    await expect(decrypt(eve, alice.publicKeyBase64, note)).rejects.toThrow('Decryption failed')
  })

  test('the sender cannot read the note back', async () => {
    await expect(decrypt(alice, alice.publicKeyBase64, note)).rejects.toThrow('Decryption failed')
  })

  test('a forged sender is rejected', async () => {
    const forged = await encrypt(eve, bob.publicKeyBase64, 'trust me')
    await expect(decrypt(bob, alice.publicKeyBase64, forged)).rejects.toThrow('Decryption failed')
  })
})

describe('tampering', () => {
  test.each([
    ['magic', 0, 'Malformed message'],
    ['ephemeral key', 4, 'Decryption failed'],
    ['kem ciphertext', 36, 'Decryption failed'],
    ['kem ciphertext end', 1123, 'Decryption failed'],
    ['salt', 1124, 'Decryption failed'],
    ['iv', 1140, 'Decryption failed'],
    ['ciphertext', 1152, 'Decryption failed']
  ])('%s', async (_name, index, message) => {
    await expect(decrypt(bob, alice.publicKeyBase64, flip(note, index))).rejects.toThrow(message)
  })

  test('the ephemeral key is not malleable', async () => {
    await expect(decrypt(bob, alice.publicKeyBase64, flip(note, 35, 0x80))).rejects.toThrow(
      'Decryption failed'
    )
  })
})

describe('public key parsing', () => {
  test('base64url and whitespace are accepted', async () => {
    const url = bob.publicKeyBase64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    const spaced = alice.publicKeyBase64.slice(0, 20) + ' \n ' + alice.publicKeyBase64.slice(20)
    const payload = await encrypt(alice, url, 'hello')
    expect(await decrypt(bob, spaced, payload)).toBe('hello')
  })

  test('malformed recipient keys are refused', async () => {
    const nonCanonical = fromBase64(bob.publicKeyBase64)
    nonCanonical[31] |= 0x80
    const badKem = fromBase64(bob.publicKeyBase64).fill(0xff, 32)
    const keys = [
      '',
      'not a key!!',
      'AAAA',
      toBase64(nonCanonical.subarray(0, 32)),
      toBase64(nonCanonical),
      toBase64(badKem)
    ]
    for (const key of keys) {
      await expect(encrypt(alice, key, 'hello')).rejects.toThrow('Invalid recipient key')
    }
  })

  test('a non canonical sender key is refused', async () => {
    const bytes = fromBase64(alice.publicKeyBase64)
    bytes[31] |= 0x80
    await expect(decrypt(bob, toBase64(bytes), note)).rejects.toThrow('Invalid sender key')
  })
})

describe('payload parsing', () => {
  test('whitespace is accepted', async () => {
    expect(await decrypt(bob, alice.publicKeyBase64, note.slice(0, 40) + '\n ' + note.slice(40))).toBe(
      'hello'
    )
  })

  test('malformed payloads are refused', async () => {
    const bytes = fromBase64(note)
    const truncated = toBase64(bytes.subarray(0, 1160))
    const shortened = toBase64(bytes.subarray(0, bytes.length - 1))
    const wrongMagic = toBase64(bytes.map((b, i) => (i === 3 ? 0x32 : b)))
    const payloads = ['!!!', '', note.slice(0, -2) + '/=', truncated, shortened, wrongMagic]
    for (const payload of payloads) {
      await expect(decrypt(bob, alice.publicKeyBase64, payload)).rejects.toThrow('Malformed message')
    }
  })
})

describe('identity files', () => {
  test('a plain export carries the private scalar', async () => {
    const file = await exportIdentity(alice)
    expect(isEncryptedIdentity(file)).toBe(false)
    expect(file.key.x.d).toBeString()
    expect(fromBase64(file.key.kem)).toHaveLength(64)
    const restored = await importIdentity(file)
    expect(restored.publicKeyBase64).toBe(alice.publicKeyBase64)
    expect(restored.fingerprint).toBe(alice.fingerprint)
  })

  test('a passphrase export hides the private scalar', async () => {
    const file = await exportIdentity(bob, 'correct horse')
    expect(isEncryptedIdentity(file)).toBe(true)
    expect(file.key).toBeUndefined()
    expect(JSON.stringify(file)).not.toContain('"d"')
    expect(JSON.stringify(file)).not.toContain('"kem"')
    const restored = await importIdentity(file, 'correct horse')
    expect(restored.publicKeyBase64).toBe(bob.publicKeyBase64)
    expect(await decrypt(restored, alice.publicKeyBase64, note)).toBe('hello')
  })

  test('a wrong passphrase is refused', async () => {
    const file = await exportIdentity(bob, 'correct horse')
    await expect(importIdentity(file, 'battery staple')).rejects.toThrow('Wrong passphrase')
    await expect(importIdentity(file)).rejects.toThrow('Passphrase required')
  })

  test('an absurd iteration count is refused', async () => {
    const file = await exportIdentity(bob, 'correct horse')
    await expect(importIdentity({ ...file, iterations: 1e12 }, 'correct horse')).rejects.toThrow(
      'Invalid identity file'
    )
  })

  test('the public key is re-derived, never trusted', async () => {
    const file = await exportIdentity(alice)
    const forged = { ...file, key: { ...file.key, x: { ...file.key.x, x: 'ZZZZ' } } }
    const restored = await importIdentity(forged).catch(() => null)
    expect(restored === null || restored.publicKeyBase64 === alice.publicKeyBase64).toBe(true)
  })

  test.each([
    ['null', null],
    ['wrong algorithm', { alg: 'RSA', key: {} }],
    ['previous version', { v: 2, alg: 'X25519', key: {} }],
    ['no key', { alg: 'X25519+ML-KEM-768' }],
    ['short seed', { alg: 'X25519+ML-KEM-768', key: { x: {}, kem: 'AAAA' } }],
    ['junk key', { alg: 'X25519+ML-KEM-768', key: { x: { kty: 'OKP', d: 'nope' }, kem: 'A'.repeat(88) } }]
  ])('%s is refused', async (_name, file) => {
    await expect(importIdentity(file)).rejects.toThrow('Invalid identity file')
  })
})
