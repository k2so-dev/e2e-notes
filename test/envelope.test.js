import { beforeAll, describe, expect, test } from 'bun:test'
import { decrypt, encrypt, generateIdentity } from '../src/crypto.js'
import { parse, seal } from '../src/envelope.js'

const SLOT = '<script type="application/json" id="envelope"></script>'
const PAGE = `<!doctype html>\n<html><head>${SLOT}</head><body><script type="module">app()</script></body></html>`

const slotText = (html) => html.match(/<script type="application\/json" id="envelope">([\s\S]*?)<\/script>/)[1]

let alice, bob, note

beforeAll(async () => {
  alice = await generateIdentity()
  bob = await generateIdentity()
  note = await encrypt(alice, bob.publicKeyBase64, 'hello')
})

describe('seal', () => {
  test('writes the envelope into the slot and nothing else', () => {
    const sealed = seal(PAGE, { v: 1, from: 'from', note: 'note' })
    expect(slotText(sealed)).toBe('{"v":1,"from":"from","note":"note"}')
    expect(sealed.replace(slotText(sealed), '')).toBe(PAGE)
  })

  test('null strips the envelope', () => {
    const sealed = seal(PAGE, { v: 1, from: 'from', note: 'note' })
    expect(seal(sealed, null)).toBe(PAGE)
  })

  test('a sealed page is resealed, not appended', () => {
    const first = seal(PAGE, { v: 1, from: 'a', note: 'b' })
    const second = seal(first, { v: 1, from: 'c', note: 'd' })
    expect(slotText(second)).toBe('{"v":1,"from":"c","note":"d"}')
    expect(second.match(/id="envelope"/g)).toHaveLength(1)
  })

  test('a page without the slot is refused', () => {
    expect(() => seal('<html></html>', null)).toThrow('Envelope slot missing')
  })
})

describe('parse', () => {
  test('an empty slot is no envelope', () => {
    expect(parse('')).toBeNull()
    expect(parse(' \n')).toBeNull()
    expect(parse(undefined)).toBeNull()
  })

  test('a valid envelope is returned without extras', () => {
    expect(parse('{"v":1,"from":"a","note":"b","extra":1}')).toEqual({ from: 'a', note: 'b' })
  })

  test.each([
    ['junk', '{'],
    ['array', '[]'],
    ['null', 'null'],
    ['wrong version', '{"v":2,"from":"a","note":"b"}'],
    ['missing note', '{"v":1,"from":"a"}'],
    ['empty note', '{"v":1,"from":"a","note":""}'],
    ['non-string from', '{"v":1,"from":1,"note":"b"}']
  ])('%s is refused', (_name, text) => {
    expect(() => parse(text)).toThrow('Invalid envelope')
  })
})

describe('round trip', () => {
  test('a sealed note decrypts for the recipient', async () => {
    const sealed = seal(PAGE, { v: 1, from: alice.publicKeyBase64, note })
    const envelope = parse(slotText(sealed))
    expect(envelope.from).toBe(alice.publicKeyBase64)
    expect(await decrypt(bob, envelope.from, envelope.note)).toBe('hello')
  })
})
