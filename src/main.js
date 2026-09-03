import Alpine from '@alpinejs/csp'
import './style.css'
import {
  environment,
  isSupported,
  generateIdentity,
  exportIdentity,
  importIdentity,
  isEncryptedIdentity,
  encrypt as encryptNote,
  decrypt as decryptNote,
  fingerprint
} from './crypto.js'
import { seal, parse } from './envelope.js'

const ENVELOPE = document.getElementById('envelope').textContent
const SOURCE = seal(`<!doctype html>\n${document.documentElement.outerHTML}`, null)

const MESSAGES = {
  framed: 'This page must not be embedded in a frame.',
  insecure: 'This page needs a secure context. Serve it over https or from localhost.',
  unsupported:
    'This browser lacks X25519 in WebCrypto or WebAssembly. Use Chrome 133+, Firefox 132+ or Safari 17.4+.'
}

Alpine.data('app', () => ({
  state: 'checking',
  identity: null,
  tab: 'encrypt',
  envelope: false,
  passphrase: '',
  recipient: '',
  recipientFingerprint: '',
  message: '',
  ciphertext: '',
  sender: '',
  senderFingerprint: '',
  payload: '',
  plaintext: '',
  decrypted: false,
  verifiedSender: '',
  encryptError: '',
  decryptError: '',
  identityError: '',
  confirming: '',
  copied: '',
  copyFailed: '',
  run: 0,

  async init() {
    const env = environment()
    this.state = env === 'ok' ? ((await isSupported()) ? 'ok' : 'unsupported') : env
    if (this.ready) this.openEnvelope()
  },

  openEnvelope() {
    let envelope
    try {
      envelope = parse(ENVELOPE)
    } catch (error) {
      this.tab = 'decrypt'
      this.decryptError = error.message
      return
    }
    if (!envelope) return
    this.tab = 'decrypt'
    this.envelope = true
    this.sender = envelope.from
    this.payload = envelope.note
    this.previewSender()
  },

  get ready() {
    return this.state === 'ok'
  },

  get blocked() {
    return MESSAGES[this.state] || ''
  },

  get publicKey() {
    return this.identity ? this.identity.publicKeyBase64 : ''
  },

  copyLabel(label) {
    if (this.copied === label) return 'Copied'
    if (this.copyFailed === label) return 'Failed'
    return 'Copy'
  },

  confirm(action) {
    if (!this.identity || this.confirming === action) {
      this.confirming = ''
      clearTimeout(this.confirmTimer)
      return action === 'generate' ? this.generate() : this.clear()
    }
    this.confirming = action
    clearTimeout(this.confirmTimer)
    this.confirmTimer = setTimeout(() => (this.confirming = ''), 4000)
  },

  async generate() {
    this.identityError = ''
    this.resetOutputs()
    try {
      this.identity = await generateIdentity()
    } catch {
      this.identityError = 'Key generation failed'
    }
  },

  async exportKey() {
    if (!this.identity) return
    this.identityError = ''
    try {
      const data = await exportIdentity(this.identity, this.passphrase)
      download(JSON.stringify(data, null, 2), 'e2e-identity.json', 'application/json')
    } catch {
      this.identityError = 'Export failed'
    }
  },

  saveOffline() {
    download(SOURCE, 'e2e-notes.html', 'text/html')
  },

  savePage() {
    if (!this.identity || !this.ciphertext) return
    const page = seal(SOURCE, { v: 1, from: this.identity.publicKeyBase64, note: this.ciphertext })
    download(page, 'e2e-note.html', 'text/html')
  },

  async importFile(event) {
    const file = event.target.files[0]
    event.target.value = ''
    if (!file) return
    this.identityError = ''
    let data
    try {
      data = JSON.parse(await file.text())
    } catch {
      this.identityError = 'Invalid identity file'
      return
    }
    if (isEncryptedIdentity(data) && !this.passphrase) {
      this.identityError = 'Enter the passphrase, then import again'
      return
    }
    this.resetOutputs()
    try {
      this.identity = await importIdentity(data, this.passphrase)
    } catch (error) {
      this.identity = null
      this.identityError = error.message
    }
  },

  clear() {
    this.identity = null
    this.passphrase = ''
    this.recipient = ''
    this.recipientFingerprint = ''
    this.message = ''
    this.sender = ''
    this.senderFingerprint = ''
    this.payload = ''
    this.identityError = ''
    this.resetOutputs()
  },

  async previewRecipient() {
    this.ciphertext = ''
    const value = this.recipient
    const preview = await fingerprint(value).catch(() => '')
    if (value === this.recipient) this.recipientFingerprint = preview
  },

  async previewSender() {
    this.decrypted = false
    const value = this.sender
    const preview = await fingerprint(value).catch(() => '')
    if (value === this.sender) this.senderFingerprint = preview
  },

  resetOutputs() {
    this.run++
    this.ciphertext = ''
    this.plaintext = ''
    this.decrypted = false
    this.verifiedSender = ''
    this.encryptError = ''
    this.decryptError = ''
    this.copied = ''
    this.copyFailed = ''
  },

  async encrypt() {
    this.encryptError = ''
    this.ciphertext = ''
    if (!this.identity) {
      this.encryptError = 'Create or import an identity first'
      return
    }
    if (!this.recipient.trim() || !this.message) {
      this.encryptError = 'Recipient key and message are required'
      return
    }
    const run = ++this.run
    try {
      const ciphertext = await encryptNote(this.identity, this.recipient.trim(), this.message)
      if (run === this.run) this.ciphertext = ciphertext
    } catch (error) {
      if (run === this.run) this.encryptError = error.message
    }
  },

  async decrypt() {
    this.decryptError = ''
    this.plaintext = ''
    this.decrypted = false
    this.verifiedSender = ''
    if (!this.identity) {
      this.decryptError = 'Create or import an identity first'
      return
    }
    if (!this.sender.trim() || !this.payload.trim()) {
      this.decryptError = 'Sender key and message are required'
      return
    }
    const run = ++this.run
    const sender = this.sender.trim()
    try {
      const plaintext = await decryptNote(this.identity, sender, this.payload.trim())
      const verifiedSender = await fingerprint(sender)
      if (run !== this.run) return
      this.plaintext = plaintext
      this.decrypted = true
      this.verifiedSender = verifiedSender
    } catch (error) {
      if (run === this.run) this.decryptError = error.message
    }
  },

  async copy(value, label) {
    if (!value) return
    const ok = await writeClipboard(value)
    this.copied = ok ? label : ''
    this.copyFailed = ok ? '' : label
    clearTimeout(this.copyTimer)
    this.copyTimer = setTimeout(() => {
      this.copied = ''
      this.copyFailed = ''
    }, 1500)
  }
}))

function download(content, filename, type) {
  const url = URL.createObjectURL(new Blob([content], { type }))
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.rel = 'noopener'
  document.body.append(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 10000)
}

async function writeClipboard(value) {
  try {
    await navigator.clipboard.writeText(value)
    return true
  } catch {}
  const area = document.createElement('textarea')
  area.value = value
  area.style.cssText = 'position:fixed;opacity:0'
  document.body.append(area)
  area.select()
  area.setSelectionRange(0, value.length)
  let ok = false
  try {
    ok = document.execCommand('copy')
  } catch {}
  area.remove()
  return ok
}

Alpine.start()
