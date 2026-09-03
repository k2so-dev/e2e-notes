const SLOT = /(<script type="application\/json" id="envelope">)[\s\S]*?(<\/script>)/

export function seal(html, envelope) {
  if (!SLOT.test(html)) throw new Error('Envelope slot missing')
  const content = envelope ? JSON.stringify(envelope) : ''
  return html.replace(SLOT, (_, open, close) => open + content + close)
}

export function parse(text) {
  if (!text || !text.trim()) return null
  let data
  try {
    data = JSON.parse(text)
  } catch {
    throw new Error('Invalid envelope')
  }
  if (
    !data ||
    typeof data !== 'object' ||
    data.v !== 1 ||
    typeof data.from !== 'string' ||
    !data.from ||
    typeof data.note !== 'string' ||
    !data.note
  ) {
    throw new Error('Invalid envelope')
  }
  return { from: data.from, note: data.note }
}
