import { createHash } from 'node:crypto'
import { defineConfig } from 'vite'
import tailwindcss from '@tailwindcss/vite'
import { viteSingleFile } from 'vite-plugin-singlefile'

function cspHash() {
  return {
    name: 'csp-hash',
    enforce: 'post',
    generateBundle(_, bundle) {
      const html = bundle['index.html']
      const [, script] = html.source.match(/<script type="module" crossorigin>([\s\S]*?)<\/script>/)
      const hash = createHash('sha256').update(script).digest('base64')
      html.source = html.source.replace("script-src 'unsafe-inline'", `script-src 'sha256-${hash}'`)
    }
  }
}

export default defineConfig({
  plugins: [tailwindcss(), viteSingleFile(), cspHash()],
  build: { target: 'esnext' }
})
