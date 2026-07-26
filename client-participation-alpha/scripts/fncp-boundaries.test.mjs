import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const projectRoot = new URL('../', import.meta.url)

async function source(path) {
  return readFile(new URL(path, projectRoot), 'utf8')
}

test('browser API and generated asset bases are fixed same-origin paths', async () => {
  const [requestSource, netSource, astroConfig] = await Promise.all([
    source('src/lib/polis-request.ts'),
    source('src/lib/net.ts'),
    source('astro.config.mjs')
  ])

  assert.match(requestSource, /BROWSER_POLIS_API_BASE = '\/api\/v3'/)
  assert.doesNotMatch(netSource, /PUBLIC_SERVICE_URL|INTERNAL_SERVICE_URL/)
  assert.match(astroConfig, /base: '\/'/)
  assert.match(astroConfig, /assets: '_astro'/)
})
test('gateway identity remains in the SSR request context and out of rendered state', async () => {
  const [pageSource, participationSource] = await Promise.all([
    source('src/pages/[conversation_id].astro'),
    source('src/api/participation.ts')
  ])

  assert.match(pageSource, /resolveFncpAlphaRequest\(Astro\.request, conversation_id\)/)
  assert.match(pageSource, /fncpContext\.polisRequest/)
  assert.match(pageSource, /define:vars=\{\{ initialAuth \}\}/)
  assert.doesNotMatch(pageSource, /define:vars=\{\{ initialData \}\}/)
  assert.match(pageSource, /fncpContext\.gatewayEnforced \? null : initialData\?\.auth/)
  assert.match(participationSource, /serverRequest\?: PolisServerRequest/)
})
