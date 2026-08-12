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

test('the alpha build uses Astro passthrough images without a Sharp runtime', async () => {
  const astroConfig = await source('astro.config.mjs')

  assert.match(
    astroConfig,
    /import \{ defineConfig, passthroughImageService \} from 'astro\/config'/
  )
  assert.match(astroConfig, /service: passthroughImageService\(\)/)
  assert.doesNotMatch(astroConfig, /sharpImageService|services\/sharp/)
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

test('FNCP completion state collects no email and calls no notification route', async () => {
  const surveySource = await source('src/components/Survey.tsx')

  assert.match(surveySource, /className="survey-complete"/)
  assert.match(surveySource, /s\.completionTitle/)
  assert.match(surveySource, /s\.completionBody/)
  assert.doesNotMatch(surveySource, /EmailSubscribeForm|notifications/)
})

test('block markdown is rendered inside a valid flow container', async () => {
  const pageSource = await source('src/pages/[conversation_id].astro')

  assert.match(
    pageSource,
    /<div class="description" set:html=\{marked\.parse\(surveyDetails\?\.description \?\? ''\)\}><\/div>/
  )
  assert.doesNotMatch(pageSource, /<p class="description" set:html=\{marked\.parse/)
})

test('hydrated participant islands have deterministic initial markup', async () => {
  const [statementSource, translationsSource] = await Promise.all([
    source('src/components/Statement.tsx'),
    source('src/strings/en_us.ts')
  ])

  assert.match(
    statementSource,
    /useSyncExternalStore\(subscribeToLanguage, uiLanguage, serverLanguage\)/
  )
  assert.match(statementSource, /const serverLanguage = \(\) => null/)

  for (const name of [
    'participantHelpWelcomeText',
    'tipCommentsRandom',
    'writeCommentHelpText'
  ]) {
    const match = translationsSource.match(
      new RegExp(`${name}:\\s*\\n?\\s*["']([^"']*)["']`)
    )
    assert.ok(match, `expected ${name} in English translations`)
    assert.equal(
      (match[1].match(/<b>/g) ?? []).length,
      (match[1].match(/<\/b>/g) ?? []).length,
      `${name} must contain balanced bold tags`
    )
  }
})
