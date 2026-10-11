import assert from 'node:assert/strict'
import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const projectRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..'
)
const clientRoot = path.join(projectRoot, 'dist', 'client')
const serverRoot = path.join(projectRoot, 'dist', 'server')
const textExtensions = new Set([
  '.css',
  '.html',
  '.js',
  '.json',
  '.map',
  '.mjs',
  '.svg',
  '.txt'
])

async function textFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true })
  const files = []
  for (const entry of entries) {
    const absolute = path.join(directory, entry.name)
    if (entry.isDirectory()) {
      files.push(...await textFiles(absolute))
    } else if (textExtensions.has(path.extname(entry.name))) {
      files.push(absolute)
    }
  }
  return files
}

test('built browser assets keep private FNCP values and service origins out', async () => {
  const files = await textFiles(clientRoot)
  assert.ok(files.length > 0, 'Run the production alpha build before this check.')

  const combined = (
    await Promise.all(files.map((file) => readFile(file, 'utf8')))
  ).join('\n')

  for (const forbidden of [
    /INTERNAL_SERVICE_URL/u,
    /FNCP_GATEWAY_SHARED_SECRET/u,
    /PUBLIC_SERVICE_URL/u,
    /http:\/\/server:5000/u,
    /polis-api\.internal/u,
    /gateway-secret-that-is-at-least/u,
    /participant_xid_01/u
  ]) {
    assert.doesNotMatch(combined, forbidden)
  }
  assert.match(combined, /["'`]\/api\/v3["'`]/u)
})

test('generated JavaScript and CSS assets use the explicit _astro directory', async () => {
  const files = await textFiles(clientRoot)
  const generated = files.filter((file) =>
    ['.js', '.css'].includes(path.extname(file))
  )
  assert.ok(generated.length > 0)

  for (const file of generated) {
    assert.equal(
      path.relative(clientRoot, file).split(path.sep)[0],
      '_astro'
    )
  }
})

test('built SSR output uses Astro passthrough images without build-tool imports', async () => {
  const files = await textFiles(serverRoot)
  assert.ok(files.length > 0, 'Run the production alpha build before this check.')

  const combined = (
    await Promise.all(files.map((file) => readFile(file, 'utf8')))
  ).join('\n')

  assert.match(combined, /astro\/assets\/services\/noop/u)
  assert.doesNotMatch(combined, /astro\/assets\/services\/sharp/u)
  assert.doesNotMatch(combined, /(?:from\s+|import\()['"]sharp['"]/u)
  assert.doesNotMatch(
    combined,
    /(?:from\s+|import\()['"](?:@esbuild\/[^'"]+|esbuild)['"]/u
  )
  assert.doesNotMatch(
    combined,
    /(?:from\s+|import\()['"](?:@astrojs\/[^'"]+|@oxc-project\/[^'"]+|@rolldown\/[^'"]+|@vitejs\/[^'"]+|astro|lightningcss|rolldown|vite)['"]/u
  )

  // Astro injects this internal route for the SSR build. The outer FNCP proxy
  // contract, rather than generated-output rewriting, denies both public
  // spellings.
  assert.match(combined, /"route":"\/_image"/u)
})
