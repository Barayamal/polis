// @ts-check
import { defineConfig } from 'astro/config'

import react from '@astrojs/react'

import node from '@astrojs/node'

// https://astro.build/config
export default defineConfig({
  base: '/',
  output: 'server',
  build: {
    assets: '_astro'
  },
  adapter: node({
    mode: 'standalone'
  }),
  server: {
    host: '0.0.0.0'
  },
  integrations: [
    react({
      experimentalDisableStreaming: true,
      experimentalReactChildren: true
    })
  ]
})
