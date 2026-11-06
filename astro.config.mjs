import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import { rehypeWrapTables } from './src/lib/rehype-wrap-tables.js';

export default defineConfig({
  // TODO: Update `site` URL in `astro.config.mjs` after deploying
  site: 'https://TODO_YOUR_DOMAIN.vercel.app',
  output: 'static',
  integrations: [sitemap()],
  markdown: {
    rehypePlugins: [rehypeWrapTables],
  },
  // For GitHub Pages: uncomment and set base
  // base: '/repository-name',
});