import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://routsom.github.io',
  base: '/portcullis/',
  integrations: [
    starlight({
      title: 'portcullis',
      description: 'An open-source MCP gateway you can put in front of untrusted tools.',
      logo: { src: './src/assets/logo.svg', alt: 'portcullis' },
      favicon: '/favicon.svg',
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/routsom/portcullis' }],
      editLink: { baseUrl: 'https://github.com/routsom/portcullis/edit/main/docs/site/' },
      customCss: ['./src/styles/custom.css'],
      sidebar: [
        { label: 'Getting started', items: [
          'getting-started/install', 'getting-started/first-server', 'getting-started/configuration',
        ]},
        { label: 'Concepts', items: [
          'concepts/architecture', 'concepts/prime-directives', 'concepts/domain-model',
        ]},
        { label: 'Security', items: [
          'security/model', 'security/threat-model', 'security/sandbox',
        ]},
        { label: 'Operations', items: [
          'operations/policy', 'operations/limits', 'operations/audit', 'operations/metrics', 'operations/ha',
        ]},
        { label: 'Extending', items: [
          'extending/translation', 'extending/facade', 'extending/plugins',
        ]},
        { label: 'Project', items: [
          'project/roadmap', 'project/traceability', 'project/contributing', 'project/adrs',
        ]},
      ],
    }),
  ],
});
