import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'QRAuth Documentation',
  description: 'Cryptographic QR code verification & authentication platform',
  head: [
    ['link', { rel: 'icon', href: '/favicon.svg' }],
  ],
  themeConfig: {
    logo: '/logo.svg',
    siteTitle: 'QRAuth',
    nav: [
      { text: 'Guide', link: '/guide/quickstart' },
      { text: 'API Reference', link: '/api/overview' },
      { text: 'SDKs', link: '/sdk/node' },
      { text: 'qrauth.io', link: 'https://qrauth.io' },
    ],
    sidebar: {
      '/guide/': [
        {
          text: 'Getting Started',
          items: [
            { text: 'Quickstart', link: '/guide/quickstart' },
            { text: 'Authentication', link: '/guide/authentication' },
          ],
        },
        {
          text: 'Features',
          items: [
            { text: 'Web Components', link: '/guide/web-components' },
            { text: 'Ephemeral Access', link: '/guide/ephemeral' },
            { text: 'Proximity Verification', link: '/guide/proximity' },
            { text: 'Living Codes', link: '/guide/living-codes' },
            { text: 'Device Trust', link: '/guide/device-trust' },
            { text: 'Trust Reveal', link: '/guide/trust-reveal' },
          ],
        },
        {
          text: 'Security',
          items: [
            { text: 'Trust Levels', link: '/guide/trust-levels' },
            { text: 'Domain Verification', link: '/guide/domain-verification' },
            { text: 'Fraud Detection', link: '/guide/fraud-detection' },
            { text: 'QRVA Protocol', link: '/guide/protocol' },
            { text: 'Protocol Design Notes', link: '/guide/protocol-design' },
            { text: 'Signing Architecture', link: '/guide/signing-architecture' },
          ],
        },
      ],
      '/api/': [
        {
          text: 'API Reference',
          items: [
            { text: 'Overview', link: '/api/overview' },
            { text: 'QR Codes', link: '/api/qrcodes' },
            { text: 'Verification', link: '/api/verification' },
            { text: 'Auth Sessions', link: '/api/auth-sessions' },
            { text: 'Ephemeral Sessions', link: '/api/ephemeral' },
            { text: 'Proximity', link: '/api/proximity' },
            { text: 'Devices', link: '/api/devices' },
            { text: 'Webhooks', link: '/api/webhooks' },
          ],
        },
      ],
      '/sdk/': [
        {
          text: 'SDKs',
          items: [
            { text: 'Node.js', link: '/sdk/node' },
            { text: 'Python', link: '/sdk/python' },
            { text: 'Web Components', link: '/sdk/web-components' },
            { text: 'Animated QR', link: '/sdk/animated-qr' },
          ],
        },
      ],
    },
    socialLinks: [
      { icon: 'github', link: 'https://github.com/qrauth-io/qrauth' },
    ],
    editLink: {
      pattern: 'https://github.com/aristech/vqr/edit/main/packages/docs/:path',
      text: 'Edit this page',
    },
    footer: {
      message: 'BSL 1.1 Licensed (Apache 2.0 after 4 years)',
      copyright: '© 2026 QRAuth / ProgressNet',
    },
    search: {
      provider: 'local',
    },
  },
})
