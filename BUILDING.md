# Building QRAuth

This repository is the public mirror of QRAuth's source. The commercial
dashboard, deployment tooling, and internal CI workflows are not included.

## Packages

- `packages/api/` — Fastify API server (BSL 1.1)
- `packages/shared/` — Shared TypeScript types, Zod schemas, canonical payload
  serializer, algorithm version policy
- `packages/node-sdk/` — Official Node.js SDK (`@qrauth/node`)
- `packages/python-sdk/` — Official Python SDK (`qrauth` on PyPI)
- `packages/animated-qr/` — Living Codes: animated QR rendering (Canvas 2D +
  CanvasKit/Skia WASM)
- `packages/web-components/` — Drop-in custom elements (`<qrauth-login>`,
  `<qrauth-2fa>`, `<qrauth-ephemeral>`)
- `packages/signer-service/` — Standalone SLH-DSA signer service for
  air-gapped key management (see `SECURITY.md` § Key Management Architecture)
- `packages/protocol-tests/` — QRVA protocol test suite with cross-language
  test vectors (Node + Python byte-identical)
- `packages/docs/` — VitePress documentation source for https://docs.qrauth.io

## Post-Quantum Architecture

The signing layer is a hybrid ECDSA-P256 + SLH-DSA-SHA2-128s (FIPS 205)
architecture with Merkle batch issuance and a commitment-only transparency
log. The full technical specification is in `SECURITY.md`, `THREAT_MODEL.md`,
`COMPLIANCE.md` at the repo root, and `packages/docs/guide/protocol.md`.

## Getting Started

See https://qrauth.io/docs for integration guides, SDK quickstarts, and the
QRVA protocol specification.
