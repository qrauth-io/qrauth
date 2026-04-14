# Contributing to QRAuth

Thanks for your interest in contributing to QRAuth. This guide covers the basics for getting started.

## Reporting Issues

- Use [GitHub Issues](https://github.com/qrauth-io/qrauth/issues) for bug reports and feature requests.
- Search existing issues before opening a new one.
- For security vulnerabilities, see the [Security Disclosure Policy](#security-disclosure-policy) below.

## Security Disclosure Policy

**Do not open public GitHub issues for security vulnerabilities.**

If you discover a vulnerability in QRAuth — including issues with ECDSA signing, HMAC validation, WebAuthn flows, fraud detection bypass, or authentication logic — please disclose it responsibly:

1. **Email** security@qrauth.io with a description of the issue, reproduction steps, and potential impact.
2. **PGP**: If you need to encrypt the report, request our public key in the initial email.
3. **Response time**: We aim to acknowledge reports within 48 hours and provide a resolution timeline within 7 days.
4. **Scope**: The platform API, SDKs, web dashboard, and the QRVA protocol implementation are all in scope. Third-party dependencies and infrastructure outside our control are out of scope.
5. **Credit**: We will credit researchers in the release notes unless you prefer to remain anonymous.

We do not currently run a bug bounty program, but significant findings will be recognized publicly.

## Development Setup

### Prerequisites

- Node.js 22+
- Docker (for PostgreSQL + Redis)
- Git

### Getting Started

```bash
git clone https://github.com/qrauth-io/qrauth.git
cd qrauth
npm install

# Start local databases
docker compose up -d

# Run database migrations
npm run db:migrate

# Start the API server
npm run dev

# Start the web dashboard
npm run dev:web
```

### Running Tests

```bash
npm run test:e2e          # Full E2E test suite (39 tests)
```

## Making Changes

1. Fork the repository and create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature
   ```

2. Make your changes. Follow the existing code style.

3. Run lint and typecheck:
   ```bash
   npm run build              # Build all packages
   ```

4. Submit a pull request against `main`.

## PR Checklist

Before submitting a pull request, confirm the following:

- [ ] Branch is based on the latest `main`
- [ ] `npm run build` passes with no errors
- [ ] New or changed behavior is covered by E2E tests (`npm run test:e2e`)
- [ ] No new environment variables introduced without updating `.env.example`
- [ ] No schema changes without a corresponding Prisma migration
- [ ] SDK changes do not require database migrations (see [no-db-changes policy](CLAUDE.md))
- [ ] PR description explains the problem and the approach, not just the diff
- [ ] Security-sensitive paths (signing, verification, WebAuthn, fraud detection) have 80%+ test coverage

## Code Standards

- **TypeScript** strict mode across all packages
- **ESLint + Prettier** for formatting
- **Zod** for runtime schema validation
- 80%+ test coverage for security-critical paths (signing, verification, WebAuthn)

## SDK Contributions

We welcome SDKs in new languages. Every SDK must:

1. Implement the full `QRAuth` client interface (`create`, `verify`, `revoke`, `webhooks`)
2. Pass the QRVA protocol compliance test suite
3. Include type definitions (where the language supports them)
4. Provide a quickstart example in its README
5. Be published to the language's standard package registry

Existing SDKs for reference:
- **Node.js**: [`packages/node-sdk/`](packages/node-sdk/)
- **Python**: [`packages/python-sdk/`](packages/python-sdk/)

## Project Structure

| Package | Description |
|---|---|
| `packages/shared/` | TypeScript types, Zod schemas, crypto utilities |
| `packages/api/` | Fastify 5 API server |
| `packages/web/` | React 19 + MUI 7 dashboard |
| `packages/animated-qr/` | Living Codes renderer (MIT) |
| `packages/web-components/` | Drop-in custom elements (MIT) |
| `packages/node-sdk/` | Node.js SDK (MIT) |
| `packages/python-sdk/` | Python SDK (MIT) |
| `packages/e2e/` | Playwright E2E tests |

## License

By contributing, you agree that your contributions will be licensed under the [BSL 1.1](LICENSE) for core platform code, or [MIT](packages/node-sdk/LICENSE) for SDKs and client libraries.

The QRVA protocol specification is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
