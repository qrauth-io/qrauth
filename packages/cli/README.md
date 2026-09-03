# @qrauth/cli

Official command-line interface for [QRAuth](https://qrauth.io) — scan-to-authenticate
login and QR code management from your terminal.

<a href="https://openid.net/certification/certified-openid-providers-profiles/"><img src="https://qrauth.io/assets/certifications/openid-certified.png" alt="OpenID Certified" width="180" /></a>

QRAuth is an **OpenID Certified™** OpenID Provider (Basic OP + Config OP profiles).

The CLI earns its place where it beats both the dashboard and the raw
[`@qrauth/node`](https://www.npmjs.com/package/@qrauth/node) SDK: **automation**
(scriptable, pipe-able with `--json`), **secret-free auth** (no raw API keys in
`.env` files or CI logs — credentials land in the OS keyring), and **speed under
pressure** (revoke a leaked session faster than clicking through the dashboard).

## Install

```bash
npm i -g @qrauth/cli
```

Requires Node.js 20 or newer.

## Quick start

```bash
qrauth login            # scan the QR with the QRAuth app to authenticate
qrauth whoami           # show the active org, role, and key prefix
qrauth qr list          # list QR codes for the active organization
```

`qrauth login` runs a PKCE scan-to-authenticate flow (ADR-0002): it prints a QR
code and a short verification code to the terminal. Scan the QR with the QRAuth
app, confirm the verification code matches, and a role-bounded API key is stored
locally — no key is ever pasted into a file or CI log.

## Commands

### Authentication & context

| Command | Description |
| --- | --- |
| `qrauth login` | Authenticate by scanning a QR code with the QRAuth app |
| `qrauth logout [--all]` | Revoke and remove the stored credential (`--all` for every org) |
| `qrauth whoami` | Show the active credential (organization, role, key prefix) |
| `qrauth orgs` | List organizations with stored credentials |
| `qrauth org use <slug>` | Set the active organization context |

### QR codes

| Command | Description |
| --- | --- |
| `qrauth qr create <destination> [--label <label>]` | Create a signed QR code for a destination URL |
| `qrauth qr list` | List QR codes for the active organization |
| `qrauth qr get <token>` | Show a QR code by token |
| `qrauth qr rm <token>` | Revoke a QR code by token |

### Ephemeral delegated access

| Command | Description |
| --- | --- |
| `qrauth ephemeral create <scopes...> [--ttl <dur>] [--max-uses <n>] [--device-binding]` | Create an ephemeral session with one or more scopes |
| `qrauth ephemeral list` | List ephemeral sessions for the active organization |
| `qrauth ephemeral revoke <sessionId>` | Revoke an ephemeral session by id |

## Global flags

| Flag | Description |
| --- | --- |
| `--json` | Output machine-readable JSON (progress UI goes to stderr, so stdout carries only the result) |
| `--org <slug>` | Override the active organization context for one command |
| `--api-url <url>` | QRAuth API base URL (also via `QRAUTH_API_URL`; defaults to the production API) |

## Scripting

Every command supports `--json`, making the CLI pipe-able in CI/CD:

```bash
# Batch-mint signed codes in a release job
cat skus.txt | while read sku; do
  qrauth qr create "https://shop.example/p/$sku" --label "$sku" --json
done

# Drive an ephemeral access session from a test stage
qrauth ephemeral create read:profile --ttl 10m --json
```

## License

MIT © [Gernard Cerma](https://github.com/aristech) / ProgressNet
