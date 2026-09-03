---
title: Sign in with QRAuth (OIDC)
description: QRAuth is an OpenID Certified OpenID Provider. Discover the issuer, scopes, claims, and how to integrate a standard OIDC relying party.
---

# Sign in with QRAuth (OIDC)

QRAuth is an **OpenID Certified™** OpenID Provider. Any application that speaks
standard OpenID Connect can add "Sign in with QRAuth" using an off-the-shelf
OIDC client library — discover the issuer, run the authorization-code flow with
PKCE, and read the user's claims from the ID token and UserInfo endpoint.

Every fact on this page is taken from the running provider implementation in
`packages/api` (the discovery document, the `/authorize`, `/token`, and
`/userinfo` handlers, and the ID-token builder). Where the published discovery
metadata advertises a capability that is not yet emitted by an endpoint, that is
called out explicitly.

## Certification

QRAuth is certified for the **Basic OP** and **Config OP** profiles of OpenID
Connect, approved by the OpenID Foundation on 2026-06-05. The certification is
listed in the OpenID Foundation's
[certified OpenID Providers directory](https://openid.net/certification/certified-openid-providers-profiles/)
under "QRAuth".

The Dynamic OP profile is **not** part of this certification — Dynamic Client
Registration is not enabled (see [Client registration](#client-registration)
below).

## Issuer and endpoints

The issuer identifier is `https://id.qrauth.io`. A conformant client only needs
the discovery URL; everything else is read from the discovery document.

| Endpoint | URL |
| --- | --- |
| Issuer | `https://id.qrauth.io` |
| Discovery | `https://id.qrauth.io/.well-known/openid-configuration` |
| JWKS | `https://id.qrauth.io/.well-known/jwks.json` |
| Authorization | `https://id.qrauth.io/authorize` (GET and POST) |
| Token | `https://id.qrauth.io/token` |
| UserInfo | `https://id.qrauth.io/userinfo` (GET and POST) |

There is no `end_session` / RP-initiated logout endpoint, and none is advertised.

## What the discovery document advertises

These values come verbatim from the published discovery document:

| Metadata | Value |
| --- | --- |
| `response_types_supported` | `code` |
| `response_modes_supported` | `query` |
| `grant_types_supported` | `authorization_code`, `refresh_token` |
| `subject_types_supported` | `pairwise` |
| `id_token_signing_alg_values_supported` | `RS256`, `ES256` |
| `token_endpoint_auth_methods_supported` | `client_secret_basic`, `client_secret_post`, `none` |
| `code_challenge_methods_supported` | `S256` |
| `scopes_supported` | `openid`, `profile`, `email`, `offline_access`, `qrauth:device_trust`, `qrauth:proximity`, `qrauth:fraud_signals`, `qrauth:auth_method` |

Only the authorization-code flow is supported (`response_type=code`,
`response_mode=query`).

## ID token signing

ID tokens are signed **RS256 by default** — the OIDC Core §15.1
mandatory-to-implement baseline, which every stock OIDC library can verify.
**ES256** is available as an opt-in, selected per client by setting
`id_token_signed_response_alg=ES256` at registration. Both algorithms' public
keys are published at the JWKS endpoint; a client selects the matching key by
`kid` and `alg`.

ID tokens carry the following claims:

- `iss`, `aud`, `sub`, `exp`, `iat`, `auth_time` — always present.
- `acr`, `amr` — always present (see [Authentication context](#authentication-context)).
- `nonce` — echoed only when the client supplied one on the authorization
  request.

## Subject identifier (`sub`)

The `sub` claim is **pairwise pseudonymous**: each client receives a different,
opaque `sub` for the same end user, so two clients cannot collude to correlate a
user across services. The value is stable for a given (client, user) pair and is
byte-identical between the ID token and the UserInfo response.

The pairwise sector is derived from the client's registered
`sector_identifier_uri` host when set, otherwise from the host of the client's
first redirect URI.

If you need a **stable, cross-client identifier** (for example to reconcile a
returning user against an existing account), request the `email` scope and join
on `email` + `email_verified` instead of `sub`.

## Scopes and claims

`openid` is required on every authorization request. A client may only request
scopes that are in its allow-list; an unknown or not-allowed scope is rejected
with `invalid_scope`.

### Standard claims (emitted today)

| Scope | Claims returned at `/userinfo` |
| --- | --- |
| `openid` | `sub` |
| `email` | `email`, `email_verified` |
| `profile` | `name`, `picture` (when the user has an avatar) |
| `qrauth:auth_method` | `qrauth:auth_method` |

### The `qrauth:` claim namespace

QRAuth's custom claims are namespaced under `qrauth:` and each is gated behind an
opt-in scope.

**Emitted today:**

- **`qrauth:auth_method`** (scope `qrauth:auth_method`) — how the user
  authenticated, one of `qr_living_code`, `passkey`, or `oauth_upstream`.

**Advertised in discovery, not yet emitted (Phase 2):** the discovery document
also lists the `qrauth:device_trust`, `qrauth:proximity`, and
`qrauth:fraud_signals` scopes, and the corresponding `qrauth:device_trust`,
`qrauth:proximity_attested`, `qrauth:proximity_geohash`,
`qrauth:proximity_distance_m`, and `qrauth:fraud_score` claims, in
`scopes_supported` / `claims_supported`. These are reserved for a future release
— the authorization and UserInfo endpoints do **not** return them today. Do not
build an integration that depends on them yet. (Per OIDC Discovery 1.0,
`claims_supported` is the set of claims the OP *may* be able to supply, not a
guarantee that every claim is returned for every request.)

## Authentication context

`acr` (authentication context class) and `amr` (authentication methods
reference, RFC 8176) are derived from how the user authenticated. Every OIDC
login reaches the provider by scanning a Living Code, so that is always the base;
a recent passkey or federated dashboard login strengthens the context:

| Underlying auth | `acr` | `amr` | `qrauth:auth_method` |
| --- | --- | --- | --- |
| Living Code only | `qrauth:living-code` | `["qrauth-living-code"]` | `qr_living_code` |
| + passkey | `qrauth:living-code+passkey` | `["qrauth-living-code", "hwk"]` | `passkey` |
| + federated (Google/GitHub/Microsoft/Apple) | `qrauth:living-code+oauth_upstream` | `["qrauth-living-code", "fed"]` | `oauth_upstream` |

## PKCE

PKCE with `S256` is the only supported challenge method (`plain` is always
rejected). It is **mandatory for public clients** — a client with no
`client_secret` must send a `code_challenge` or the authorization request is
rejected.

For **confidential clients** (those with a `client_secret`), PKCE is optional:
the client secret authenticates the token exchange. When a confidential client
*does* send a `code_challenge`, it must use `S256`.

::: tip
Sending PKCE on every request — public or confidential — is always safe and is
the recommended default.
:::

## Refresh tokens

Request the `offline_access` scope to receive a refresh token alongside the ID
and access tokens.

- **Opaque and hashed** — refresh tokens are random opaque strings, stored only
  as a hash.
- **Rotated on every use** — each `grant_type=refresh_token` call returns a new
  refresh token and invalidates the one presented.
- **Reuse detection** — presenting an already-rotated refresh token invalidates
  the entire token family for that grant, forcing re-authentication.
- **14-day family TTL** — refresh tokens expire 14 days from issuance.

Access tokens are opaque bearer tokens with a 1-hour lifetime; validate them by
calling `/userinfo`.

## Client registration

Register your OIDC clients yourself from the QRAuth dashboard — open
**Sign-in Clients** (`/dashboard/sign-in-clients`) and create a client. An
**OWNER** or **ADMIN** of the organization can create, edit, rotate secrets
for, and delete clients; other roles see the list read-only.

Dynamic Client Registration (DCR) is **not enabled** — the discovery document
does not advertise a `registration_endpoint`, and there is no public
`/register` endpoint. Registration is through the dashboard, not a protocol
call.

### Public vs confidential

Choose the client type at creation; it cannot be changed afterwards.

- **Public** — for browser or native apps that cannot keep a secret. No
  `client_secret` is issued; the client authenticates the code exchange with
  **PKCE (S256)**, which is mandatory for public clients.
- **Confidential** — for server-side apps. A `client_secret` is generated and
  **shown exactly once** at creation — store it immediately, it is not
  retrievable afterwards (only a hash is kept). Rotating the secret issues a
  new one and **invalidates the old secret immediately** — there is no overlap
  window, so update your app in the same change.

### Redirect URIs

Redirect URIs are matched **exactly** (no wildcards, no pattern matching), so
register every callback URL your app uses. Each must be:

- an absolute URI using **`https:`** — except loopback addresses
  (`http://localhost[:port]/…` or `http://127.0.0.1[:port]/…`), allowed for
  native/dev clients;
- free of a URL **fragment** (`#…`) and of embedded **credentials**
  (`user:pass@…`).

Duplicates are rejected. A client may register up to 10 redirect URIs.

### Scopes

The grantable scopes are:

- **`openid`** — required on every client.
- **`profile`**, **`email`** — standard OIDC claims.
- **`offline_access`** — issues a refresh token.
- **`qrauth:auth_method`** — the QRAuth auth-method claim
  (`qr_living_code` | `passkey` | `oauth_upstream`).

The other advertised `qrauth:*` claims (device trust, proximity, fraud
signals) are **not yet grantable** through self-serve registration and will
become available in a later phase.

### Sector identifier (pairwise subjects)

QRAuth issues **pairwise** `sub` values, derived from the client's sector. A
single-host client needs nothing extra. A client whose `redirect_uris` span
multiple hosts can set a **`sector_identifier_uri`** so its `sub` stays stable
across them; its host must **match the host of one of the client's registered
redirect URIs** (`https:` only). Fetch-and-verify of the sector document
itself is not performed yet, so the host-match rule is the current safeguard.

### Limits

An organization may register up to **20** sign-in clients. Delete an unused
client to free a slot.

## Minimal RP integration

The example below uses [`openid-client`](https://github.com/panva/node-openid-client),
a stock Node.js OIDC library, to run the full discover → authorize → token →
userinfo flow with PKCE.

```typescript
import * as client from 'openid-client'

// 1. Discover the provider from the issuer URL.
const issuer = new URL('https://id.qrauth.io')
const config = await client.discovery(issuer, process.env.QRAUTH_CLIENT_ID!, {
  client_secret: process.env.QRAUTH_CLIENT_SECRET, // omit for a public client
})

// 2. Build the authorization URL with PKCE (S256) + state.
const codeVerifier = client.randomPKCECodeVerifier()
const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier)
const state = client.randomState()

const authUrl = client.buildAuthorizationUrl(config, {
  redirect_uri: 'https://yourapp.com/callback',
  scope: 'openid email profile offline_access qrauth:auth_method',
  code_challenge: codeChallenge,
  code_challenge_method: 'S256',
  state,
})
// → redirect the user's browser to authUrl

// 3. On the callback, exchange the code for tokens (PKCE verifier + state checked).
const tokens = await client.authorizationCodeGrant(config, new URL(currentUrl), {
  pkceCodeVerifier: codeVerifier,
  expectedState: state,
})
const claims = tokens.claims() // verified ID-token claims (sub, email, acr, amr, …)

// 4. Fetch additional claims from UserInfo.
const userinfo = await client.fetchUserInfo(config, tokens.access_token, claims.sub)
console.log(userinfo.sub, userinfo.email, userinfo['qrauth:auth_method'])
```

The same flow works with any conformant OIDC library (for example
`oidc-client-ts` in the browser, or the OIDC middleware in your framework of
choice) — point it at the issuer `https://id.qrauth.io` and enable PKCE.

## See also

- [Quickstart](/guide/quickstart) — create an account and your first QR code.
- [Authentication](/guide/authentication) — the QR scan-to-approve auth-sessions
  flow and Web Components (the alternate, SDK-driven integration path).
- [Signing Architecture](/guide/signing-architecture) — how QRAuth signs tokens
  and QR codes, and the isolated signer service.
