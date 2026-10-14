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
`/userinfo` handlers, and the ID-token builder). The discovery document
advertises only what the endpoints return.

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
| End session (logout) | `https://id.qrauth.io/logout` (GET and POST) |
| Revocation | `https://id.qrauth.io/revoke` |

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
| `scopes_supported` | `openid`, `profile`, `email`, `offline_access`, `qrauth:auth_method` |
| `claims_supported` | `sub`, `iss`, `aud`, `exp`, `iat`, `auth_time`, `nonce`, `acr`, `amr`, `name`, `picture`, `email`, `email_verified`, `qrauth:auth_method` |

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

The pairwise sector is one host, fixed when the client is created: the host
of its `sector_identifier_uri` if it has one, otherwise the host its redirect
URIs are on. It never changes afterwards, so editing or reordering redirect
URIs does not change any user's `sub`.

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

**Reserved, not available:** `qrauth:device_trust`, `qrauth:proximity` and
`qrauth:fraud_signals` are planned scopes. They are not in the discovery
document, cannot be granted, and no endpoint returns their claims. Discovery
lists only what the provider returns today.

## Consent

The first time a user signs in to your client, QRAuth shows them a consent
page: your client's name, your organization's name, the host they will be sent
back to, and what each requested scope shares. Nothing is issued until they
choose **Allow**.

- **Remembered per user and client.** Later requests for the same or fewer
  scopes skip the page. Asking for a scope the user has not yet allowed shows
  it again.
- **`prompt=consent`** always shows the page.
- **`prompt=none`** never shows it: if consent is missing the request returns
  `error=consent_required` to your redirect URI.
- **Deny** returns `error=access_denied` to your redirect URI, with your
  `state`.
- **Revocable.** Users can remove your client under *Settings → Connected
  apps* in the QRAuth dashboard. That revokes its tokens for that user, and the
  next sign-in asks again.

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

**Treat `acr`, `amr` and `qrauth:auth_method` as advisory.** They describe the
user's most recent dashboard sign-in around the time of the scan, not a
verified property of the approval itself, and they are worked out again when
a token is refreshed. Do not use them as the only basis for an access
decision such as step-up; use `auth_time` and `max_age` or `prompt=login` to
require a fresh scan.

## Authorization codes

A code is valid for 60 seconds and can be redeemed once. Exchange it as soon
as the browser returns to your `redirect_uri`. Presenting a code a second time
is treated as a leak: the request is refused and the access and refresh tokens
issued from the first redemption are revoked.

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

::: warning
`offline_access` cannot currently be added to a client registered from the
dashboard or the client API. Contact us if your integration needs refresh
tokens.
:::

- **Opaque and hashed** — refresh tokens are random opaque strings, stored only
  as a hash.
- **90-day limit** — a refresh token family lasts at most 90 days from the
  original sign-in, however often it is rotated. After that the user signs in
  again.
- **Re-checked on every use** — the scope is cut to what your client is still
  registered for and what the user still consents to; if `openid` is no longer
  covered the grant ends with `invalid_grant`.
- **Rotated on every use** — each `grant_type=refresh_token` call returns a new
  refresh token and invalidates the one presented.
- **Reuse detection** — presenting an already-rotated refresh token invalidates
  the entire token family for that grant, forcing re-authentication.
- **14-day family TTL** — refresh tokens expire 14 days from issuance.

Access tokens are opaque bearer tokens with a 1-hour lifetime; validate them by
calling `/userinfo`.

## Sessions: every sign-in is a scan

Pressing "Sign in with QRAuth" always shows the QR code. QRAuth does not sign
a returning browser in silently, so a user who signed out of your application,
or the next person at a shared computer, has to scan again.

QRAuth keeps a session at `id.qrauth.io` for 15 minutes after a scan. It is
used only when your request asks for it:

- **`prompt=none`** returns a code without showing anything if that session
  exists, and `login_required` if it does not.
- **`max_age=<seconds>`** reuses the session when the scan is at most that old,
  and shows the QR code otherwise. `max_age=0` always shows it.
- **`prompt=login`** always shows the QR code.

A request with none of these shows the QR code, whatever session exists.

## Signing out and revoking tokens

**Call the `end_session_endpoint` when the user signs out of your
application.** Clearing your own session is not enough on its own: for up to
15 minutes a `prompt=none` or `max_age` request from the same browser would
still succeed. Ending the session at QRAuth closes that window.

**RP-initiated logout.** Send the browser to the `end_session_endpoint` with
the user's ID token as `id_token_hint` (an expired one is fine) and, if you
want them back, a `post_logout_redirect_uri` plus `state`:

```
https://id.qrauth.io/logout?id_token_hint=<id token>&post_logout_redirect_uri=https://yourapp.com/signed-out&state=<state>
```

- The redirect only happens to a URI registered on your client as a
  post-logout redirect URI, compared exactly. Otherwise the user sees
  QRAuth's own signed-out page.
- Without a valid `id_token_hint` for the signed-in user, QRAuth asks the user
  to confirm before ending the session.

**Token revocation (RFC 7009).** `POST` the token to the
`revocation_endpoint`, authenticating as you do at the token endpoint.
Revoking a refresh token ends the whole grant: its rotation family and the
access tokens issued to your client for that user. The response is `200`
whether or not the token was known.

**What ends a session without you asking.** QRAuth ends the user's OP session
and revokes the tokens issued to relying parties when the user resets their
password, revokes a device, signs out everywhere, or removes your client under
*Connected apps*.

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

All redirect URIs must be on **one host**; loopback addresses are exempt, so a
production host plus `localhost` for development is fine. That host is the
client's pairwise sector and cannot be changed later: to move to a different
host, register a new client (your users will get new `sub` values there).

### Scopes

The grantable scopes are:

- **`openid`** — required on every client.
- **`profile`**, **`email`** — standard OIDC claims.
- **`qrauth:auth_method`** — the QRAuth auth-method claim
  (`qr_living_code` | `passkey` | `oauth_upstream`).

No other `qrauth:*` scope exists yet.

### Sector identifier (pairwise subjects)

QRAuth issues **pairwise** `sub` values, derived from the client's sector
host. A client needs nothing extra. A **`sector_identifier_uri`** is optional
and, when set, must be `https:` and on the same host as the client's redirect
URIs. Clients whose redirect URIs span several hosts are not supported yet:
that needs fetch-and-verify of the sector document (OIDC Core §8.1), which is
not implemented.

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
  scope: 'openid email profile qrauth:auth_method',
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
- [Microsoft Entra ID admin guide](/guide/microsoft-entra) — for tenant
  administrators whose users reach QRAuth with a Microsoft work or school
  account (the `fed` upstream above): permissions, admin consent, troubleshooting.
- [Signing Architecture](/guide/signing-architecture) — how QRAuth signs tokens
  and QR codes, and the isolated signer service.
