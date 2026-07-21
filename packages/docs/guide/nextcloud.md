---
title: Sign in to Nextcloud with QRAuth
description: Add scan-to-login to a self-hosted Nextcloud using the official user_oidc app and QRAuth as the OpenID Provider. Step-by-step occ configuration, the required settings, and troubleshooting.
---

# Sign in to Nextcloud with QRAuth

Add **scan-to-login** to a self-hosted Nextcloud: users sign in by scanning a
QRAuth Living Code with their phone instead of typing a password. This uses
Nextcloud's official [`user_oidc`](https://github.com/nextcloud/user_oidc) app
with QRAuth as a standard OpenID Provider — no custom code, about ten minutes of
configuration.

This page is the Nextcloud-specific setup. For the underlying provider — issuer,
scopes, claims, PKCE, refresh tokens — see
[Sign in with QRAuth (OIDC)](/guide/oidc); this guide links to it rather than
repeating it.

The steps and values below were verified end-to-end against the production
issuer `https://id.qrauth.io` on **Nextcloud 33** with **`user_oidc` 8.10.1**.

## What you get

- A "Log in with QRAuth" button on the Nextcloud login page.
- First-time users are auto-provisioned as Nextcloud accounts on successful login.
- Returning users map back to the same account (the subject identifier is stable
  per client — see [Subject identifier](/guide/oidc#subject-identifier-sub)).

## Prerequisites

- A Nextcloud instance you administer, reachable over **HTTPS** (see the
  [HTTPS note](#nextcloud-must-be-served-over-https) in troubleshooting).
- Shell access to run `occ` (or an admin account for the equivalent web UI).
- A QRAuth **OIDC client** — a `client_id`, `client_secret`, and your
  Nextcloud redirect URI registered with QRAuth. See
  [Obtain OIDC client credentials](#obtain-oidc-client-credentials).

## Obtain OIDC client credentials

Register the OIDC client for your Nextcloud yourself from the QRAuth dashboard:
open **Sign-in Clients** (`/dashboard/sign-in-clients`) as an organization
**OWNER** or **ADMIN** and create a **confidential** client (see
[Client registration](/guide/oidc#client-registration)). When you create it you set:

- the **redirect URI** your Nextcloud will use (see
  [Find your redirect URI](#find-your-redirect-uri) — register the exact string),
- the scopes you need: `openid profile email offline_access`.

The `client_secret` is shown **once** at creation — copy it then, as it is not
retrievable afterwards.

::: warning Do not use "Create app" credentials from the dashboard
The QRAuth dashboard's **Create app** feature issues credentials for the QR-SDK
app model — a `client_id` shaped like `qrauth_app_…` with a `qrauth_secret_…`
secret. **These do not work for OIDC login.** The OpenID Connect endpoints only
recognise registered OIDC clients, so presenting app credentials fails at the
authorization step with `unknown client_id`. Create an OIDC client on the
**Sign-in Clients** page instead.
:::

Open-source projects and registered non-profits can run on QRAuth Pro free of
charge — see [pricing](https://qrauth.io/pricing).

## Find your redirect URI

`user_oidc`'s callback path is `/apps/user_oidc/code`. The full redirect URI is
that path on your Nextcloud's base URL — for most instances:

```
https://your-nextcloud.example/apps/user_oidc/code
```

If your Nextcloud serves non–pretty URLs (no URL rewriting), the value includes
`/index.php`:

```
https://your-nextcloud.example/index.php/apps/user_oidc/code
```

QRAuth matches the redirect URI **exactly** (byte-for-byte), so register the
precise string your instance emits. If you are unsure which form your instance
uses, confirm it after configuring the provider: start a login and inspect the
`redirect_uri` query parameter on the redirect to `https://id.qrauth.io/authorize`.

## Install and enable user_oidc

```bash
occ app:install user_oidc
occ app:enable user_oidc
```

(Or install **OpenID Connect user backend** from the Nextcloud app store.)

## Configure the QRAuth provider

```bash
occ user_oidc:provider qrauth \
  --clientid="<your client_id>" \
  --clientsecret="<your client_secret>" \
  --discoveryuri="https://id.qrauth.io/.well-known/openid-configuration" \
  --scope="openid profile email offline_access" \
  --mapping-uid=sub \
  --mapping-display-name=name \
  --mapping-email=email \
  --unique-uid=0
```

What each part does:

- `--discoveryuri` — QRAuth's discovery document; `user_oidc` reads every
  endpoint and the JWKS from it.
- `--scope` — `offline_access` is what makes QRAuth issue a refresh token so the
  Nextcloud session can be kept alive (see
  [Refresh tokens](/guide/oidc#refresh-tokens)).
- `--mapping-uid=sub`, `--mapping-display-name=name`, `--mapping-email=email` —
  map the QRAuth claims onto the Nextcloud account fields.
- `--unique-uid=0` — use the QRAuth `sub` directly as the Nextcloud username.
  See [Usernames are opaque](#usernames-are-opaque) for the trade-off.

## Required Nextcloud settings

Two settings are needed for a usable result. Both are properties of the
`user_oidc` system configuration.

### Pull name and email from UserInfo

QRAuth returns `name`, `email`, and `email_verified` from the **UserInfo
endpoint only** — they are not in the ID token (see
[Scopes and claims](/guide/oidc#scopes-and-claims)). By default `user_oidc`
provisions accounts from ID-token claims, so without the setting below, accounts
are created with a **blank display name and email** (both fall back to the
opaque subject identifier). Enable UserInfo enrichment so `user_oidc` fetches and
merges those claims:

```bash
occ config:system:set user_oidc enrich_login_id_token_with_userinfo --value=true --type=boolean
```

### UserInfo bearer-token validation

QRAuth access tokens are **opaque** (random strings, not JWTs) — they are
validated by calling UserInfo. If you use Nextcloud's API/WebDAV with OIDC bearer
tokens, set `user_oidc` to validate bearer tokens against the UserInfo endpoint
rather than decoding them as self-contained JWTs:

```bash
occ config:system:set user_oidc userinfo_bearer_validation --value=true --type=boolean
occ config:system:set user_oidc selfencoded_bearer_validation --value=false --type=boolean
```

## Verify login

1. Open your Nextcloud login page.
2. Click **Log in with qrauth**.
3. You are redirected to `https://id.qrauth.io`, which shows a QR code.
4. Scan it with your phone (signed in to QRAuth) and approve.
5. You are returned to Nextcloud, signed in.

Confirm the account was provisioned with the expected fields:

```bash
occ user:list
occ user:info <username>
```

The display name and email should match your QRAuth profile; the username is the
opaque subject identifier (next section).

## What to expect

### Usernames are opaque

QRAuth uses a **pairwise** subject identifier, so the `sub` — and therefore the
Nextcloud username, with `--unique-uid=0` — is an opaque, stable string unique to
your client (roughly 43 characters), not a human-readable handle. The display
name and email come from the mapped claims and are human-readable. If you omit
`--unique-uid=0`, `user_oidc` derives the username by hashing the subject instead;
either way the username is opaque, so map display name and email for anything
user-facing.

### No single logout

QRAuth does not expose an RP-initiated logout (`end_session_endpoint`) endpoint,
and none is advertised. Logging out of Nextcloud ends the **Nextcloud** session
only; while your QRAuth session is still alive, clicking **Log in with qrauth**
signs you back in silently without another scan. If you need to force
re-authentication on each login, drive it from the relying-party side with
`prompt=login` (see [Sign in with QRAuth (OIDC)](/guide/oidc)).

### Custom claims

The only QRAuth-namespaced claim emitted today is `qrauth:auth_method` (plus the
standard `acr`/`amr`). The other `qrauth:` scopes shown in discovery are not yet
returned — see
[The `qrauth:` claim namespace](/guide/oidc#the-qrauth-claim-namespace). The
mappings in this guide rely only on the standard `sub`, `name`, and `email`
claims.

## Troubleshooting

These are the failure modes you are most likely to hit.

### `unknown client_id` at the QRAuth login page

You are using QR-SDK **app** credentials (`qrauth_app_…`) instead of an OIDC
client. Request an OIDC client through the contact channel in
[Obtain OIDC client credentials](#obtain-oidc-client-credentials).

### Display name and email are blank

`enrich_login_id_token_with_userinfo` is not enabled. QRAuth serves `name` and
`email` from UserInfo only; see
[Pull name and email from UserInfo](#pull-name-and-email-from-userinfo). After
enabling it, log in again to refresh the account fields.

### Redirect URI mismatch

The redirect URI registered with QRAuth must match what your Nextcloud sends
**exactly**. Confirm whether your instance uses the pretty `/apps/user_oidc/code`
form or the `/index.php/apps/user_oidc/code` form and register that precise
string — see [Find your redirect URI](#find-your-redirect-uri).

### Nextcloud must be served over HTTPS

`user_oidc` refuses to start the login flow when Nextcloud is accessed over plain
HTTP, with: *"You must access Nextcloud with HTTPS to use OpenID Connect."* Serve
your Nextcloud over HTTPS.

For a **local, non-TLS test instance only**, you can bypass the check:

```bash
occ config:app:set user_oidc allow_insecure_http --value=1
```

::: danger
Never set `allow_insecure_http` on a production Nextcloud. It disables a
transport-security safeguard and is for local testing over `http://localhost`
only.
:::

## See also

- [Sign in with QRAuth (OIDC)](/guide/oidc) — the provider reference: issuer,
  endpoints, scopes, claims, PKCE, refresh tokens, and a minimal RP example.
- [Authentication](/guide/authentication) — the QR scan-to-approve flow QRAuth
  uses to authenticate the user behind the OIDC login.
- [Signing Architecture](/guide/signing-architecture) — how QRAuth signs the ID
  tokens your Nextcloud verifies.
