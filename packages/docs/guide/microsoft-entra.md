---
title: Microsoft Entra ID admin guide
description: What QRAuth requests when your users sign in with a Microsoft work or school account, how a tenant administrator approves it, how to restrict access, and how to fix common sign-in errors.
---

# Microsoft Entra ID admin guide

This page is for Microsoft Entra ID (formerly Azure AD) administrators whose
users sign in to QRAuth with their organisational Microsoft account. It states
exactly what QRAuth requests, how to approve the application for your tenant,
how to limit who can use it, and how to resolve the errors users are most likely
to meet.

Every fact on this page is taken from the running implementation in
`packages/api` and from the QRAuth app registration.

## What QRAuth does with Microsoft sign-in

"Continue with Microsoft" on the QRAuth sign-in page lets a user prove who they
are with their work or school account instead of a QRAuth password. The direct
sign-in address is
[https://qrauth.io/auth/jwt/sign-in](https://qrauth.io/auth/jwt/sign-in).

**Protocol:** OpenID Connect on the OAuth 2.0 authorization code flow (Microsoft
identity platform v2.0). QRAuth is a confidential web client; sign-in is started
from QRAuth (service-provider initiated).

**Licensing:** No Microsoft licence is required for sign-in. Any work or school
account in the tenant can sign in, subject to admin consent and assignment.

It is a sign-in only integration:

- QRAuth reads the user's **name** and **email address** from the ID token that
  Microsoft issues at sign-in, together with the user's object ID and tenant ID.
- QRAuth has **no access to mail, files, calendars, contacts, Teams, or
  directory data**. It does not call Microsoft Graph.
- QRAuth does not receive a refresh token, so it cannot act on a user's behalf
  after the sign-in has completed.
- The user's Microsoft password is entered at Microsoft and is never seen by
  QRAuth. Your Conditional Access and multifactor policies apply as usual.

Only work and school accounts are supported. The application is registered for
accounts in organisational directories only, and QRAuth sends users to
Microsoft's work-and-school sign-in endpoint (`/organizations`), so personal
Microsoft accounts (Outlook, Hotmail, Live) cannot be used.

## Permissions and justification

At sign-in QRAuth requests three OpenID Connect scopes and nothing else:

| Scope | What it allows | Why QRAuth needs it |
|-------|----------------|---------------------|
| `openid` | Sign the user in and issue an ID token | Required for any OpenID Connect sign-in. Provides the immutable object ID (`oid`) and tenant ID (`tid`) that identify the user. |
| `profile` | Read the user's basic profile | Provides the display name shown in the QRAuth dashboard. |
| `email` | Read the user's email address | Provides the address for the user's QRAuth account, and lets an existing QRAuth account with the same verified address be matched. |

The app registration lists one Microsoft Graph **delegated** permission, which
is what an administrator sees under **Permissions** in the Entra admin center:

| Graph permission | Type | Use |
|------------------|------|-----|
| `email` (View users' email address) | Delegated | The `email` scope above. |

`User.Read` is not requested and is not on the registration.

To be explicit:

- **Delegated permissions only.** QRAuth holds no application permissions
  (app roles) and cannot do anything without a user actively signing in.
- **No offline access to Microsoft data.** `offline_access` is not requested, so
  no refresh token is issued.
- **No Graph calls.** The access token returned by Microsoft is not used and is
  not stored. Identity comes only from the ID token, after its signature,
  audience, issuer and tenant have been verified.

The registration also asks Microsoft to include two optional claims in the ID
token: `email` and `xms_edov` (see [User identification](#user-identification)).

## Publisher

Use these details to confirm that the application in your tenant is QRAuth:

| Property | Value |
|----------|-------|
| Application name | QRAuth |
| Application (client) ID | `8e4af711-ee74-4f67-bdc1-fbe970244af9` |
| Verified publisher | PROGRESSNET E.E. |
| Publisher domain | `progressnet.gr` |
| Supported account types | Accounts in any organisational directory (multitenant). No personal Microsoft accounts. |
| Redirect URIs | `https://qrauth.io/api/v1/auth/oauth/microsoft/callback` (sign-in) and `https://qrauth.io/api/v1/auth/oauth/microsoft/admin-consent` (admin consent result page) |
| Privacy statement | [https://qrauth.io/privacy](https://qrauth.io/privacy) |
| Terms of service | [https://qrauth.io/terms](https://qrauth.io/terms) |
| Support | This page |

QRAuth is built and operated by ProgressNet, which is why the verified
publisher and publisher domain carry the ProgressNet name. The consent screen
shows the blue "verified" badge next to the publisher. If the client ID or
publisher you see does not match this table, do not approve the request.

## Admin approval

Whether your users can approve QRAuth themselves depends on your tenant's user
consent settings. If user consent is disabled or limited, users see
"Need admin approval" and an administrator has to grant consent once for the
whole organisation. A Privileged Role Administrator, Cloud Application
Administrator or Application Administrator can do this.

### Option 1: admin consent URL

1. Open the following URL in a browser, replacing `{tenant}` with your tenant ID
   or a verified domain such as `contoso.com`:

   ```text
   https://login.microsoftonline.com/{tenant}/adminconsent?client_id=8e4af711-ee74-4f67-bdc1-fbe970244af9&redirect_uri=https://qrauth.io/api/v1/auth/oauth/microsoft/admin-consent
   ```

2. Sign in with an administrator account.
3. Check the publisher and the permissions against this page, then select
   **Accept**.
4. Microsoft sends you to a QRAuth confirmation page: "QRAuth is now approved
   for your organisation. Your users can sign in with Microsoft." If you decline
   or Microsoft reports a problem, the page shows the error code instead. This
   step does not sign anyone in to QRAuth.

### Option 2: Entra admin center

The QRAuth enterprise application appears in your tenant after the first user
has attempted to sign in, or after Option 1 has been used.

1. Go to the [Microsoft Entra admin center](https://entra.microsoft.com) and
   open **Entra ID** > **Enterprise apps**.
2. Search for **QRAuth** and confirm the application ID matches the one above.
3. Open **Security** > **Permissions**.
4. Select **Grant admin consent for _your organisation_** and accept.

### Admin consent workflow

If your tenant has the admin consent workflow enabled, a user who is blocked
sees **Approval required** and can type a justification and select **Request
approval**. The request reaches the reviewers you have designated, who approve
it under **Enterprise apps** > **Admin consent requests**. Once approved, the
user is notified by email and can sign in.

## Restricting access (optional)

By default every user in your tenant can sign in to QRAuth once consent has been
granted. To limit sign-in to selected people:

1. In the Entra admin center, open **Enterprise apps** > **QRAuth** >
   **Properties**.
2. Set **Assignment required?** to **Yes** and save.
3. Open **Users and groups** and add the users or groups that may sign in.

Two things to know:

- When assignment is required, users cannot consent for themselves. Grant admin
  consent first (see above).
- A user who is not assigned is stopped by Microsoft with error `AADSTS50105`
  and never reaches QRAuth.

## User identification

QRAuth identifies a Microsoft user by the `oid` claim: the user's object ID in
your tenant. It is immutable, is never reassigned, and does not change when the
user's name, email address or user principal name changes. A returning user is
always matched on `oid` first.

The email address is treated with more caution, because an email attribute can
be set to any value by a directory administrator. QRAuth uses the `email` claim
only when Microsoft also sends `xms_edov` set to `true`, which means the
address's domain has been verified by its owner in the user's tenant. In
practice:

| Situation | Result |
|-----------|--------|
| The user has signed in before (known `oid`) | Signed in. The email claim is not consulted. |
| First sign-in, email verified, no QRAuth account with that address | A new QRAuth account is created. |
| First sign-in, email verified, a QRAuth account with that address exists | Signed in to that account, and the Microsoft identity is linked to it. |
| First sign-in, email present but not verified | Sign-in is refused. No account is created or linked. |
| First sign-in, no email attribute, no QRAuth account with the user's sign-in name | A new QRAuth account is created from the sign-in name. Its address is marked unverified. |
| First sign-in, no email attribute, a QRAuth account with the user's sign-in name exists | Sign-in is refused. The existing account is never linked. |

Users without an email attribute, for example accounts with no mailbox, are
therefore created from their sign-in name (the `preferred_username` claim, for
example `user@contoso.onmicrosoft.com`), marked unverified, and never linked to
existing accounts. Guest sign-in names (containing `#EXT#`) are not accepted.
On later sign-ins these users are matched on `oid` like everyone else.

QRAuth never reads `mail` or `userPrincipalName` from Microsoft Graph.

## Testing with pilot users

Before a wider rollout, try the flow with a few users. If you use
**Assignment required**, assign the pilot users first.

A pilot user does the following:

1. Opens [https://qrauth.io/auth/jwt/sign-in](https://qrauth.io/auth/jwt/sign-in).
2. Selects **Continue with Microsoft** (labelled "Work or school accounts
   only").
3. Chooses their work account in the Microsoft account picker, and completes
   any multifactor or Conditional Access step your tenant requires.
4. If no administrator has granted consent and your tenant allows user consent,
   reviews the permissions and selects **Accept**. With admin consent in place
   this screen does not appear.
5. Is returned to QRAuth. On a first sign-in QRAuth creates an account and a default
   organisation for the user and starts onboarding; on later
   sign-ins the user lands on the dashboard.

What to check with the pilot group: the consent screen shows the verified
publisher, the user lands in QRAuth with the expected name and email address,
and a second sign-in returns to the same account.

## Troubleshooting

### "Need admin approval" or "Approval required"

**Cause:** your tenant does not allow users to consent to applications, or not
to this one.
**Fix:** grant admin consent as described in [Admin approval](#admin-approval),
or approve the user's request in the admin consent workflow.

### AADSTS90094

**Cause:** the sign-in needs permissions that only an administrator can grant
in your tenant.
**Fix:** grant admin consent for the organisation.

### AADSTS65001

**Cause:** neither the user nor an administrator has consented to QRAuth. This
is common when **Assignment required** is on, because user consent is then not
available.
**Fix:** grant admin consent for the organisation.

### AADSTS50105

**Cause:** **Assignment required** is on and the user is not assigned to the
QRAuth enterprise application.
**Fix:** add the user, or a group they belong to, under **Users and groups**.

### AADSTS53003 or another Conditional Access block

**Cause:** a Conditional Access policy in your tenant blocked the sign-in, for
example because of device compliance, location or sign-in risk. The decision is
made by Microsoft before QRAuth is involved.
**Fix:** open **Entra ID** > **Sign-in logs**, find the failed sign-in to
QRAuth and read the **Conditional Access** tab to see which policy applied.
Adjust the policy, or have the user meet its requirements.

### "We couldn't sign you in with that account"

The user completed the Microsoft sign-in but QRAuth refused it. QRAuth shows
the same message for every refusal so that it does not reveal whether an
account exists.

**Cause:** on a first sign-in, one of the following applied:

- The user's email address is on a domain that is not verified in your tenant,
  so Microsoft did not vouch for it.
- The user has no email attribute, and a QRAuth account already exists for
  their sign-in name. QRAuth does not attach a Microsoft identity to an
  existing account on the strength of a sign-in name alone.

**Fix:** in the Entra admin center, check the user's **Email** property. Set it
to an address on a domain listed as verified under **Entra ID** > **Domain
names**, or verify the domain. Then ask the user to sign in again. A user with
no email attribute and no existing QRAuth account does not need any change.

### A personal Microsoft account is rejected

**Cause:** the user tried a personal account (Outlook, Hotmail, Live). Microsoft
stops these at its own sign-in page, because QRAuth accepts work and school
accounts only.
**Fix:** sign in again and choose the work or school account.

## Data handling and support

From a Microsoft sign-in QRAuth stores the user's object ID, email address and
display name, and a record of each sign-in for security auditing. It does not
store Microsoft access tokens or ID tokens.

- [Privacy policy](https://qrauth.io/privacy)
- [Terms of service](https://qrauth.io/terms)
- [Security](https://qrauth.io/security)
- [Data processing agreement](https://qrauth.io/dpa) and
  [subprocessors](https://qrauth.io/subprocessors)

For help with a rollout, write to [hello@qrauth.io](mailto:hello@qrauth.io). To
report a security issue, write to
[security@qrauth.io](mailto:security@qrauth.io).

To remove QRAuth from your tenant, delete the QRAuth enterprise application in
the Entra admin center. This revokes all consent; users can then no longer sign
in with Microsoft.

## See also

- [Authentication](/guide/authentication) — the sign-in methods QRAuth offers.
- [Sign in with QRAuth (OIDC)](/guide/oidc) — using QRAuth itself as an
  OpenID Provider for your own applications.
- [Device Trust](/guide/device-trust) — device registration and policy after
  sign-in.
