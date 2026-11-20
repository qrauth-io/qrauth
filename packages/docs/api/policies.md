---
title: Organization Policies
description: Limit QR code destinations to an allowlist of domains and choose which role may change where a code points.
---

# Organization Policies

An organization has one policy with two settings:

- **Destination allowlist.** When enforced, a code's destination, and every link of a [smart link or link list](./qrcodes#smart-link-and-link-list) code, must be on one of the listed domains. Other content types (vCard, event, coupon, PDF, feedback) point at their own hosted page and are not affected.
- **Destination-edit role.** The lowest role that may change where a code points (its destination or content) or restore an earlier destination. The default, `MEMBER`, is the rule without a policy.

Every change to the policy is recorded in the [audit log](./audit-log) as `policy.update`, with the policy before and after.

## Access

| | |
|---|---|
| Plan | Business and above to enable or change a policy. Below Business, a policy already in force stays in force and can only be switched off (see [Plan changes](#plan-changes)) |
| Role | `OWNER` or `ADMIN`. Changes and previews re-read the caller's role from the membership on each request (an API key: the lower of its role and its owner's current role) |
| Scope | The caller's organization only |

**Headers:** `X-API-Key: <key>`

## The allowlist

Each entry is a **registrable domain**: the domain one level below a public suffix of the [Public Suffix List](https://publicsuffix.org/). Submitted entries are normalised:

| Submitted | Stored | Note |
|-----------|--------|------|
| `Example.COM` | `example.com` | |
| `www.shop.example.co.uk` | `example.co.uk` | Reduced to the registrable domain |
| `https://www.example.com/path` | `example.com` | Only the domain is kept |
| `*.example.com` | `example.com` | Subdomains come from `includeSubdomains`, not a wildcard |
| `alice.github.io` | `alice.github.io` | `github.io` is a public suffix, so each name under it is its own domain |
| `münchen.de` | `xn--mnchen-3ya.de` | Stored in punycode; `unicode` holds `münchen.de` for display |
| `co.uk`, `github.io` | refused | A public suffix: anyone can register names under it |
| `192.0.2.1`, `localhost`, `intranet` | refused | Not a public domain name |

A domain listed twice is merged (subdomains included if either entry includes them). The list is sorted by domain and holds at most 200 entries.

A destination host is allowed when it is an entry's domain or, with `includeSubdomains` (the default), a subdomain of it. Hosts are compared in punycode, so an internationalised entry matches the same name written in Unicode or punycode, and never a different name that only looks alike (`exаmple.com` with a Cyrillic `а` does not match `example.com`).

An allowed destination still goes through every other check: the `http`/`https` and public-host rules, Google Web Risk screening, and the [lookalike domain check](../guide/fraud-detection).

### What is checked

When the allowlist is enforced, every request that sets or changes where a code points is checked:

- [Create](./qrcodes#create-qr-code) and [bulk create](./qrcodes#bulk-create) (per item);
- [Update](./qrcodes#update-qr-code), when the destination or the links change. Resending the current destination (in any spelling) or the current content is not a change, so saving a code's label, tags, style, expiry or limits is never refused;
- [Restore a destination](./qrcodes#restore-a-destination).

A destination outside the list is refused with `422`:

```json
{
  "statusCode": 422,
  "error": "Unprocessable Entity",
  "code": "destination-not-allowed",
  "message": "elsewhere.example.net is not on this organization's destination allowlist. Allowed: example.com (and subdomains).",
  "outside": ["https://elsewhere.example.net/spring"],
  "allowedDomains": [{ "domain": "example.com", "includeSubdomains": true, "unicode": "example.com" }]
}
```

In a bulk create, such an item fails with `errorCode` `DESTINATION_NOT_ALLOWED` and the others are created.

### Codes outside the list

Enforcing a list does not change existing codes. Codes whose destination or links are outside it keep working and are marked `outsidePolicy: true` in [List QR Codes](./qrcodes#list-qr-codes) and [Get QR Code](./qrcodes#get-qr-code); filter with `outsidePolicy=true`. Their destination can only be changed to an allowed domain. The mark is recalculated whenever the policy changes, and cleared when the code's destination is changed to an allowed one or the allowlist is switched off. Revoked codes are never marked.

Use [Preview](#preview) before enforcing a list to see which codes it would mark.

## The destination-edit role

| `destinationEditMinRole` | Who can change destinations and content |
|---|---|
| `MEMBER` (default) | `OWNER`, `ADMIN`, `MANAGER`, `MEMBER` |
| `MANAGER` | `OWNER`, `ADMIN`, `MANAGER` |
| `ADMIN` | `OWNER`, `ADMIN` |

Restoring a destination needs `MANAGER` or above in any case; with `ADMIN`, it needs `ADMIN`. Creating codes and editing a code's label, tags, folder, style, expiry and scan limits are not affected.

With a minimum above `MEMBER`, the role is read from the organization's membership on every request:

- **Signed-in members:** their current role. A member who was demoted or removed is refused at once, even with a session that is still valid.
- **API keys** belong to the member who created them and act with the lower of the key's role and that member's current role. A key is allowed while both meet the minimum: a `MEMBER` key never does, so give a key the `MANAGER` or `ADMIN` role when you create it (up to your own role) if it must change destinations. It is refused once its owner is demoted below the minimum or leaves the organization.
- **Legacy API keys** (created before keys recorded an owner) have none, so they cannot change destinations while the minimum is above `MEMBER`. They can still create codes and edit other settings. `apiKeysWithoutCreator` in the policy counts the active ones; [rotate](../guide/authentication#rotate-an-api-key) them to replace each with a key you own.

A refusal is `403`:

```json
{
  "statusCode": 403,
  "error": "Forbidden",
  "code": "destination-edit-role-required",
  "requiredRole": "MANAGER",
  "message": "Changing a code's destination requires the Manager role or higher in this organization. You can still edit the code's label, tags and other settings."
}
```

## Plan changes

Policies are enabled and changed on the Business plan and above. When an organization moves to a lower plan, its policy stays in force. It can then only be switched off: `allowlistMode` to `OFF` and/or `destinationEditMinRole` to `MEMBER`, with the same allowlist. Leave `allowlist` out of the request to keep the stored list exactly as it is. Any other change is refused with `403` and `code` `governance-plan-required`, and `editable` is `false`.

---

## Get the Policy

`GET /api/v1/policies`

Available on every plan. An organization that has never set a policy gets the defaults.

**Response (200):**

```json
{
  "allowlistMode": "ENFORCE",
  "allowlist": [
    { "domain": "example.com", "includeSubdomains": true, "unicode": "example.com" },
    { "domain": "xn--mnchen-3ya.de", "includeSubdomains": false, "unicode": "münchen.de" }
  ],
  "destinationEditMinRole": "MANAGER",
  "updatedAt": "2026-11-03T14:20:05.112Z",
  "editable": true,
  "outsidePolicyCount": 1,
  "apiKeysWithoutCreator": 1
}
```

| Field | Description |
|-------|-------------|
| `allowlistMode` | `OFF` or `ENFORCE` |
| `allowlist` | Stored entries; `domain` in punycode, `unicode` for display |
| `destinationEditMinRole` | `MEMBER`, `MANAGER` or `ADMIN` |
| `updatedAt` | Last change; `null` when the policy was never set |
| `editable` | `false` below the Business plan |
| `outsidePolicyCount` | Codes currently marked outside the allowlist |
| `apiKeysWithoutCreator` | Active legacy API keys (no owner) |

## Update the Policy

`PUT /api/v1/policies`

Replaces the whole policy and returns it, as [Get the Policy](#get-the-policy). A request that changes nothing records nothing.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `allowlistMode` | string | Yes | `OFF` or `ENFORCE`. `ENFORCE` needs at least one domain |
| `allowlist` | array | No | Up to 200 `{ "domain": string, "includeSubdomains"?: boolean }`; `includeSubdomains` defaults to `true`. Omitted: the stored list is kept as it is (not normalised again) |
| `destinationEditMinRole` | string | Yes | `MEMBER`, `MANAGER` or `ADMIN` |

```bash
curl -X PUT https://qrauth.io/api/v1/policies \
  -H "X-API-Key: $QRAUTH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"allowlistMode":"ENFORCE","allowlist":[{"domain":"example.com"}],"destinationEditMinRole":"MANAGER"}'
```

**Errors:**

| Status | `code` | When |
|--------|--------|------|
| `400` | — | A missing or unknown field, an unknown mode or role, more than 200 entries |
| `403` | — | The caller's role is not `OWNER` or `ADMIN` |
| `403` | `policy-role-required` | The caller's current membership role (re-read for the change) is below `ADMIN`, e.g. after a demotion |
| `403` | `governance-plan-required` | Below the Business plan, a change other than switching off |
| `422` | `policy-invalid` | An entry is not a valid domain (`entries` gives the outcome of each, in order), or `ENFORCE` with no domains. Nothing is changed |

## Preview

`POST /api/v1/policies/preview`

How an allowlist would be stored, and which active codes it would leave outside. Changes nothing. Business plan and above.

**Request:** `{ "allowlist": [{ "domain": "www.example.com" }, { "domain": "co.uk" }] }`

**Response (200):**

```json
{
  "entries": [
    {
      "input": "www.example.com",
      "ok": true,
      "entry": { "domain": "example.com", "includeSubdomains": true, "unicode": "example.com" },
      "note": "Reduced to the registrable domain example.com."
    },
    { "input": "co.uk", "ok": false, "message": "“co.uk” is a public suffix: anyone can register names under it. Enter your own domain, such as example.co.uk." }
  ],
  "allowlist": [{ "domain": "example.com", "includeSubdomains": true, "unicode": "example.com" }],
  "affected": [
    { "token": "Kp3vQx9a", "label": "Spring campaign", "contentType": "url", "outside": ["https://elsewhere.example.net/spring"] }
  ],
  "affectedTotal": 1
}
```

`entries` lists each submitted entry in order; `allowlist` is what would be stored (invalid entries left out). `affected` holds the first 100 active codes outside the list, with only the destinations that are not allowed; `affectedTotal` counts them all.
