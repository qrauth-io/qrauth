# Device Trust Registry

The Device Trust Registry lists the devices each user signs in from (including passkey registration and passkey sign-in) and their current trust standing. Devices progress through a state machine. The organization's device policy can revoke inactive devices automatically (`autoRevokeAfterDays`).

---

## Trust state machine

```
NEW ──► TRUSTED ──► SUSPICIOUS ──► REVOKED
         │                │
         └────────────────┘ (re-verify)
```

| State | Meaning |
|---|---|
| `NEW` | First seen — no history yet |
| `TRUSTED` | Marked trusted by the user |
| `SUSPICIOUS` | Marked suspicious by the user |
| `REVOKED` | Revoked by the user or by the auto-revoke policy; its passkeys are revoked |

`TRUSTED` and `SUSPICIOUS` are set by the signed-in user (`PATCH /devices/:id`). From `SUSPICIOUS` a device can be returned to `TRUSTED` via reverification (`POST /devices/:id/reverify`) or `REVOKED`. Devices move to `REVOKED` when the user revokes them or when the auto-revoke policy applies.

---

## Device identification

A device is identified per user by a fingerprint:

- If the request carries an `X-Device-Fingerprint` header, its value is used as the fingerprint.
- Otherwise the server parses the User-Agent and uses the SHA-256 hash of `browser|OS|device type`.

Alongside the fingerprint, the registry stores the parsed browser, OS and device type, and the country and city derived from the request IP.

---

## Passkey binding

WebAuthn passkeys are linked to the device they were registered from. Passkeys are registered through the WebAuthn routes, not the device API. Revoking a device revokes the passkeys linked to it.

---

## API reference

### List devices

```
GET /api/v1/devices
```

Returns the signed-in user's non-revoked devices, sorted by last-seen descending.

```ts
const res = await fetch('https://qrauth.io/api/v1/devices', {
  headers: { Authorization: `Bearer ${token}` },
});
const { data: devices } = await res.json();
// devices[].id, .fingerprint, .trustLevel, .browser, .os, .deviceType, .lastSeenAt, .passkeyCount
```

### Update device trust

```
PATCH /api/v1/devices/:id
```

```json
{ "trustLevel": "TRUSTED" }
```

### Revoke a device

```
POST /api/v1/devices/:id/revoke
```

Moves the device to `REVOKED`, revokes the passkeys linked to it, and ends the user's OIDC sessions and tokens.

```ts
await fetch(`https://qrauth.io/api/v1/devices/${deviceId}/revoke`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${token}` },
});
```

### Reverify a device

```
POST /api/v1/devices/:id/reverify
```

Transitions the device from `SUSPICIOUS` back to `TRUSTED` for the signed-in owner. Returns `409` if the device is not `SUSPICIOUS`.

---

## Device policy

Set per-organization device policy. `PUT` requires the OWNER or ADMIN role.

```
GET  /api/v1/devices/policy
PUT  /api/v1/devices/policy
```

### Policy fields

| Field | Type | Default | Description |
|---|---|---|---|
| `autoRevokeAfterDays` | `number \| null` | `null` | Revoke devices inactive for N days (1-365). See [Auto-revocation](#auto-revocation). |
| `maxDevices` | `number` | `10` | Stored with the policy (1-100) |
| `requireBiometric` | `boolean` | `false` | Stored with the policy |
| `geoFenceLat`, `geoFenceLng`, `geoFenceRadiusKm` | `number \| null` | `null` | Stored with the policy |

### Update policy

::: code-group

```ts [Node.js]
const policy = await fetch('https://qrauth.io/api/v1/devices/policy', {
  method: 'PUT',
  headers: {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    autoRevokeAfterDays: 90,
  }),
}).then(r => r.json());
```

```python [Python]
import httpx

resp = httpx.put(
    "https://qrauth.io/api/v1/devices/policy",
    headers={"Authorization": f"Bearer {token}"},
    json={
        "autoRevokeAfterDays": 90,
    },
)
policy = resp.json()
```

:::

---

## Auto-revocation

The background cleanup worker runs hourly and revokes any non-revoked device belonging to a member of the organization whose `lastSeenAt` is older than `autoRevokeAfterDays`. Revoked devices remain in the database for audit purposes.

::: tip Inactivity window
Set `autoRevokeAfterDays: 30` for consumer apps and `autoRevokeAfterDays: 1` for high-security environments like event check-in kiosks.
:::

---

## Dashboard

The device registry is available in the dashboard at **Devices** (`/dashboard/devices`). From there users can:

- View their devices and trust states.
- Mark a device trusted or revoke it.
- Manage the passkeys linked to each device.
