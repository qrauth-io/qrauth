# Device Trust Registry

The Device Trust Registry tracks which physical devices have interacted with your QR codes and their current trust standing. Devices progress through a state machine. Policy rules automate promotion and revocation based on scan history, biometric capability, and inactivity.

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
| `TRUSTED` | Verified and approved |
| `SUSPICIOUS` | Flagged by fraud signals; manual review recommended |
| `REVOKED` | Permanently blocked; cannot re-enter the flow |

A device moves to `SUSPICIOUS` when fraud signals (proxy, geo-impossibility, velocity) exceed the configured threshold. From `SUSPICIOUS` it can be returned to `TRUSTED` via reverification (`POST /devices/:id/reverify`) or permanently `REVOKED`.

---

## Device identification

The device fingerprint is a SHA-256 hash of a composite of hardware and software signals:

- User-Agent string
- Screen resolution
- Hardware concurrency (CPU core count)
- Device memory (GB)
- Timezone
- Language
- Platform

The raw signals are never stored — only the SHA-256 digest. Two browsers on the same machine produce different fingerprints.

---

## Passkey binding

Devices can have a WebAuthn passkey linked to them. When `requireBiometric` is enabled in the org's device policy, a scan from an unbound device triggers a passkey registration flow before granting access.

```ts
// POST /api/v1/devices/:id/passkeys/register
// Returns a WebAuthn registration options object
const options = await fetch(`/api/v1/devices/${deviceId}/passkeys/register`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${apiKey}` },
}).then(r => r.json());

const credential = await navigator.credentials.create({ publicKey: options });
// POST /api/v1/devices/:id/passkeys/register/complete
```

---

## API reference

### List devices

```
GET /api/v1/devices
```

Returns all devices seen by your organization, sorted by last-seen descending.

```ts
const res = await fetch('https://qrauth.io/api/v1/devices', {
  headers: { Authorization: `Bearer ${apiKey}` },
});
const { devices } = await res.json();
// devices[].id, .fingerprint, .trustLevel, .userAgent, .lastSeenAt
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

Moves the device to `REVOKED`. All future scans from this fingerprint are rejected with a `403` before fraud analysis runs.

```ts
await fetch(`https://qrauth.io/api/v1/devices/${deviceId}/revoke`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${apiKey}` },
});
```

### Reverify a device

```
POST /api/v1/devices/:id/reverify
```

Initiates a reverification flow — transitions the device from `SUSPICIOUS` back to `TRUSTED` after confirming ownership (typically via passkey challenge).

---

## Device policy

Set per-organization defaults that govern device lifecycle automatically.

```
GET  /api/v1/devices/policy
PUT  /api/v1/devices/policy
```

### Policy fields

| Field | Type | Default | Description |
|---|---|---|---|
| `maxDevices` | `number` | `null` | Max trusted devices per user. `null` = unlimited |
| `requireBiometric` | `boolean` | `false` | Require passkey/biometric before `TRUSTED` |
| `geoFence` | `object \| null` | `null` | Restrict devices to a geographic area |
| `autoRevokeAfterDays` | `number \| null` | `null` | Revoke devices inactive for N days |

### Update policy

::: code-group

```ts [Node.js]
const policy = await fetch('https://qrauth.io/api/v1/devices/policy', {
  method: 'PUT',
  headers: {
    Authorization: `Bearer ${apiKey}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    maxDevices: 5,
    requireBiometric: true,
    autoRevokeAfterDays: 90,
    geoFence: {
      lat: 37.9838,
      lng: 23.7275,
      radiusKm: 50,
    },
  }),
}).then(r => r.json());
```

```python [Python]
import httpx

resp = httpx.put(
    "https://qrauth.io/api/v1/devices/policy",
    headers={"Authorization": f"Bearer {api_key}"},
    json={
        "maxDevices": 5,
        "requireBiometric": True,
        "autoRevokeAfterDays": 90,
    },
)
policy = resp.json()
```

:::

### Geo-fence policy

When `geoFence` is set, scans from devices outside the radius are automatically flagged as `SUSPICIOUS`. Combine with `requireBiometric` to enforce physical access zones.

---

## Auto-revocation

A background cleanup worker runs daily and revokes any `TRUSTED` or `SUSPICIOUS` device whose `lastSeenAt` is older than `autoRevokeAfterDays`. Revoked devices remain in the registry for audit purposes.

::: tip Inactivity window
Set `autoRevokeAfterDays: 30` for consumer apps and `autoRevokeAfterDays: 1` for high-security environments like event check-in kiosks.
:::

---

## Dashboard

The device registry is available in the dashboard at **Devices** (`/dashboard/devices`). From there you can:

- View all devices by trust state.
- Manually revoke or promote individual devices.
- Export the registry as CSV for compliance audits.
- Configure device policy (above).

---

## Trust level display in verification page

When a device scans a QR code, its current trust state is factored into the overall `trustScore` displayed on the verification page:

| Device state | Trust score impact |
|---|---|
| `TRUSTED` | No deduction |
| `NEW` | −10 |
| `SUSPICIOUS` | −35 |
| `REVOKED` | Scan blocked entirely |

See [Trust Levels](./trust-levels) for the full scoring breakdown.
