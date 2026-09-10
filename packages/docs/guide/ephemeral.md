# Ephemeral Delegated Access

Ephemeral sessions grant temporary, scoped access to a resource without requiring the recipient to create an account or hold long-lived credentials. The session has a hard TTL, optional device binding, and an optional use limit — when time runs out or uses are exhausted the session becomes permanently invalid.

**Typical use cases:** hotel room unlocks, contractor dashboard access, event check-in, restaurant ordering, single-use download links.

## How it works

1. Your backend calls `createEphemeralSession` — the API returns a `claimUrl` encoded as a QR code.
2. You display the QR to the end user (or use `<qrauth-ephemeral>` to handle rendering).
3. The user scans the QR on their device. The API records the claim and issues a short-lived access token.
4. Your backend receives a `ephemeral.claimed` webhook (or polls the status endpoint) and grants the appropriate access.

---

## SDK

### Create a session

::: code-group

```ts [Node.js]
import { QRAuth } from '@qrauth/node';

const qrauth = new QRAuth({ apiKey: process.env.QRAUTH_API_KEY! });

const session = await qrauth.createEphemeralSession({
  scopes: ['read:menu', 'write:order'],
  ttl: '30m',       // 30 minutes
  maxUses: 1,       // single-claim
  deviceBinding: true,
  metadata: {
    tableId: 'T12',
    restaurantId: 'loc-athens-01',
  },
});

console.log(session.claimUrl);   // Display as QR
console.log(session.sessionId);  // Store for status polling
console.log(session.expiresAt);  // ISO 8601
```

```python [Python]
from qrauth import QRAuth

qrauth = QRAuth(api_key=os.environ["QRAUTH_API_KEY"])

session = qrauth.create_ephemeral_session(
    scopes=["read:menu", "write:order"],
    ttl="30m",
    max_uses=1,
    device_binding=True,
    metadata={
        "table_id": "T12",
        "restaurant_id": "loc-athens-01",
    },
)

print(session["claimUrl"])   # Display as QR
print(session["sessionId"])  # Store for status polling
```

:::

**Response shape (`EphemeralSessionResponse`):**

```ts
{
  sessionId: string;
  token:     string;
  claimUrl:  string;    // URL to encode as QR
  expiresAt: string;    // ISO 8601
  scopes:    string[];
  ttlSeconds: number;
  maxUses:   number;
}
```

### Get session status

::: code-group

```ts [Node.js]
const detail = await qrauth.getEphemeralSession(session.sessionId);

// detail.status: 'PENDING' | 'CLAIMED' | 'EXPIRED' | 'REVOKED'
// detail.useCount: number
// detail.claimedAt: string | null
```

```python [Python]
detail = qrauth.get_ephemeral_session(session["sessionId"])
# detail["status"], detail["useCount"], detail["claimedAt"]
```

:::

### Claim a session (consumer side)

::: code-group

```ts [Node.js]
// Called when the end-user scans the QR — typically your mobile app or web handler
const result = await qrauth.claimEphemeralSession(token, {
  deviceFingerprint: sha256(navigator.userAgent + screen.width),
});

// result.scopes   — what was granted
// result.metadata — developer-defined context set at creation time
```

```python [Python]
result = qrauth.claim_ephemeral_session(token, device_fingerprint=fp)
# result["scopes"], result["metadata"]
```

:::

### Revoke a session

::: code-group

```ts [Node.js]
await qrauth.revokeEphemeralSession(session.sessionId);
```

```python [Python]
qrauth.revoke_ephemeral_session(session["sessionId"])
```

:::

### List sessions

::: code-group

```ts [Node.js]
const { data, total } = await qrauth.listEphemeralSessions({
  status: 'PENDING',
  page: 1,
  pageSize: 20,
});
```

```python [Python]
result = qrauth.list_ephemeral_sessions(status="PENDING", page=1, page_size=20)
# result["data"], result["total"]
```

:::

---

## TTL strings

| String | Duration |
|---|---|
| `30s` | 30 seconds |
| `5m` | 5 minutes |
| `6h` | 6 hours |
| `30d` | 30 days |
| `1y` | 1 year |

::: tip Long-lived sessions
For contractor access spanning weeks or months, prefer `autoRevokeAfterDays` in [Device Policy](./device-trust) over extremely long TTLs.
:::

---

## Device binding

When `deviceBinding: true`, the session is locked to the SHA-256 fingerprint of the **first** device that claims it. Any subsequent claim attempt from a different device returns `403 Forbidden`.

Compute the fingerprint client-side and pass it during `claimEphemeralSession`:

```ts
async function deviceFingerprint(): Promise<string> {
  const raw = [
    navigator.userAgent,
    navigator.language,
    screen.width,
    screen.height,
    Intl.DateTimeFormat().resolvedOptions().timeZone,
  ].join('|');

  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
```

---

## Multi-use sessions

Set `maxUses > 1` for shared resources (a table's ordering QR, an event check-in post).

```ts
const session = await qrauth.createEphemeralSession({
  scopes: ['checkin:event-2026'],
  ttl: '8h',
  maxUses: 200,  // up to 200 attendees can scan
});
```

The session status stays `CLAIMED` (not terminal) until `useCount >= maxUses`. The `detail.useCount` field increments with each scan.

---

## Webhook events

Configure a webhook endpoint in the dashboard under **Settings → Webhooks**.

| Event | Fired when |
|---|---|
| `ephemeral.claimed` | A session is claimed (fires on each use for multi-use sessions) |
| `ephemeral.expired` | TTL elapsed with status still `PENDING` |

```ts
// POST to your endpoint
{
  event: 'ephemeral.claimed',
  sessionId: 'eph_abc123',
  token: 'AbCdEfGh',
  scopes: ['read:menu', 'write:order'],
  useCount: 1,
  maxUses: 1,
  metadata: { tableId: 'T12' },
  claimedAt: '2026-04-10T14:32:00Z',
}
```

---

## Web component integration

Use `<qrauth-ephemeral>` to handle QR rendering and status polling entirely in the browser — no backend polling code needed.

```html
<qrauth-ephemeral
  tenant="qrauth_app_xxx"
  scopes="read:menu write:order"
  ttl="30m"
  device-binding
></qrauth-ephemeral>

<script>
  document.querySelector('qrauth-ephemeral').addEventListener('qrauth:claimed', (e) => {
    // e.detail.scopes, e.detail.metadata, e.detail.useCount
    showOrderUI(e.detail.scopes);
  });
</script>
```

See [Web Components](./web-components) for the full attribute and event reference.

---

## Use-case patterns

### Hotel room controls

```ts
// On check-in, create a session scoped to the room
const session = await qrauth.createEphemeralSession({
  scopes: [`open:room-${roomNumber}`, 'wifi:access'],
  ttl: `${nightsBooked * 24}h`,
  deviceBinding: true,
  metadata: { guestId, checkoutDate },
});

// Display session.claimUrl as QR on the check-in receipt
```

### Contractor dashboard

```ts
// Grant read-only access to a specific project for 5 business days
const session = await qrauth.createEphemeralSession({
  scopes: ['read:project-447', 'read:files'],
  ttl: '120h',
  maxUses: 3,  // contractor can claim on laptop + phone + tablet
  metadata: { contractorId, projectId: '447' },
});
```

### Event check-in staff QR

```ts
// One QR for 50 staff members to tap in — no account required
const session = await qrauth.createEphemeralSession({
  scopes: ['staff:checkin'],
  ttl: '12h',
  maxUses: 50,
  metadata: { eventId: 'conf-2026', role: 'volunteer' },
});
```
