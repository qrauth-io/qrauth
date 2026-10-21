# Ephemeral Delegated Access

Ephemeral sessions grant temporary, scoped access to a resource without requiring the recipient to create an account or hold long-lived credentials. The session has a hard TTL, optional device binding, and an optional use limit — when time runs out or uses are exhausted the session becomes permanently invalid.

**Typical use cases:** hotel room unlocks, contractor dashboard access, event check-in, restaurant ordering, single-use download links.

## How it works

1. Your backend calls `createEphemeralSession` — the API returns a `claimUrl` encoded as a QR code.
2. You display the QR to the end user (or use `<qrauth-ephemeral>` to handle rendering).
3. The user scans the QR on their device. The API records the claim and returns the session's scopes and metadata. No token is issued.
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
  deviceFingerprint: deviceId, // see Device binding below
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

A TTL is a whole number followed by a unit: `s`, `m`, `h` or `d`. The default is `30m` and the maximum is 72 hours; longer values are capped at 72 hours.

| String | Duration |
|---|---|
| `30s` | 30 seconds |
| `5m` | 5 minutes |
| `6h` | 6 hours |
| `3d` | 3 days (maximum, same as `72h`) |

::: tip Longer access
Sessions last at most 72 hours. For longer access, create a new session when the previous one ends.
:::

---

## Device binding

When `deviceBinding: true`, a claim must include `deviceFingerprint` (up to 256 characters); a claim without it returns `400`. The server stores the SHA-256 hash of the value supplied by the **first** successful claim. Later claims must supply a value whose SHA-256 hash matches (compared in constant time); otherwise they return `403 Forbidden`.

Binding is as specific as the value you send. A random identifier generated once per install and kept on the device works well:

```ts
function deviceFingerprint(): string {
  let id = localStorage.getItem('device-id');
  if (!id) {
    id = crypto.randomUUID();
    localStorage.setItem('device-id', id);
  }
  return id;
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

The session status stays `PENDING` until `useCount` reaches `maxUses`, then becomes `CLAIMED`. The `detail.useCount` field increments with each successful claim.

---

## Webhook events

Configure a webhook endpoint in the dashboard under **Settings → Webhooks**.

| Event | Fired when |
|---|---|
| `ephemeral.claimed` | A session is claimed (fires on each use for multi-use sessions) |
| `ephemeral.expired` | A session past its TTL is next read, listed or claimed |

```ts
// POST to your endpoint
{
  event: 'ephemeral.claimed',
  timestamp: '2026-04-10T14:32:00.000Z',
  data: { sessionId: 'clx...' },
}
```

Fetch the session with `getEphemeralSession(sessionId)` for its status and use count. See [Webhooks](/api/webhooks) for signature verification.

---

## Web component integration

::: warning Not available since October 2026
`<qrauth-ephemeral>` created the session from the browser with only the
public client id. Creating a session now requires an API key or the app's
client secret, so use the backend flow above and render the `claimUrl`
yourself. The example below is kept for reference.
:::

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
  ttl: '24h',  // maximum 72h; issue a new session for longer stays
  deviceBinding: true,
  metadata: { guestId, checkoutDate },
});

// Display session.claimUrl as QR on the check-in receipt
```

### Contractor dashboard

```ts
// Grant read-only access to a specific project for 3 days (the maximum)
const session = await qrauth.createEphemeralSession({
  scopes: ['read:project-447', 'read:files'],
  ttl: '72h',
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
