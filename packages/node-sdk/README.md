# @qrauth/node

Official Node.js SDK for [QRAuth](https://qrauth.io) — cryptographic QR code verification and anti-fraud infrastructure.

<a href="https://openid.net/certification/certified-openid-providers-profiles/"><img src="https://qrauth.io/assets/certifications/openid-certified.png" alt="OpenID Certified" width="180" /></a>

QRAuth is an **OpenID Certified™** OpenID Provider (Basic OP + Config OP profiles).

## Install

```bash
npm install @qrauth/node
```

## Quick Start

```typescript
import { QRAuth } from '@qrauth/node';

const qrauth = new QRAuth({
  apiKey: process.env.QRAUTH_API_KEY!,
});

// Generate a verified QR code
const qr = await qrauth.create({
  destination: 'https://municipal-parking.com/pay',
  location: { lat: 40.63, lng: 22.94 },
  expiresIn: '1y',
});

console.log(qr.verification_url);
// → https://qrauth.io/v/xK9m2pQ7

// Verify a scanned QR code
const result = await qrauth.verify('xK9m2pQ7');
console.log(result.trust_state);    // 'VERIFIED' | 'SIGNED_UNVERIFIED_ISSUER' | 'UNTRUSTED'
console.log(result.verified);       // true only when trust_state is 'VERIFIED'
if (result.organization.verified) {
  console.log(result.organization.name); // issuer name, VERIFIED only
}
console.log(result.security.trustScore); // 94
```

## API

### `new QRAuth(options)`

| Option         | Type     | Required | Description                                                         |
|----------------|----------|----------|---------------------------------------------------------------------|
| `apiKey`       | `string` | *        | API key for QR code management (starts with `qrauth_`)              |
| `clientId`     | `string` | *        | App client ID for auth sessions (starts with `qrauth_app_`)         |
| `clientSecret` | `string` | No       | App client secret. Required with `clientId` for server-side flows.  |
| `baseUrl`      | `string` | No       | API base URL. Defaults to `https://qrauth.io`                       |

*At least one of `apiKey` or `clientId` is required.

### `qrauth.create(options)`

Generate a cryptographically signed QR code.

```typescript
const qr = await qrauth.create({
  destination: 'https://example.com/pay',
  label: 'Parking Meter #42',
  location: { lat: 40.63, lng: 22.94, radiusM: 100 },
  expiresIn: '30d',
});
```

| Option        | Type     | Description                                          |
|---------------|----------|------------------------------------------------------|
| `destination` | `string` | Target URL                                           |
| `label`       | `string` | Human-readable label                                 |
| `location`    | `object` | `{ lat, lng, radiusM? }` — geo-fence binding         |
| `expiresIn`   | `string` | Duration (`30s`, `5m`, `6h`, `30d`, `1y`) or ISO date |
| `contentType` | `string` | Content type: `url`, `event`, `coupon`, `vcard`, etc. |
| `content`     | `object` | Structured content (for non-URL types)               |
| `scanMode`    | `string` | `FLASH` (default): verified https URL scans show a short trust reveal, then open the destination. `PAGE`: always the full verification page |

### `qrauth.verify(token, options?)`

Verify a QR code and get its trust score.

```typescript
const result = await qrauth.verify('xK9m2pQ7', {
  clientLat: 40.63,
  clientLng: 22.94,
});
```

### `qrauth.list(options?)`

List QR codes for your organization.

```typescript
const { data, total } = await qrauth.list({
  page: 1,
  pageSize: 20,
  status: 'ACTIVE',
});
```

Search and filter with `q` (label, destination host of URL codes, token prefix or content type), `contentType` (ignoring case), `tagIds` (codes with any of the tags) and `folderId` (`'unfiled'` for codes without a folder):

```typescript
const { data } = await qrauth.list({ q: 'menu', tagIds: [summer.id], folderId: 'unfiled' });
```

### `qrauth.get(token)`

Get details of a specific QR code.

### `qrauth.revoke(token)`

Revoke a QR code so it no longer verifies.

### `qrauth.getHistory(token, options?)`

A code's edit history, newest first: one revision per change to its destination, content, style, expiry, scan mode or status, with who made it.

```typescript
const { data } = await qrauth.getHistory('abc123', { pageSize: 50 });
for (const rev of data) {
  console.log(rev.revision, rev.kind, rev.actor.type, Object.keys(rev.changes));
}
```

### `qrauth.restoreDestination(token, revision)`

Restore the destination (or, for other content types, the content) a code had right after `revision`. The code is re-signed and the updated code is returned. Needs an OWNER, ADMIN or MANAGER key.

```typescript
const qr = await qrauth.restoreDestination('abc123', 3);
```

### `qrauth.bulk(items)`

Create up to 64 QR codes in a single request.

```typescript
const result = await qrauth.bulk([
  { destination: 'https://example.com/1', label: 'Meter 1' },
  { destination: 'https://example.com/2', label: 'Meter 2' },
]);
```

### Tags and folders

Tags are organization-wide labels, many per code, in a fixed palette (`TAG_COLORS`). Folders are flat; a code is in at most one folder, or unfiled. Every role can read them; OWNER, ADMIN, MANAGER and MEMBER keys can change them.

```typescript
const summer = await qrauth.createTag({ name: 'Summer', color: 'teal' });
const lobby = await qrauth.createFolder('Lobby');

// Up to 100 codes per call; tokens that are not yours come back in notFound.
await qrauth.bulkTag(['abc123', 'def456'], { add: [summer.id] });
await qrauth.bulkMove(['abc123'], lobby.id); // null moves codes out of any folder

const tags = await qrauth.listTags(); // with codeCount
const { data: folders, unfiledCount } = await qrauth.listFolders();
```

Also `updateTag(tagId, { name?, color? })`, `deleteTag(tagId)`, `renameFolder(folderId, name)` and `deleteFolder(folderId)` (its codes become unfiled). A duplicate name or a full organization (100 tags, 200 folders) throws `ConflictError` with `reason` `'name-taken'` or `'limit-reached'`.

### Audit log

Your organization's audit log, newest first: changes to settings, members, API keys, sign-in clients and QR codes, with who made them. Needs an OWNER or ADMIN key and the Business plan or above.

```typescript
// One page (limit 1-100, default 50); pass nextCursor for the next, older page.
const page = await qrauth.listAuditEntries({ actorType: 'USER', from: new Date('2026-10-01') });

// Every matching entry, page by page.
for await (const entry of qrauth.iterateAuditEntries({ action: 'apiKey.revoke' })) {
  console.log(entry.createdAt, entry.label, entry.actor.type);
}

// The same filters as CSV text.
// The date range is required; one export holds at most 100,000 entries.
const csv = await qrauth.exportAuditCsv({ resourceType: 'QRCode', from: '2026-10-01T00:00:00Z', to: '2026-10-31T23:59:59Z' });
```

Filters: `actor`, `actorType`, `action`, `resourceType`, `resourceId`, `from`, `to`. A key without the role, or a plan below Business, throws `AuthorizationError` with `reason` `'audit-role-required'` or `'governance-plan-required'`.

### Organization policies

Limit destinations to an allowlist of domains and choose the lowest role that may change where a code points. Needs an OWNER or ADMIN key; changes need the Business plan or above.

```typescript
// Which active codes a list would leave outside (changes nothing).
const preview = await qrauth.previewPolicy([{ domain: 'example.com' }]);

await qrauth.updatePolicy({
  allowlistMode: 'ENFORCE',
  allowlist: [{ domain: 'example.com' }],
  destinationEditMinRole: 'MANAGER',
});

const outside = await qrauth.list({ outsidePolicy: true });
```

A destination outside an enforced list is a `QRAuthError` with `statusCode` 422 (a `bulk()` item: `errorCode` `'DESTINATION_NOT_ALLOWED'`); a role below the minimum is an `AuthorizationError` with `reason` `'destination-edit-role-required'`.

## Error Handling

```typescript
import { QRAuth, AuthenticationError, RateLimitError } from '@qrauth/node';

try {
  await qrauth.create({ destination: 'https://example.com' });
} catch (err) {
  if (err instanceof AuthenticationError) {
    console.error('Bad API key');
  } else if (err instanceof RateLimitError) {
    console.error(`Rate limited. Retry after ${err.retryAfter}s`);
  }
}
```

Every error carries `err.requestId`, the API's `X-Request-Id` for the failed request, when the API sent one. Quote it when contacting support.

## QR-Based Authentication

Add "Sign in with QRAuth" to your application. Users scan a QR code with their phone to authenticate — no password required.

Auth-session methods require `clientId` and `clientSecret`.

```typescript
const qrauth = new QRAuth({
  clientId: process.env.QRAUTH_CLIENT_ID!,
  clientSecret: process.env.QRAUTH_CLIENT_SECRET!,
});
```

### `qrauth.createAuthSession(options?)`

Create a new auth session. Your frontend displays the QR code; users scan it with their phone.

```typescript
const session = await qrauth.createAuthSession({
  scopes: ['identity', 'email'],
});

// session.qrUrl     — render this as a QR code in your UI
// session.qrDataUrl — base64 PNG, ready for an <img> tag
// session.sessionId — keep this to poll status or verify the result
// session.expiresAt — session expiry (ISO 8601)
```

| Option                | Type       | Description                                            |
|-----------------------|------------|--------------------------------------------------------|
| `scopes`              | `string[]` | Requested scopes, e.g. `['identity', 'email']`         |
| `redirectUrl`         | `string`   | Redirect URL after approval (for deep-link flows)      |
| `metadata`            | `object`   | Arbitrary key/value attached to the session            |
| `codeChallenge`       | `string`   | PKCE code challenge (S256). Required for public clients |
| `codeChallengeMethod` | `'S256'`   | Only `'S256'` is supported                             |

### `qrauth.getAuthSession(sessionId, options?)`

Poll the current status of an auth session.

```typescript
const status = await qrauth.getAuthSession(session.sessionId);

// status.status — 'PENDING' | 'SCANNED' | 'APPROVED' | 'DENIED' | 'EXPIRED'
if (status.status === 'APPROVED') {
  console.log(status.user);     // { id, name, email }
  console.log(status.signature); // present once approved
}
```

For PKCE sessions, provide the `codeVerifier` to unlock user data:

```typescript
const status = await qrauth.getAuthSession(sessionId, { codeVerifier });
```

### `qrauth.verifyAuthResult(sessionId, signature)`

Verify an approved session from your backend callback. Call this after your frontend receives the `onSuccess` event from the browser SDK. This is the authoritative server-side check — do not skip it.

```typescript
const result = await qrauth.verifyAuthResult(sessionId, signature);

if (result.valid) {
  const { email, name } = result.session.user!;
  // Issue your own JWT or session
}
```

Returns `AuthSessionVerifyResult`:

| Field              | Type      | Description                              |
|--------------------|-----------|------------------------------------------|
| `valid`            | `boolean` | `true` if the session is genuine         |
| `session.id`       | `string`  | Session ID                               |
| `session.status`   | `string`  | Final status (`APPROVED`)                |
| `session.appName`  | `string`  | Your registered app name                 |
| `session.scopes`   | `string[]`| Granted scopes                           |
| `session.user`     | `object`  | `{ id, name?, email? }` — null if denied |
| `session.signature`| `string`  | Approval signature                       |

### Complete server-side flow

```typescript
// 1. Backend: create session (your frontend requests this via your API)
app.post('/auth/qr/start', async (req, res) => {
  const session = await qrauth.createAuthSession({ scopes: ['identity', 'email'] });
  res.json({ sessionId: session.sessionId, qrUrl: session.qrUrl });
});

// 2. Frontend: display session.qrUrl as a QR code, then poll or use the
//    browser SDK which calls back to your /auth/qr/callback on success.

// 3. Backend: verify the result from the browser SDK callback
app.post('/auth/qr/callback', async (req, res) => {
  const { sessionId, signature } = req.body;

  const result = await qrauth.verifyAuthResult(sessionId, signature);
  if (!result.valid) {
    return res.status(401).json({ error: 'Invalid auth session' });
  }

  const { email, name } = result.session.user!;
  // Look up or create the user, then issue your own JWT
  const token = issueJwt({ email, name });
  res.json({ token });
});
```

## Integration Patterns

### Device QR Codes

Attach QR codes to physical assets (meters, doors, products) and store the credentials in your own database.

```typescript
const qrauth = new QRAuth({ apiKey: process.env.QRAUTH_API_KEY! });

// On asset creation
const qr = await qrauth.create({
  destination: `https://yourapp.com/assets/${assetId}`,
  label: `Asset #${assetId}`,
  location: { lat: 40.63, lng: 22.94, radiusM: 20 },
  expiresIn: '1y',
});

await db.asset.update({
  where: { id: assetId },
  data: {
    qr_token: qr.token,
    qr_url: qr.verification_url,
    qr_expires_at: qr.expires_at,   // always store expires_at
  },
});
```

Always persist `expires_at`. When it approaches, revoke the old code and generate a new one:

```typescript
async function rotateQRCode(assetId: string) {
  const asset = await db.asset.findUnique({ where: { id: assetId } });

  if (asset.qr_token) {
    await qrauth.revoke(asset.qr_token).catch(() => {});
  }

  const qr = await qrauth.create({
    destination: `https://yourapp.com/assets/${assetId}`,
    label: `Asset #${assetId}`,
    expiresIn: '1y',
  });

  await db.asset.update({
    where: { id: assetId },
    data: {
      qr_token: qr.token,
      qr_url: qr.verification_url,
      qr_expires_at: qr.expires_at,
    },
  });
}
```

### QR Login

Add QR-based sign-in alongside your existing auth methods.

**Backend setup** — the browser SDK calls your backend, which proxies to QRAuth with credentials. You can use the built-in proxy handlers or write your own:

```typescript
// Option A: use authSessionHandlers() for minimal boilerplate
const proxy = qrauth.authSessionHandlers();

app.post('/api/v1/auth-sessions', async (req, reply) => {
  const { status, body } = await proxy.createSession(req.body);
  reply.status(status).send(body);
});

app.get('/api/v1/auth-sessions/:id', async (req, reply) => {
  const { status, body } = await proxy.getSession(req.params.id, req.query);
  reply.status(status).send(body);
});
```

Or handle it manually for more control:

```typescript
const qrauth = new QRAuth({
  clientId: process.env.QRAUTH_CLIENT_ID!,
  clientSecret: process.env.QRAUTH_CLIENT_SECRET!,
});

// Proxy: create session
app.post('/auth/qr/start', async (req, res) => {
  const session = await qrauth.createAuthSession({ scopes: ['identity', 'email'] });
  // Return only what the frontend needs — never expose clientSecret
  res.json({ sessionId: session.sessionId, qrUrl: session.qrUrl, expiresAt: session.expiresAt });
});

// Callback: verify the approved session
app.post('/auth/qr/callback', async (req, res) => {
  const { sessionId, signature } = req.body;
  const result = await qrauth.verifyAuthResult(sessionId, signature);

  if (!result.valid) return res.status(401).json({ error: 'Verification failed' });

  const { email, name } = result.session.user!;
  const user = await db.user.upsert({
    where: { email },
    create: { email, name },
    update: {},
  });

  res.json({ token: issueJwt(user) });
});
```

**Frontend setup** — load the browser SDK from the CDN and point it at your backend proxy:

```html
<div id="qrauth-login"></div>
<script src="https://qrauth.io/sdk/qrauth-auth.js"></script>
<script>
  const auth = new QRAuth({
    clientId: 'qrauth_app_xxxx',
    element: '#qrauth-login',
    baseUrl: '',  // empty = same origin (your backend proxy)
    scopes: ['identity', 'email'],
    onSuccess: async (result) => {
      // result.sessionId and result.signature are set on approval
      const res = await fetch('/auth/qr/callback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionId: result.sessionId,
          signature: result.signature,
        }),
      });
      const { token } = await res.json();
      localStorage.setItem('token', token);
      window.location.href = '/dashboard';
    },
    onError: (err) => console.error('QR login failed', err),
  });
</script>
```

The SDK renders a "Sign in with QRAuth" button, opens a modal with the QR code, and polls for status automatically. TypeScript definitions are available at `qrauth-auth.d.ts`.

## License

MIT
