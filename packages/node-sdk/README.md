# @qrauth/node

Official Node.js SDK for [QRAuth](https://qrauth.io) — cryptographic QR code verification and anti-fraud infrastructure.

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
  destination: 'https://parking.gr/pay',
  location: { lat: 40.63, lng: 22.94 },
  expiresIn: '1y',
});

console.log(qr.verification_url);
// → https://qrauth.io/v/xK9m2pQ7

// Verify a scanned QR code
const result = await qrauth.verify('xK9m2pQ7');
console.log(result.verified);       // true
console.log(result.security.trustScore); // 94
```

## API

### `new QRAuth(options)`

| Option    | Type     | Required | Description                                     |
|-----------|----------|----------|-------------------------------------------------|
| `apiKey`  | `string` | Yes      | Your API key (starts with `qrauth_`)            |
| `baseUrl` | `string` | No       | API base URL. Defaults to `https://qrauth.io`   |

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

### `qrauth.get(token)`

Get details of a specific QR code.

### `qrauth.revoke(token)`

Revoke a QR code so it no longer verifies.

### `qrauth.bulk(items)`

Create up to 100 QR codes in a single request.

```typescript
const result = await qrauth.bulk([
  { destination: 'https://example.com/1', label: 'Meter 1' },
  { destination: 'https://example.com/2', label: 'Meter 2' },
]);
```

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

## License

MIT
