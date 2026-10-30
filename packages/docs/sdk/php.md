---
title: PHP SDK
description: Official PHP SDK for the QRAuth API — signed QR codes and verification.
---

# PHP SDK

`qrauth/qrauth-php` is the official server-side SDK for PHP. Current version: **0.2.0** on [Packagist](https://packagist.org/packages/qrauth/qrauth-php). Source: [qrauth-io/qrauth-php](https://github.com/qrauth-io/qrauth-php).

::: warning Legacy sign-in methods — frozen for new public integrations
The SDK's QR-based **AuthSession** login methods (`createAuthSession`,
`getAuthSession`, `verifyAuthResult`) are frozen for new public integrations.
New sign-in integrations should use the [OIDC provider](/guide/oidc) with any
standard PHP OpenID Connect library. The QR code and verification methods are
unaffected.
:::

## Installation

```bash
composer require qrauth/qrauth-php
```

Requires PHP 8.1+ and a [PSR-18](https://www.php-fig.org/psr/psr-18/) HTTP client (Guzzle 7 is bundled and used by default).

## Initialization

```php
use QRAuth\QRAuth;

$qrauth = new QRAuth(
    tenantId: 'your-tenant-id',
    apiKey:   'your-api-key',
);
```

`baseUrl` defaults to `https://qrauth.io` and must be `https://` (loopback hosts excepted).

## Create a QR code

```php
use QRAuth\DTO\LocationData;

$qr = $qrauth->create(
    destinationUrl: 'https://example.com/landing',
    label:          'Trade Show 2026',
    location:       new LocationData(lat: 40.7128, lng: -74.0060, radiusM: 100),
    expiresAt:      new DateTimeImmutable('+30 days'),
);

echo $qr->verificationUrl;
```

Also available: `revoke(string $token)` and `list(?int $page, ?int $pageSize, ?string $status)`.

## Verify a scan

`verify()` calls the public [verification endpoint](/api/verification) and returns a `VerifyResult`. Switch on its `trustState`, a backed enum `QRAuth\DTO\TrustState`:

```php
use QRAuth\DTO\TrustState;

$result = $qrauth->verify(
    token:     $token,
    clientLat: 40.7128,   // optional, for geo-fenced codes
    clientLng: -74.0060,
);

switch ($result->trustState) {
    case TrustState::Verified:
        // Authentic, and QRAuth has verified who issued it.
        echo $result->organization->name;
        echo $result->organization->verifiedDomain; // may be null
        break;
    case TrustState::SignedUnverifiedIssuer:
        // Authentic signed code; the issuer is not verified by QRAuth.
        // No issuer name is returned.
        echo parse_url((string) $result->destinationUrl, PHP_URL_HOST);
        break;
    case TrustState::Untrusted:
        // Revoked, expired, flagged, lookalike destination, invalid signature, ...
        echo $result->reason; // may be null
        break;
}
```

| Property | Type | Notes |
|---|---|---|
| `trustState` | `TrustState` | `Verified`, `SignedUnverifiedIssuer` or `Untrusted` (wire values `VERIFIED`, `SIGNED_UNVERIFIED_ISSUER`, `UNTRUSTED`). See [Trust state](/api/verification#trust-state) |
| `verified` | `bool` | `true` only for `TrustState::Verified`. Kept for compatibility; switch on `trustState` |
| `organization` | `Organization` | `verified` (`bool`); `name` and `verifiedDomain` are set only when `verified` is `true` |
| `destinationUrl` | `?string` | `null` on failure responses (revoked, expired, scan limit, suspended issuer, flagged destination) |
| `reason` | `?string` | Explanation on many `Untrusted` results |
| `security` | `SecurityInfo` | `signatureValid`, `trustScore`, `algVersion`, … |
| `locationMatch` | `LocationMatch` | `matched`, `distanceM`, `registeredAddress` |

## Errors

All SDK exceptions implement `QRAuth\Exception\QRAuthExceptionInterface`:

| Exception | When |
|---|---|
| `ConfigurationException` | Invalid SDK configuration |
| `TransportException` | DNS, TLS, timeout or connection failure |
| `ApiException` | Non-2xx response from QRAuth (carries `statusCode` and the body) |
| `InvalidResponseException` | 2xx response that is not the expected shape |
