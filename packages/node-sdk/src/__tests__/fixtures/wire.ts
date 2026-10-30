// Real API responses captured from a local QRAuth API (2026-10-27) and
// declared with `satisfies`: `npm test` type-checks this file, so any field
// the SDK types get wrong or miss fails the build. qr_image_url is trimmed.
import type { BulkCreateResponse, QRCodeDetail, QRCodeResponse, VerificationResult } from '../../types.js';

export const createResponse = {
  "token": "6Fa84gpd",
  "verification_url": "https://qrauth.io/v/6Fa84gpd",
  "qr_image_url": "data:image/png;base64,...",
  "signature": "MEUCIDEeRfs4qd8+bzfdoMIfR+F6RYmbzqFvjibfgpPUiP+4AiEAnN2JvqbaoAq6EhoNrDJoVl3dCZF7UTHnoc7qvaxXu1w=",
  "organization_id": "cmvqtw2920001a9n647br9q5z",
  "label": "Menu",
  "created_at": "2026-10-27T15:16:31.894Z",
  "expires_at": null,
  "transparency_log_index": 1,
  "alg_version": "hybrid-ecdsa-slhdsa-v1",
  "merkle_batch_id": "8b6cc63dafcaf8d63b18bf593a37ae63",
  "scan_mode": "FLASH"
} satisfies QRCodeResponse;

// GET /api/v1/qrcodes/:token from a local API (2026-10-29), cut to the
// fields QRCodeDetail declares.
export const getResponse = {
  "token": "RKcPf9kv",
  "destinationUrl": "https://example.com/menu",
  "label": "Preview sample",
  "status": "ACTIVE",
  "signature": "MEUCIQDwBBrmBxw/jCTEpD9pxVuuFjIvjrsDG/lQHXUzWS1YkgIgUEK9Uw1G1a2uP7Ec2D2g2Ow6lsaLWHcffOXJW86o0Ms=",
  "contentType": "url",
  "content": null,
  "latitude": null,
  "longitude": null,
  "radiusM": 50,
  "expiresAt": null,
  "createdAt": "2026-10-29T10:43:54.899Z",
  "updatedAt": "2026-10-29T10:43:54.899Z",
  "_count": { "scans": 0 },
  "algVersion": "hybrid-ecdsa-slhdsa-v1",
  "merkleBatchId": "600900b3a78d92393e42e2788796679d",
  "scanMode": "FLASH",
  "verification_url": "http://localhost:3000/v/RKcPf9kv"
} satisfies QRCodeDetail;

export const bulkCreateResponse = {
  "results": [
    {
      "index": 0,
      "success": true,
      "data": {
        "token": "ZT93ojMs",
        "verification_url": "https://qrauth.io/v/ZT93ojMs",
        "qr_image_url": "data:image/png;base64,...",
        "signature": "MEQCIGoSmqwK+v4Vh7pIbib04E2nMT6099I8qiG8tFcJWhCbAiAVNdregnefbiLS90zja/V1fLip59c0Gyr22iPBJiXNhw==",
        "organization_id": "cmvqtw2920001a9n647br9q5z",
        "label": "A",
        "created_at": "2026-10-27T15:16:34.449Z",
        "expires_at": null,
        "transparency_log_index": 2,
        "alg_version": "hybrid-ecdsa-slhdsa-v1",
        "merkle_batch_id": "0dd9b4401d235aaa59db8d881f0a0e78",
        "scan_mode": "FLASH"
      },
      "label": "A"
    }
  ],
  "summary": {
    "total": 1,
    "succeeded": 1,
    "failed": 0
  }
} satisfies BulkCreateResponse;

export const verifyVerified = {
  "verified": true,
  "trust_state": "VERIFIED",
  "organization": {
    "verified": true,
    "name": "Acme Wire Ltd",
    "verified_domain": "acme-wire.example"
  },
  "destination_url": "https://acme-wire.example/pay",
  "scan_mode": "FLASH",
  "security": {
    "signatureValid": true,
    "proxyDetected": false,
    "trustScore": 100,
    "transparencyLogVerified": true,
    "algVersion": "hybrid-ecdsa-slhdsa-v1",
    "algVersionStatus": "accepted",
    "pqcProtected": true,
    "merkleProofValid": true,
    "merkleBatchId": "66bf5be9628fb36a774adcc6dbad8608"
  },
  "warnings": [],
  "location_match": {
    "matched": false,
    "distanceM": null,
    "registeredAddress": null
  },
  "scannedAt": "2026-10-27T15:16:47.703Z"
} satisfies VerificationResult;

export const verifySignedUnverifiedIssuer = {
  "verified": false,
  "trust_state": "SIGNED_UNVERIFIED_ISSUER",
  "organization": {
    "verified": false
  },
  "destination_url": "https://example.com/pay",
  "scan_mode": "PAGE",
  "security": {
    "signatureValid": true,
    "proxyDetected": false,
    "trustScore": 100,
    "transparencyLogVerified": true,
    "algVersion": "hybrid-ecdsa-slhdsa-v1",
    "algVersionStatus": "accepted",
    "pqcProtected": true,
    "merkleProofValid": true,
    "merkleBatchId": "0b60fd0fc00af28e9377acc9e4194bbb"
  },
  "warnings": [],
  "location_match": {
    "matched": false,
    "distanceM": null,
    "registeredAddress": null
  },
  "scannedAt": "2026-10-27T15:16:47.739Z"
} satisfies VerificationResult;

export const verifyUntrustedLookalike = {
  "verified": false,
  "trust_state": "UNTRUSTED",
  "domain_warning": {
    "message": "This URL looks similar to \"acme-wire.example\" which belongs to verified organization \"Acme Wire Ltd\". Proceed with caution.",
    "similar_to": "acme-wire.example",
    "verified_org": "Acme Wire Ltd",
    "similarity": 95
  },
  "organization": {
    "verified": false
  },
  "destination_url": "https://acme-wlre.example/login",
  "scan_mode": "PAGE",
  "security": {
    "signatureValid": true,
    "proxyDetected": false,
    "trustScore": 50,
    "transparencyLogVerified": true,
    "algVersion": "hybrid-ecdsa-slhdsa-v1",
    "algVersionStatus": "accepted",
    "pqcProtected": true,
    "merkleProofValid": true,
    "merkleBatchId": "819b3c178d1e7348476764508f5b8181"
  },
  "warnings": [],
  "location_match": {
    "matched": false,
    "distanceM": null,
    "registeredAddress": null
  },
  "scannedAt": "2026-10-27T15:16:47.781Z"
} satisfies VerificationResult;

export const verifyRevoked = {
  "verified": false,
  "trust_state": "UNTRUSTED",
  "reason": "This QR code has been revoked by its issuer.",
  "organization": {
    "verified": false
  },
  "scan_mode": "PAGE",
  "location_match": {
    "matched": false,
    "distanceM": null,
    "registeredAddress": null
  },
  "security": {
    "signatureValid": false,
    "proxyDetected": false,
    "trustScore": 0,
    "transparencyLogVerified": false
  },
  "scannedAt": "2026-10-27T15:16:47.816Z"
} satisfies VerificationResult;

export const verifyFlagged = {
  "verified": false,
  "trust_state": "UNTRUSTED",
  "reason": "This code points to a site flagged as dangerous.",
  "organization": {
    "verified": false
  },
  "scan_mode": "PAGE",
  "location_match": {
    "matched": false,
    "distanceM": null,
    "registeredAddress": null
  },
  "security": {
    "signatureValid": false,
    "proxyDetected": false,
    "trustScore": 0,
    "transparencyLogVerified": false
  },
  "scannedAt": "2026-10-27T15:16:47.820Z"
} satisfies VerificationResult;
