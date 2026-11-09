// Real API responses captured from a local QRAuth API (2026-10-27) and
// declared with `satisfies`: `npm test` type-checks this file, so any field
// the SDK types get wrong or miss fails the build. qr_image_url is trimmed.
import type {
  AuditPage,
  BulkDryRun,
  BulkExportLink,
  BulkJob,
  BulkCreateResponse,
  BulkOrganizeResult,
  Folder,
  ListFoldersResponse,
  OrgPolicy,
  PaginatedResponse,
  PolicyPreview,
  QRCodeDetail,
  QRCodeHistory,
  QRCodeResponse,
  Tag,
  UpdatedQRCode,
  VerificationResult,
} from '../../types.js';

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

// Search, tags and folders (2026-11-01). Shaped after the API's tag, folder
// and list services (packages/api/src/services/qr-organize.ts, qr-search.ts)
// rather than captured; list items are cut to the fields QRCodeDetail declares.
export const tagResponse = {
  "id": "cmhgz1k0q0003pn6r2c1d9x7a",
  "name": "Summer",
  "color": "teal",
  "codeCount": 2,
  "createdAt": "2026-11-01T18:02:11.412Z"
} satisfies Tag;

export const listTagsResponse = {
  "data": [tagResponse]
} satisfies { data: Tag[] };

export const folderResponse = {
  "id": "cmhgz1m4b0005pn6r8u0h3k2c",
  "name": "Lobby",
  "codeCount": 1,
  "createdAt": "2026-11-01T18:02:14.077Z"
} satisfies Folder;

export const listFoldersResponse = {
  "data": [folderResponse],
  "unfiledCount": 4
} satisfies ListFoldersResponse;

export const bulkTagResponse = {
  "updated": ["RKcPf9kv"],
  "notFound": ["zzzzzzzz"]
} satisfies BulkOrganizeResult;

export const searchListResponse = {
  "data": [
    {
      "token": "RKcPf9kv",
      "destinationUrl": "https://menu.example.com/summer?table=4",
      "label": "Summer menu",
      "status": "ACTIVE",
      "signature": "MEUCIQDwBBrmBxw/jCTEpD9pxVuuFjIvjrsDG/lQHXUzWS1YkgIgUEK9Uw1G1a2uP7Ec2D2g2Ow6lsaLWHcffOXJW86o0Ms=",
      "contentType": "url",
      "content": null,
      "latitude": null,
      "longitude": null,
      "radiusM": 50,
      "expiresAt": null,
      "createdAt": "2026-10-29T10:43:54.899Z",
      "updatedAt": "2026-11-01T18:03:02.310Z",
      "_count": { "scans": 3 },
      "algVersion": "hybrid-ecdsa-slhdsa-v1",
      "merkleBatchId": "600900b3a78d92393e42e2788796679d",
      "scanMode": "FLASH",
      "destinationHost": "menu.example.com",
      "folderId": "cmhgz1m4b0005pn6r8u0h3k2c",
      "folder": { "id": "cmhgz1m4b0005pn6r8u0h3k2c", "name": "Lobby" },
      "tags": [{ "id": "cmhgz1k0q0003pn6r2c1d9x7a", "name": "Summer", "color": "teal" }]
    }
  ],
  "total": 1,
  "page": 1,
  "pageSize": 20,
  "totalPages": 1
} satisfies PaginatedResponse<QRCodeDetail>;

// GET /api/v1/qrcodes/:token/history, written from listRevisions() in
// packages/api/src/services/qr-revisions.ts (2026-11-02): a code issued
// before edit history (BASELINE), changed by a user, by an API key, restored
// to revision 1 and revoked. Newest first.
export const historyResponse = {
  "data": [
    {
      "revision": 5,
      "kind": "REVOKED",
      "createdAt": "2026-11-02T10:05:00.000Z",
      "changes": { "status": { "before": "ACTIVE", "after": "REVOKED" } },
      "actor": { "type": "USER", "id": "cmuser0001", "name": "Jane Doe", "email": "jane@example.com" },
      "requestId": "7d2f6b1e-0c4a-4f7e-9a51-2b8f3c6d9e10",
      "restoredFrom": null
    },
    {
      "revision": 4,
      "kind": "RESTORED",
      "createdAt": "2026-11-02T10:04:00.000Z",
      "changes": { "destinationUrl": { "before": "https://example.com/menu-v2", "after": "https://example.com/menu" } },
      "actor": { "type": "API_KEY", "id": "cmkey0001", "label": "CI", "prefix": "qrauth_ab12" },
      "requestId": "0f8e1c2d-3b4a-4c5d-8e6f-7a8b9c0d1e2f",
      "restoredFrom": 1
    },
    {
      "revision": 3,
      "kind": "UPDATED",
      "createdAt": "2026-11-02T10:03:00.000Z",
      "changes": {
        "expiresAt": { "before": null, "after": "2027-01-01T00:00:00.000Z" },
        "scanMode": { "before": "FLASH", "after": "PAGE" }
      },
      "actor": { "type": "API_KEY", "id": "cmkey0002", "label": null, "prefix": null },
      "requestId": "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d",
      "restoredFrom": null
    },
    {
      "revision": 2,
      "kind": "UPDATED",
      "createdAt": "2026-11-02T10:02:00.000Z",
      "changes": {
        "destinationUrl": { "before": "https://example.com/menu", "after": "https://example.com/menu-v2" },
        "style": {
          "before": null,
          "after": { "version": 2, "presetId": "classic", "fg": "#000000", "bg": "#FFFFFF", "inverted": false, "modules": "rounded", "eyes": "rounded", "ecLevel": "auto", "quietZone": 4, "logo": null }
        }
      },
      "actor": { "type": "USER", "id": "cmuser0002", "name": null, "email": null },
      "requestId": "1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e",
      "restoredFrom": null
    },
    {
      "revision": 1,
      "kind": "BASELINE",
      "createdAt": "2026-11-02T09:00:00.000Z",
      "changes": {
        "destinationUrl": { "before": null, "after": "https://example.com/menu" },
        "content": { "before": null, "after": null },
        "style": { "before": null, "after": null },
        "expiresAt": { "before": null, "after": null },
        "scanMode": { "before": null, "after": "FLASH" },
        "status": { "before": null, "after": "ACTIVE" }
      },
      "actor": { "type": "SYSTEM", "id": "migration" },
      "requestId": null,
      "restoredFrom": null
    }
  ],
  "total": 5,
  "page": 1,
  "pageSize": 20,
  "totalPages": 1
} satisfies QRCodeHistory;

// POST /api/v1/qrcodes/:token/history/:revision/restore: the updated row,
// as PATCH returns it, cut to the fields UpdatedQRCode declares.
export const restoreResponse = {
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
  "updatedAt": "2026-11-02T10:04:00.000Z",
  "algVersion": "hybrid-ecdsa-slhdsa-v1",
  "merkleBatchId": "600900b3a78d92393e42e2788796679d",
  "scanMode": "FLASH"
} satisfies UpdatedQRCode;

// Smart link and link list (Milestone 1), captured from a local API on
// 2026-11-02: create (the smart link's fallback URL is a lookalike of a
// verified organization's domain, so domain_warnings names the link), GET
// cut to the fields QRCodeDetail declares, and the verify JSON.

export const createAppLinkResponse = {
  "token": "VWYJhMRZ",
  "verification_url": "http://localhost:3000/v/VWYJhMRZ",
  "qr_image_url": "data:image/png;base64,...",
  "signature": "MEUCIDOHj4vtM1I/SjjpwfHkqtZoYlZcnwu5LHp7kla5NHLEAiEA/CvQNZ2+00POpYkyZmh/9R/Hmw+ESYw8QxvIt9+sRlk=",
  "organization_id": "cmvz02sc000072gmidbmjfmii",
  "label": "Bistro App",
  "created_at": "2026-11-02T09:36:39.548Z",
  "expires_at": null,
  "transparency_log_index": 28,
  "alg_version": "hybrid-ecdsa-slhdsa-v1",
  "merkle_batch_id": "e18b39cea18efd92030d1b259c80abfa",
  "scan_mode": "FLASH",
  "domain_warnings": [
    {
      "url": "https://thessa1oniki.gr/app",
      "similar_to": "thessaloniki.gr",
      "verified_org": "Municipality of Thessaloniki",
      "similarity": 95,
      "reason": "homoglyph_match"
    }
  ]
} satisfies QRCodeResponse;

export const getAppLinkResponse = {
  "token": "VWYJhMRZ",
  "destinationUrl": "http://localhost:3000/v/VWYJhMRZ",
  "label": "Bistro App",
  "status": "ACTIVE",
  "signature": "MEUCIDOHj4vtM1I/SjjpwfHkqtZoYlZcnwu5LHp7kla5NHLEAiEA/CvQNZ2+00POpYkyZmh/9R/Hmw+ESYw8QxvIt9+sRlk=",
  "contentType": "app-link",
  "content": {
    "iosUrl": "https://apps.apple.com/app/id1234567",
    "androidUrl": "https://play.google.com/store/apps/details?id=com.example.bistro",
    "fallbackUrl": "https://thessa1oniki.gr/app"
  },
  "latitude": null,
  "longitude": null,
  "radiusM": 50,
  "expiresAt": null,
  "createdAt": "2026-11-02T09:36:39.548Z",
  "updatedAt": "2026-11-02T09:36:39.548Z",
  "_count": {
    "scans": 0
  },
  "algVersion": "hybrid-ecdsa-slhdsa-v1",
  "merkleBatchId": "e18b39cea18efd92030d1b259c80abfa",
  "scanMode": "FLASH",
  "verification_url": "http://localhost:3000/v/VWYJhMRZ"
} satisfies QRCodeDetail;

export const verifyAppLink = {
  "verified": false,
  "trust_state": "UNTRUSTED",
  "domain_warning": {
    "message": "This URL looks similar to \"thessaloniki.gr\" which belongs to verified organization \"Municipality of Thessaloniki\". Proceed with caution.",
    "similar_to": "thessaloniki.gr",
    "verified_org": "Municipality of Thessaloniki",
    "similarity": 95
  },
  "organization": {
    "verified": false
  },
  "destination_url": "http://localhost:3000/v/VWYJhMRZ",
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
    "merkleBatchId": "e18b39cea18efd92030d1b259c80abfa"
  },
  "warnings": [],
  "location_match": {
    "matched": false,
    "distanceM": null,
    "registeredAddress": null
  },
  "scannedAt": "2026-11-02T09:36:48.077Z"
} satisfies VerificationResult;

export const createLinkListResponse = {
  "token": "jKJw3QHd",
  "verification_url": "http://localhost:3000/v/jKJw3QHd",
  "qr_image_url": "data:image/png;base64,...",
  "signature": "MEUCIDeLzJbdiyzFkM1hhjvwRMjVb/H+mD4t96hKpQdGzdlUAiEA2uNYosPvPtlCKHqAbIccYRv+FCiHVN5ckLML4zvmyaM=",
  "organization_id": "cmvz02sc000072gmidbmjfmii",
  "label": null,
  "created_at": "2026-11-02T09:36:41.923Z",
  "expires_at": null,
  "transparency_log_index": 29,
  "alg_version": "hybrid-ecdsa-slhdsa-v1",
  "merkle_batch_id": "d08f37f3cb34812530f0b0207d9f95e0",
  "scan_mode": "FLASH"
} satisfies QRCodeResponse;

export const getLinkListResponse = {
  "token": "jKJw3QHd",
  "destinationUrl": "http://localhost:3000/v/jKJw3QHd",
  "label": null,
  "status": "ACTIVE",
  "signature": "MEUCIDeLzJbdiyzFkM1hhjvwRMjVb/H+mD4t96hKpQdGzdlUAiEA2uNYosPvPtlCKHqAbIccYRv+FCiHVN5ckLML4zvmyaM=",
  "contentType": "link-list",
  "content": {
    "links": [
      {
        "url": "https://example.com/menu",
        "label": "Menu"
      },
      {
        "url": "https://bookings.example.com/bistro",
        "label": "Book a table"
      }
    ],
    "title": "Example Bistro",
    "description": "Menu, bookings and opening hours"
  },
  "latitude": null,
  "longitude": null,
  "radiusM": 50,
  "expiresAt": null,
  "createdAt": "2026-11-02T09:36:41.923Z",
  "updatedAt": "2026-11-02T09:36:41.923Z",
  "_count": {
    "scans": 0
  },
  "algVersion": "hybrid-ecdsa-slhdsa-v1",
  "merkleBatchId": "d08f37f3cb34812530f0b0207d9f95e0",
  "scanMode": "FLASH",
  "verification_url": "http://localhost:3000/v/jKJw3QHd"
} satisfies QRCodeDetail;

export const verifyLinkList = {
  "verified": true,
  "trust_state": "VERIFIED",
  "organization": {
    "verified": true,
    "name": "Example Bistro"
  },
  "destination_url": "http://localhost:3000/v/jKJw3QHd",
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
    "merkleBatchId": "d08f37f3cb34812530f0b0207d9f95e0"
  },
  "warnings": [],
  "location_match": {
    "matched": false,
    "distanceM": null,
    "registeredAddress": null
  },
  "scannedAt": "2026-11-02T09:36:48.120Z"
} satisfies VerificationResult;

// GET /api/v1/audit, written from listAuditEntries() in
// packages/api/src/services/audit-query.ts (2026-11-03): an audit-table entry
// by a user, a QR code change by an API key and a QRAuth staff action.
// Newest first.
export const auditPageResponse = {
  "data": [
    {
      "id": "log:cmaudit0003",
      "source": "audit",
      "action": "admin.organization.kycApproved",
      "label": "Verification approved by QRAuth",
      "resourceType": "Organization",
      "resourceId": "cmvqtw2920001a9n647br9q5z",
      "resourceName": null,
      "actor": { "type": "SUPERADMIN", "id": null, "name": "QRAuth" },
      "createdAt": "2026-11-03T09:12:00.000Z",
      "requestId": "3c9e1a7b-5d2f-4e8a-b6c1-0f4d2e9a7b13",
      "ipAddress": null,
      "userAgent": null,
      "metadata": null,
      "changes": null
    },
    {
      "id": "qr:cmrev0002",
      "source": "qr_revision",
      "action": "qr.updated",
      "label": "QR code updated",
      "resourceType": "QRCode",
      "resourceId": "cmqr0001",
      "resourceName": "RKcPf9kv",
      "actor": { "type": "API_KEY", "id": "cmkey0001", "label": "CI deploy", "prefix": "qra_live_ab12" },
      "createdAt": "2026-11-03T09:05:00.000Z",
      "requestId": "8f1d2c3b-4a5e-4b6c-9d7e-1a2b3c4d5e6f",
      "ipAddress": null,
      "userAgent": null,
      "metadata": { "revision": 2 },
      "changes": { "destinationUrl": { "before": "https://example.com/menu", "after": "https://example.com/menu-autumn" } }
    },
    {
      "id": "log:cmaudit0001",
      "source": "audit",
      "action": "apiKey.create",
      "label": "API key created",
      "resourceType": "ApiKey",
      "resourceId": "cmkey0001",
      "resourceName": null,
      "actor": { "type": "USER", "id": "cmuser0001", "name": "Jane Doe", "email": "jane@example.com" },
      "createdAt": "2026-11-03T09:00:00.000Z",
      "requestId": "7d2f6b1e-0c4a-4f7e-9a51-2b8f3c6d9e10",
      "ipAddress": "203.0.113.7",
      "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15",
      "metadata": { "prefix": "qra_live_ab12", "label": "CI deploy" },
      "changes": null
    }
  ],
  "nextCursor": "eyJ0IjoiMjAyNi0xMS0wM1QwOTowMDowMC4wMDBaIiwiaWQiOiJsb2c6Y21hdWRpdDAwMDEifQ"
} satisfies AuditPage;

// GET /api/v1/policies of an organization moved from Business to Pro with
// its policy in force (local API, 2026-11-03).
export const policyResponse = {
  "allowlistMode": "ENFORCE",
  "allowlist": [{ "domain": "example.com", "includeSubdomains": true, "unicode": "example.com" }],
  "destinationEditMinRole": "MANAGER",
  "updatedAt": "2026-11-03T14:05:08.373Z",
  "editable": false,
  "outsidePolicyCount": 0,
  "apiKeysWithoutCreator": 0
} satisfies OrgPolicy;

// POST /api/v1/policies/preview with www.example.com and co.uk (local API, 2026-11-03).
export const policyPreviewResponse = {
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
    { "token": "TsJXQCZR", "label": "Old campaign", "contentType": "url", "outside": ["https://www.example.net/old-campaign"] },
    { "token": "xeUpdWXD", "label": "Visitor links", "contentType": "link-list", "outside": ["https://maps.example.org/partner"] }
  ],
  "affectedTotal": 2
} satisfies PolicyPreview;

// POST /api/v1/bulk/imports/dry-run?timezone=Europe/Athens with a
// semicolon-delimited Greek file (local API, 2026-11-05); rows 3, 4 and 7 trimmed.
export const bulkDryRunResponse = {
  "id": "RqOGOCJke-nhpY5R91-fzQ",
  "expiresAt": "2026-11-05T18:51:47.183Z",
  "delimiter": ";",
  "columns": [
    "url",
    "label",
    "folder",
    "tags",
    "expiresAt",
    "scanMode"
  ],
  "timezone": "Europe/Athens",
  "totals": {
    "rows": 6,
    "ok": 3,
    "warning": 2,
    "error": 1,
    "newFolders": [],
    "newTags": []
  },
  "rows": [
    {
      "row": 2,
      "status": "ok",
      "code": null,
      "messages": [],
      "url": "https://www.thessaloniki.gr/menu",
      "label": "Μενού δημαρχείου",
      "folder": "Δημαρχείο",
      "tags": [
        "ενημέρωση",
        "μενού"
      ],
      "expiresAt": "2027-12-31T21:59:59.000Z",
      "expiresDate": "2027-12-31",
      "scanMode": "FLASH"
    },
    {
      "row": 5,
      "status": "warning",
      "code": "lookalike",
      "messages": [
        "The destination looks like paypal.com (PayPal); it is recorded as a fraud incident when created."
      ],
      "url": "https://paypa1.com/login",
      "label": "Ύποπτος σύνδεσμος",
      "folder": null,
      "tags": [],
      "expiresAt": null,
      "expiresDate": null,
      "scanMode": null
    },
    {
      "row": 6,
      "status": "error",
      "code": "url-invalid",
      "messages": [
        "Must be an absolute http(s) URL"
      ],
      "url": "javascript:alert(1)",
      "label": "Κακός σύνδεσμος",
      "folder": null,
      "tags": [],
      "expiresAt": null,
      "expiresDate": null,
      "scanMode": null
    }
  ]
} satisfies BulkDryRun;

// GET /api/v1/bulk/jobs/:id of a finished export (local API, 2026-11-05).
export const bulkExportJobResponse = {"id":"cmw3svc9w04nv2g1etex12juh","kind":"EXPORT","status":"SUCCEEDED","total":1000,"processed":1000,"succeeded":1000,"failed":0,"skipped":0,"error":null,"createdAt":"2026-11-05T17:08:54.884Z","startedAt":"2026-11-05T17:08:54.891Z","finishedAt":"2026-11-05T17:08:58.568Z","expiresAt":"2026-11-06T17:08:58.568Z","fileBytes":11180850} satisfies BulkJob;

// POST /api/v1/bulk/exports/:id/link (local API, 2026-11-05; signature shortened).
export const bulkExportLinkResponse = {"url":"http://localhost:3000/api/v1/bulk/exports/cmw3svc9w04nv2g1etex12juh/download?expires=1793898886&sig=XpdKPeZHASTpagg1","expiresAt":"2026-11-05T17:14:46.000Z"} satisfies BulkExportLink;
