import { z } from 'zod';
import { ID_TOKEN_EXPIRES_IN_SECONDS } from './oidc-id-token.js';

const envSchema = z.object({
  // Database
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),

  // Cache
  REDIS_URL: z.string().min(1, 'REDIS_URL is required'),

  // Server
  PORT: z
    .string()
    .optional()
    .default('3000')
    .transform((val) => parseInt(val, 10))
    .pipe(z.number().int().positive()),
  // Loopback by default: the API is meant to sit behind the local reverse
  // proxy. Containers and CI set HOST=0.0.0.0 explicitly.
  HOST: z.string().optional().default('127.0.0.1'),
  NODE_ENV: z
    .enum(['development', 'test', 'production'])
    .optional()
    .default('development'),

  // Dev/test-only HTTP hooks (the /_test/* routes). Second, fail-closed lock
  // IN ADDITION to the NODE_ENV !== 'production' registration gate: NODE_ENV
  // is optional (defaults to 'development' when unset), so an UNSET NODE_ENV
  // alone must never be enough to expose routes that flip email verification
  // or mint real signing-key material. Absent by default — set
  // ENABLE_TEST_HOOKS=1 only in E2E environments (e2e.yml, local e2e .env).
  ENABLE_TEST_HOOKS: z
    .enum(['0', '1'])
    .optional()
    .default('0')
    .transform((v) => v === '1'),

  // ADR-0004 freeze of the App-based sign-in surface. Set to 1 to refuse
  // registration of new Apps (POST /api/v1/apps) for every organization
  // except the platform's. Off by default: see lib/legacy-app-freeze.ts.
  LEGACY_APP_FREEZE: z
    .enum(['0', '1'])
    .optional()
    .default('0')
    .transform((v) => v === '1'),

  // Auth
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  JWT_EXPIRES_IN: z.string().default('15m'),
  // Audit-4 A4-H2: JWT key rotation support
  JWT_SECRET_VERSION: z
    .string()
    .min(1, 'JWT_SECRET_VERSION is required (e.g. "v1")')
    .default('v1'),
  JWT_SECRET_PREV: z.string().optional(),
  JWT_SECRET_PREV_VERSION: z.string().optional(),
  REFRESH_TOKEN_EXPIRES_DAYS: z
    .string()
    .optional()
    .default('30')
    .transform((val) => parseInt(val, 10))
    .pipe(z.number().int().positive()),

  // KMS / signing
  KMS_PROVIDER: z.enum(['local', 'aws', 'vault']).optional().default('local'),
  ECDSA_PRIVATE_KEY_PATH: z.string().optional().default('./keys'),

  // Signing-key lifecycle (ISO 27001 A.10.1.2; docs/ops/signing-key-rotation-loop.md).
  //
  // SIGNING_KEY_ROTATION_DAYS — age at which the hourly cleanup worker rotates
  // an ACTIVE SigningKey. 90 days is the documented control.
  //
  // SIGNING_KEY_REVOKE_GRACE_DAYS — how long a ROTATED key stays published in
  // JWKS for verification before being REVOKED (pruned from JWKS; the row is
  // never deleted — qr_codes.signingKeyId is ON DELETE RESTRICT, and QR
  // verification resolves keys by FK without a status filter, so revocation
  // never breaks QR signatures). The window must exceed the longest-lived
  // signature verified through a status-filtered path: auth-session approval
  // signatures (sessions live <= 24 h), OIDC ID tokens (1 h), proximity
  // attestations (5 min). 30 days gives a 30x margin over the 24 h bound and
  // matches the MAC-key ROTATED->RETIRED grace precedent (ALGORITHM.md §10.3).
  SIGNING_KEY_ROTATION_DAYS: z
    .string()
    .optional()
    .default('90')
    .transform(Number)
    .pipe(z.number().int().positive()),
  SIGNING_KEY_REVOKE_GRACE_DAYS: z
    .string()
    .optional()
    .default('30')
    .transform(Number)
    .pipe(z.number().int().positive()),

  // SIGNING_KEY_JWKS_WINDOW_HOURS — how long a ROTATED key stays PUBLISHED in
  // JWKS after rotation. Publication is keyed off TIME, deliberately decoupled
  // from retention/status (docs/ops/signing-key-rotation-loop.md, 2026-09-08
  // design note): JWKS has exactly one consumer class — OIDC RPs verifying ID
  // tokens — so the window only needs to exceed the ID-token lifetime plus
  // clock skew. 24 h is a >20x margin over that floor and bounds JWKS by
  // construction regardless of any retention policy. Validated at boot
  // against the derived floor (assertJwksWindowAboveFloor below).
  SIGNING_KEY_JWKS_WINDOW_HOURS: z
    .string()
    .optional()
    .default('24')
    .transform(Number)
    .pipe(z.number().positive()),

  // SIGNING_KEY_ROTATION_OVERDUE_GRACE_DAYS — how far past
  // SIGNING_KEY_ROTATION_DAYS an ACTIVE key's age may drift before /health
  // degrades with the rotation-overdue reason. Pure DB-age check, fully
  // independent of the canary/signer/Redis: it catches the
  // rotation-probe-abort retry loop (rotation failing hourly while the key
  // ages), any future trigger-never-fires regression, and the ISO 27001
  // A.10.1.2 control silently lapsing. 2 days ≈ 48 failed hourly retries
  // before the alarm — enough to ride out a transient signer outage without
  // paging, small against the 90-day control.
  SIGNING_KEY_ROTATION_OVERDUE_GRACE_DAYS: z
    .string()
    .optional()
    .default('2')
    .transform(Number)
    .pipe(z.number().positive()),

  // SLH-DSA signer backend (ALGORITHM.md §13.1)
  //
  //   local — load private keys from disk and sign in-process. Dev only.
  //   http  — POST sign requests to the standalone signer service. Use
  //           in production so private keys never live on the API host.
  SLH_DSA_SIGNER: z.enum(['local', 'http']).optional().default('local'),
  SLH_DSA_SIGNER_URL: z.string().optional(),
  SLH_DSA_SIGNER_TOKEN: z.string().optional(),

  // ECDSA signer backend (ADR-001, AUDIT-FINDING-016)
  //
  //   local — load encrypted PEM envelopes from disk, sign in-process. Dev only.
  //   http  — POST to the standalone signer service. Production backend so
  //           API host holds zero ECDSA private-key material.
  ECDSA_SIGNER: z.enum(['local', 'http']).optional().default('local'),
  ECDSA_SIGNER_URL: z.string().optional(),
  ECDSA_SIGNER_TOKEN: z.string().optional(),

  // Signing-key generation
  //
  //   local  — the API generates key pairs, encrypts them with
  //            SIGNER_MASTER_KEY and provisions the envelopes to the signer.
  //            Default; required while the signer predates /v1/keys/generate.
  //   signer — the signer generates and stores key pairs (POST
  //            /v1/keys/generate) and returns only public keys. Requires
  //            ECDSA_SIGNER=http and SLH_DSA_SIGNER=http. With this setting
  //            the API needs no SIGNER_MASTER_KEY.
  SIGNER_KEYGEN: z.enum(['local', 'signer']).optional().default('local'),

  // MAC signer backend (ADR-0001 A4-M2 Phase 1)
  //
  //   local  — derive animated-QR frame HMACs in-process from ANIMATED_QR_SECRET.
  //            Default. Existing behaviour, no RPC traffic.
  //   dual   — derive locally AND shadow-call the signer on session register /
  //            sign / verify. Local remains authoritative for the response.
  //            Phase 1 observation posture.
  //   signer — signer is the SOLE MAC verifier (Phase 3, no local fallback).
  //            REQUIRED in production; local/dual are dev/test-only.
  MAC_BACKEND: z.enum(['local', 'dual', 'signer']).optional().default('local'),
  SIGNER_MAC_URL: z.string().optional(),
  SIGNER_MAC_TOKEN: z.string().optional(),
  SIGNER_MAC_TOKEN_NEXT: z.string().optional(),
  MAC_SIGNER_DEADLINE_MS: z
    .string()
    .optional()
    .default('50')
    .transform(Number)
    .pipe(z.number().int().min(10).max(500)),
  MAC_SIGNER_MAX_RETRIES: z
    .string()
    .optional()
    .default('2')
    .transform(Number)
    .pipe(z.number().int().min(0).max(5)),
  MAC_SIGNER_CB_THRESHOLD: z
    .string()
    .optional()
    .default('5')
    .transform(Number)
    .pipe(z.number().int().min(1)),
  MAC_SIGNER_CB_WINDOW_MS: z
    .string()
    .optional()
    .default('10000')
    .transform(Number)
    .pipe(z.number().int().min(1000)),
  MAC_SIGNER_CB_HALF_OPEN_MS: z
    .string()
    .optional()
    .default('5000')
    .transform(Number)
    .pipe(z.number().int().min(1000)),
  MAC_SIGNER_OVERALL_BUDGET_MS: z
    .string()
    .optional()
    .default('200')
    .transform(Number)
    .pipe(z.number().int().min(50).max(2000)),

  // Internal stats endpoint token (ADR-0001 A4-M2 Phase 1).
  // Protects GET /internal/mac-stats. Generate with `openssl rand -hex 32`.
  INTERNAL_STATS_TOKEN: z.string().optional(),

  // Visual proof HMAC
  VISUAL_PROOF_SECRET: z.string().optional(),

  // WebAuthn
  WEBAUTHN_ORIGIN: z.string().optional(),
  WEBAUTHN_RP_NAME: z.string().optional().default('QRAuth'),

  // OIDC Provider issuer (ADR-0003).
  //
  // The OP's stable identity. RPs compare the ID token `iss` claim and the
  // discovery document's `issuer` field byte-for-byte, so this must be an
  // https:// URL with NO trailing slash. The value is permanent per
  // ADR-0003 §"Issuer URL — https://id.qrauth.io".
  OIDC_ISSUER: z
    .string()
    .optional()
    .default('https://id.qrauth.io')
    .refine(
      (v) => {
        try {
          return new URL(v).protocol === 'https:';
        } catch {
          return false;
        }
      },
      { message: 'OIDC_ISSUER must be a valid https:// URL' },
    )
    .refine((v) => !v.endsWith('/'), {
      message:
        'OIDC_ISSUER must not have a trailing slash (the iss claim is compared byte-for-byte by RPs)',
    }),

  // OIDC pairwise subject secret (ADR-0003 Slice 3b).
  //
  // HMAC key for computing pairwise `sub` values — base64-encoded, must
  // decode to >= 32 bytes (256 bits). REQUIRED in production (validated in
  // parseEnv below); in dev/test a deterministic per-process default is
  // substituted so the OP works without operator setup. Generate with
  // `openssl rand -base64 32`.
  OIDC_PAIRWISE_SECRET: z.string().optional(),

  // Set to 1 once Cloudflare's "Add visitor location headers" managed
  // transform is enabled on the zone. Cloudflare always overwrites
  // CF-IPCountry, but it only overwrites CF-IPCity when that transform is on;
  // with it off, a visitor's own CF-IPCity header reaches the origin
  // unchanged. Until this is set the city header is ignored.
  CF_VISITOR_LOCATION_HEADERS: z
    .enum(['0', '1'])
    .optional()
    .default('0')
    .transform((v) => v === '1'),

  // Demo
  DEMO_API_KEY: z.string().optional().default(''),

  // Fraud — agent-rule kill switch (F-003).
  //   true  — agent-source dynamic fraud rules are evaluated normally.
  //   false — agent-source rules are filtered out of evaluation. Used to
  //           shut down a misbehaving agent run without manually disabling
  //           each rule. Manual (operator-authored) rules are unaffected.
  AGENT_RULES_ENABLED: z
    .enum(['true', 'false'])
    .optional()
    .default('true')
    .transform((v) => v === 'true'),
});

/**
 * AUDIT-2 N-5: WEBAUTHN_ORIGIN must be set to a valid HTTPS URL in
 * production. The variable drives the animated-QR origin pin
 * (AUDIT-FINDING-015) and the WebAuthn relying-party identifier; when
 * it was optional, a misconfigured prod box would silently no-op the
 * origin check instead of failing closed. This helper is exported so
 * the `config.test.ts` unit suite can exercise the production path
 * without having to re-import the module under a mutated
 * `process.env`. Spec pointer: `SECURITY.md §6`.
 */
export function assertProductionWebAuthnOrigin(env: {
  NODE_ENV: 'development' | 'test' | 'production';
  WEBAUTHN_ORIGIN?: string;
}): void {
  if (env.NODE_ENV !== 'production') return;

  const raw = env.WEBAUTHN_ORIGIN?.trim() ?? '';
  if (!raw) {
    throw new Error(
      'WEBAUTHN_ORIGIN is required in production but is unset or empty. ' +
        'Set it to the HTTPS origin the API serves from, e.g. ' +
        'WEBAUTHN_ORIGIN=https://qrauth.io. See SECURITY.md §6.',
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(
      `WEBAUTHN_ORIGIN must be a valid absolute URL in production ` +
        `(got "${raw}"). Expected something like https://qrauth.io. ` +
        `See SECURITY.md §6.`,
    );
  }

  if (parsed.protocol !== 'https:') {
    throw new Error(
      `WEBAUTHN_ORIGIN must use the https: scheme in production ` +
        `(got "${parsed.protocol}" from "${raw}"). See SECURITY.md §6.`,
    );
  }
}

/**
 * ADR-0003 Slice 3b: validate the OIDC pairwise secret's FORMAT only, in
 * any environment, and ONLY when a value is present. There is deliberately
 * no production-required branch — a missing secret is a call-time
 * (503-class) condition handled by `computePairwiseSub`, not a boot crash.
 * Boot-time enforcement of a value nothing consumes yet would brick any
 * incidental restart (deploy, reboot, crash). Present-but-malformed still
 * fails fast everywhere so an operator typo is caught at boot. Exported so
 * the unit suite can exercise it without re-importing the module under a
 * mutated `process.env`.
 */
export function assertPairwiseSecretFormat(raw: string | undefined): void {
  if (!raw) return; // unset is allowed in every environment
  if (Buffer.from(raw, 'base64').length < 32) {
    throw new Error(
      'OIDC_PAIRWISE_SECRET, when set, must base64-decode to at least 32 bytes (256 bits).',
    );
  }
}

/**
 * Allowance for RP clock skew when deciding how long a rotated key must stay
 * published. OIDC RP libraries conventionally tolerate up to ~5 minutes of
 * skew when validating `exp`/`iat`, so a token can be accepted (and its
 * signature checked against JWKS) up to this long after its nominal expiry.
 */
export const JWKS_CLOCK_SKEW_ALLOWANCE_SECONDS = 300;

/**
 * The JWKS publication window must exceed the lifetime of the longest-lived
 * artifact an RP verifies via JWKS — the ID token — plus clock skew. A window
 * tuned below that floor breaks verification intermittently (tokens signed
 * just before a rotation stop verifying while still valid) and looks like an
 * RP bug from the outside. The floor is DERIVED from
 * ID_TOKEN_EXPIRES_IN_SECONDS so it moves automatically if the token
 * lifetime ever changes — never a hardcoded constant that can silently
 * drift. Exported (with the TTL injectable) so the unit suite can exercise
 * both the rejection and the derivation without mutating process.env.
 */
export function assertJwksWindowAboveFloor(
  windowHours: number,
  idTokenTtlSeconds: number = ID_TOKEN_EXPIRES_IN_SECONDS,
): void {
  const floorSeconds = idTokenTtlSeconds + JWKS_CLOCK_SKEW_ALLOWANCE_SECONDS;
  if (windowHours * 3600 < floorSeconds) {
    throw new Error(
      `SIGNING_KEY_JWKS_WINDOW_HOURS=${windowHours} is below the derived floor of ` +
        `${floorSeconds}s (ID-token lifetime ${idTokenTtlSeconds}s + ` +
        `${JWKS_CLOCK_SKEW_ALLOWANCE_SECONDS}s clock-skew allowance). A rotated key must ` +
        'stay published in JWKS at least as long as a token it signed can still be ' +
        'legitimately verified, or verification fails intermittently after every rotation.',
    );
  }
}

/**
 * SIGNER_KEYGEN=signer means private keys exist only on the signer, so every
 * signing backend must be remote as well. Exported for tests.
 */
export function assertKeygenBackends(env: {
  SIGNER_KEYGEN: 'local' | 'signer';
  ECDSA_SIGNER: 'local' | 'http';
  SLH_DSA_SIGNER: 'local' | 'http';
  ECDSA_SIGNER_URL?: string;
  ECDSA_SIGNER_TOKEN?: string;
  SLH_DSA_SIGNER_URL?: string;
  SLH_DSA_SIGNER_TOKEN?: string;
}): void {
  if (env.SIGNER_KEYGEN !== 'signer') return;
  if (env.ECDSA_SIGNER !== 'http' || env.SLH_DSA_SIGNER !== 'http') {
    throw new Error(
      'SIGNER_KEYGEN=signer requires ECDSA_SIGNER=http and SLH_DSA_SIGNER=http: ' +
        'keys generated on the signer can only be used through the signer.',
    );
  }
  if (!env.ECDSA_SIGNER_URL || !env.ECDSA_SIGNER_TOKEN) {
    throw new Error('SIGNER_KEYGEN=signer requires ECDSA_SIGNER_URL and ECDSA_SIGNER_TOKEN.');
  }
  // Keys are generated through the ECDSA signer settings and their SLH-DSA
  // half is used through the SLH-DSA settings: both must reach one signer.
  const norm = (u?: string) => (u ?? '').replace(/\/+$/, '');
  if (
    norm(env.SLH_DSA_SIGNER_URL) !== norm(env.ECDSA_SIGNER_URL) ||
    env.SLH_DSA_SIGNER_TOKEN !== env.ECDSA_SIGNER_TOKEN
  ) {
    throw new Error(
      'SIGNER_KEYGEN=signer requires SLH_DSA_SIGNER_URL/TOKEN to match ECDSA_SIGNER_URL/TOKEN (one signer).',
    );
  }
}

/**
 * Whether this API process needs SIGNER_MASTER_KEY at all: only when it
 * generates keys locally or signs with a local backend. Exported for tests.
 */
export function apiNeedsMasterKey(env: {
  SIGNER_KEYGEN: 'local' | 'signer';
  ECDSA_SIGNER: 'local' | 'http';
  SLH_DSA_SIGNER: 'local' | 'http';
}): boolean {
  return env.SIGNER_KEYGEN === 'local' || env.ECDSA_SIGNER === 'local' || env.SLH_DSA_SIGNER === 'local';
}

/** Boot warning: a master key on a host that neither generates nor signs. */
function warnUnusedMasterKey(env: Parameters<typeof apiNeedsMasterKey>[0] & { NODE_ENV: string }): void {
  if (env.NODE_ENV === 'production' && !apiNeedsMasterKey(env) && process.env.SIGNER_MASTER_KEY) {
    console.warn(
      '[config] SIGNER_MASTER_KEY is set on a host that does not generate or sign with ' +
        'private keys (SIGNER_KEYGEN=signer, ECDSA_SIGNER=http, SLH_DSA_SIGNER=http). ' +
        'Remove it from this host.',
    );
  }
}

function parseEnv() {
  const result = envSchema.safeParse(process.env);

  if (!result.success) {
    const formatted = result.error.issues
      .map((issue) => `  ${issue.path.join('.')}: ${issue.message}`)
      .join('\n');

    throw new Error(
      `Invalid environment configuration:\n${formatted}\n\nPlease check your .env file.`,
    );
  }

  // AUDIT-2 N-5: hard-fail at boot if production is missing a valid
  // HTTPS WEBAUTHN_ORIGIN. The animated-QR origin pin relies on this
  // variable; silently no-op'ing it in prod is a real downgrade.
  assertProductionWebAuthnOrigin(result.data);

  // Audit-3 C-2: VISUAL_PROOF_SECRET must be set in production.
  if (result.data.NODE_ENV === 'production' && !result.data.VISUAL_PROOF_SECRET) {
    throw new Error(
      'VISUAL_PROOF_SECRET is required in production (Audit-3 C-2). ' +
      'Generate with `openssl rand -hex 32` and mount via the same ' +
      'secret-management path as JWT_SECRET.',
    );
  }

  if (
    result.data.NODE_ENV === 'production' &&
    result.data.VISUAL_PROOF_SECRET &&
    result.data.VISUAL_PROOF_SECRET.length < 32
  ) {
    throw new Error(
      'VISUAL_PROOF_SECRET must be at least 32 characters in production (Audit-3 C-2).',
    );
  }

  // ADR-0001 A4-M2 Phase 3: the local MAC fallback is decommissioned, so
  // the signer is the sole MAC verifier. Production must run
  // MAC_BACKEND=signer — local/dual are dev/test-only postures (no signer
  // hard-dependency). Reject any other value at boot rather than silently
  // running an unsupported posture.
  if (result.data.NODE_ENV === 'production' && result.data.MAC_BACKEND !== 'signer') {
    throw new Error(
      `MAC_BACKEND must be 'signer' in production (ADR-0001 A4-M2 Phase 3 — ` +
      `local MAC fallback decommissioned). Got '${result.data.MAC_BACKEND}'.`,
    );
  }

  assertKeygenBackends(result.data);
  warnUnusedMasterKey(result.data);

  // The JWKS publication window must clear the ID-token-lifetime floor
  // (see assertJwksWindowAboveFloor) — fail fast at boot, not intermittently
  // after the next rotation.
  assertJwksWindowAboveFloor(result.data.SIGNING_KEY_JWKS_WINDOW_HOURS);

  // ADR-0003 Slice 3b: OIDC_PAIRWISE_SECRET is validated LAZILY at call time
  // (see computePairwiseSub), NOT required at boot — only its format is
  // checked here, and only when present. See assertPairwiseSecretFormat.
  assertPairwiseSecretFormat(result.data.OIDC_PAIRWISE_SECRET);

  // Audit-4 A4-H2: warn if previous secret is set without a version tag.
  if (result.data.JWT_SECRET_PREV && !result.data.JWT_SECRET_PREV_VERSION) {
    // eslint-disable-next-line no-console
    console.warn(
      '[config] JWT_SECRET_PREV is set but JWT_SECRET_PREV_VERSION is missing. ' +
      'Tokens signed with the previous secret will not be verifiable. ' +
      'Set JWT_SECRET_PREV_VERSION to the kid of the previous secret.',
    );
  }

  return result.data;
}

// Fail fast at import time – any misconfiguration surfaces immediately.
const env = parseEnv();

export const config = {
  db: {
    url: env.DATABASE_URL,
  },
  redis: {
    url: env.REDIS_URL,
  },
  server: {
    port: env.PORT,
    host: env.HOST,
    nodeEnv: env.NODE_ENV,
    isDev: env.NODE_ENV === 'development',
    isTest: env.NODE_ENV === 'test',
    isProd: env.NODE_ENV === 'production',
    // Both locks: never in production, AND explicitly opted in. Routes gate
    // their REGISTRATION on this, so in any non-opted-in environment the
    // /_test/* paths do not exist in the router (404), regardless of what
    // NODE_ENV resolves to.
    testHooksEnabled: env.NODE_ENV !== 'production' && env.ENABLE_TEST_HOOKS,
  },
  auth: {
    jwtSecret: env.JWT_SECRET,
    jwtExpiresIn: env.JWT_EXPIRES_IN,
    jwtSecretVersion: env.JWT_SECRET_VERSION,
    jwtSecretPrev: env.JWT_SECRET_PREV,
    jwtSecretPrevVersion: env.JWT_SECRET_PREV_VERSION,
    refreshTokenExpiresDays: env.REFRESH_TOKEN_EXPIRES_DAYS,
  },
  kms: {
    provider: env.KMS_PROVIDER,
    ecdsaPrivateKeyPath: env.ECDSA_PRIVATE_KEY_PATH,
  },
  signingKeys: {
    rotationDays: env.SIGNING_KEY_ROTATION_DAYS,
    revokeGraceDays: env.SIGNING_KEY_REVOKE_GRACE_DAYS,
    jwksWindowHours: env.SIGNING_KEY_JWKS_WINDOW_HOURS,
    rotationOverdueGraceDays: env.SIGNING_KEY_ROTATION_OVERDUE_GRACE_DAYS,
  },
  slhdsaSigner: {
    backend: env.SLH_DSA_SIGNER,
    url: env.SLH_DSA_SIGNER_URL,
    token: env.SLH_DSA_SIGNER_TOKEN,
  },
  keygen: {
    backend: env.SIGNER_KEYGEN,
    /** False when every key operation runs on the signer. */
    needsMasterKey: apiNeedsMasterKey(env),
  },
  ecdsaSigner: {
    backend: env.ECDSA_SIGNER,
    url: env.ECDSA_SIGNER_URL,
    token: env.ECDSA_SIGNER_TOKEN,
  },
  macSigner: {
    backend: env.MAC_BACKEND,
    url: env.SIGNER_MAC_URL,
    token: env.SIGNER_MAC_TOKEN,
    tokenNext: env.SIGNER_MAC_TOKEN_NEXT,
    deadlineMs: env.MAC_SIGNER_DEADLINE_MS,
    maxRetries: env.MAC_SIGNER_MAX_RETRIES,
    cbThreshold: env.MAC_SIGNER_CB_THRESHOLD,
    cbWindowMs: env.MAC_SIGNER_CB_WINDOW_MS,
    cbHalfOpenMs: env.MAC_SIGNER_CB_HALF_OPEN_MS,
    overallBudgetMs: env.MAC_SIGNER_OVERALL_BUDGET_MS,
  },
  internalStats: {
    token: env.INTERNAL_STATS_TOKEN,
  },
  visualProof: {
    secret: env.VISUAL_PROOF_SECRET,
  },
  webauthn: {
    origin: env.WEBAUTHN_ORIGIN || `http://localhost:${env.PORT}`,
    rpId: env.WEBAUTHN_ORIGIN
      ? new URL(env.WEBAUTHN_ORIGIN).hostname
      : 'localhost',
    rpName: env.WEBAUTHN_RP_NAME,
  },
  demo: {
    apiKey: env.DEMO_API_KEY,
  },
  oidc: {
    issuer: env.OIDC_ISSUER,
    // Raw HMAC key for pairwise `sub`, or `undefined` when unset. Validation
    // is deferred to the call site (computePairwiseSub throws
    // OidcPairwiseSecretMissingError) so a missing secret degrades to a
    // 503-class condition on the OIDC token path rather than a boot crash.
    // parseEnv has already proven any present value decodes to >= 32 bytes.
    pairwiseSecret: env.OIDC_PAIRWISE_SECRET
      ? Buffer.from(env.OIDC_PAIRWISE_SECRET, 'base64')
      : undefined,
  },
  legacy: {
    /** True when new App registration is refused (see LEGACY_APP_FREEZE). */
    appFreeze: env.LEGACY_APP_FREEZE,
  },
  cloudflare: {
    /** True when CF-IPCity can be believed (see CF_VISITOR_LOCATION_HEADERS). */
    visitorLocationHeaders: env.CF_VISITOR_LOCATION_HEADERS,
  },
  fraud: {
    agentRulesEnabled: env.AGENT_RULES_ENABLED,
  },
} as const;

export type Config = typeof config;
