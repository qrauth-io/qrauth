import { z } from 'zod';

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
  HOST: z.string().optional().default('0.0.0.0'),
  NODE_ENV: z
    .enum(['development', 'test', 'production'])
    .optional()
    .default('development'),

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

  // MAC signer backend (ADR-0001 A4-M2 Phase 1)
  //
  //   local  — derive animated-QR frame HMACs in-process from ANIMATED_QR_SECRET.
  //            Default. Existing behaviour, no RPC traffic.
  //   dual   — derive locally AND shadow-call the signer on session register /
  //            sign / verify. Local remains authoritative for the response.
  //            Phase 1 observation posture.
  //   signer — call the signer primarily (Phase 2 target, not flipped in Phase 1).
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

  // Demo
  DEMO_API_KEY: z.string().optional().default(''),
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
  slhdsaSigner: {
    backend: env.SLH_DSA_SIGNER,
    url: env.SLH_DSA_SIGNER_URL,
    token: env.SLH_DSA_SIGNER_TOKEN,
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
} as const;

export type Config = typeof config;
