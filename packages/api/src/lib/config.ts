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
  JWT_EXPIRES_IN: z.string().default('7d'),

  // KMS / signing
  KMS_PROVIDER: z.enum(['local', 'aws', 'vault']).optional().default('local'),
  ECDSA_PRIVATE_KEY_PATH: z.string().optional().default('./keys'),

  // Visual proof HMAC
  VISUAL_PROOF_SECRET: z.string().optional(),
});

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
  },
  kms: {
    provider: env.KMS_PROVIDER,
    ecdsaPrivateKeyPath: env.ECDSA_PRIVATE_KEY_PATH,
  },
  visualProof: {
    secret: env.VISUAL_PROOF_SECRET,
  },
} as const;

export type Config = typeof config;
