import type { PrismaClient } from '@prisma/client';

const TTL_MS = 60_000;

let cache: { origins: Set<string>; expiresAt: number } | null = null;
let inflight: Promise<Set<string>> | null = null;

function deriveOrigins(redirectUrls: string[]): string[] {
  const out: string[] = [];
  for (const url of redirectUrls) {
    try {
      out.push(new URL(url).origin);
    } catch {
      // Skip malformed URLs; createAppSchema validates on write, but be defensive.
    }
  }
  return out;
}

async function loadOrigins(prisma: PrismaClient): Promise<Set<string>> {
  const apps = await prisma.app.findMany({
    where: { status: 'ACTIVE' },
    select: { redirectUrls: true },
  });
  const origins = new Set<string>();
  for (const app of apps) {
    for (const origin of deriveOrigins(app.redirectUrls)) {
      origins.add(origin);
    }
  }
  return origins;
}

/**
 * Returns the set of CORS-allowed origins derived from registered apps'
 * redirectUrls. Cached for {@link TTL_MS} so new app registrations take
 * effect within a minute without a per-request DB hit.
 */
export async function getAllowedAppOrigins(prisma: PrismaClient): Promise<Set<string>> {
  const now = Date.now();
  if (cache && cache.expiresAt > now) {
    return cache.origins;
  }
  if (inflight) {
    return inflight;
  }
  inflight = loadOrigins(prisma)
    .then((origins) => {
      cache = { origins, expiresAt: Date.now() + TTL_MS };
      return origins;
    })
    .finally(() => {
      inflight = null;
    });
  return inflight;
}

export function invalidateAllowedAppOrigins(): void {
  cache = null;
}
