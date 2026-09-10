import { Prisma, type OidcClient, type PrismaClient } from '@prisma/client';
import { randomBytes } from 'node:crypto';
import { hashString } from '../lib/crypto.js';

/**
 * Org-scoped OIDC client administration (ADR-0003 Phase 2 / ADR-0004 D4).
 *
 * Self-serve CRUD + secret rotation for CUSTOMER-tier `OidcClient` rows.
 * Strictly an admin surface: the protocol runtime (routes/oidc-flow.ts) is
 * untouched and remains the only consumer of clients at /authorize | /token.
 *
 * Invariants enforced here:
 * - Every query is org-scoped in the WHERE (id + organizationId), never
 *   fetch-then-check — the platform's IDOR-safety posture.
 * - FIRST_PARTY rows are invisible and untouchable: list filters them out,
 *   get/patch/rotate/delete treat them as not-found.
 * - `tier` is always CUSTOMER on create — never caller-settable.
 * - `clientSecretHash` never leaves this module; responses expose a derived
 *   `clientType` instead (public = null hash, the same discriminator
 *   oidc-flow.ts uses at /authorize and /token).
 */

/**
 * Scopes grantable through the self-serve routes. Deliberately HARDCODED
 * rather than derived from lib/oidc-metadata.ts: discovery advertises the
 * full Phase 2 claim surface (qrauth:device_trust / qrauth:proximity /
 * qrauth:fraud_signals) which the OP does not yet emit. Those scopes stay
 * un-grantable here until they actually emit, and will then be
 * trustLevel-gated (out of scope for this layer). qrauth:auth_method is the
 * one qrauth:* claim /userinfo already serves, so it is grantable.
 */
export const SELF_SERVE_ALLOWED_SCOPES = [
  'openid',
  'profile',
  'email',
  'offline_access',
  'qrauth:auth_method',
] as const;

/** Per-org cap on self-serve OIDC clients. */
export const MAX_OIDC_CLIENTS_PER_ORG = 20;

export type OidcClientType = 'public' | 'confidential';

/** Public projection of an OidcClient — everything except the secret hash. */
export interface OidcClientView {
  id: string;
  clientId: string;
  name: string;
  clientType: OidcClientType;
  redirectUris: string[];
  allowedScopes: string[];
  tier: string;
  sectorIdentifierUri: string | null;
  idTokenSignedResponseAlg: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateOidcClientInput {
  name: string;
  redirectUris: string[];
  allowedScopes: string[];
  clientType: OidcClientType;
  sectorIdentifierUri?: string;
  idTokenSignedResponseAlg: 'RS256' | 'ES256';
}

export interface UpdateOidcClientInput {
  name?: string;
  redirectUris?: string[];
  allowedScopes?: string[];
  sectorIdentifierUri?: string | null;
  idTokenSignedResponseAlg?: 'RS256' | 'ES256';
}

export type RotateSecretResult =
  | { outcome: 'rotated'; clientSecret: string }
  | { outcome: 'not_found' }
  | { outcome: 'public_client' };

export type CreateClientResult =
  | { outcome: 'created'; client: OidcClientView; clientSecret: string | null }
  | { outcome: 'sector_host_mismatch' }
  | { outcome: 'quota_exceeded' };

export type UpdateClientResult =
  | { outcome: 'updated'; client: OidcClientView }
  | { outcome: 'not_found' }
  | { outcome: 'sector_host_mismatch' };

/**
 * Audit FINDING-001 interim fix: a self-serve registrant may only assert a
 * sectorIdentifierUri whose host it already demonstrably uses — the host of
 * at least one of its own registered redirect URIs. Without this, a client
 * could pick another RP's sector host and collide pairwise-sub derivation
 * (lib/oidc-sub.ts deriveSectorIdentifier feeds on this value), re-enabling
 * exactly the cross-RP correlation pairwise subs exist to prevent.
 * Comparison is on URL.host (host INCLUDING port) — the same component
 * deriveSectorIdentifier reads — exact equality, no special cases. Full
 * OIDC Core §8.1 fetch-and-verify is deferred to DCR/Phase 3.
 */
export function sectorHostMatchesRedirects(
  sectorIdentifierUri: string,
  redirectUris: string[],
): boolean {
  const sectorHost = new URL(sectorIdentifierUri).host;
  return redirectUris.some((uri) => new URL(uri).host === sectorHost);
}

/** Prisma surfaces a serialization conflict (Postgres 40001) as P2034. */
function isSerializationFailure(err: unknown): boolean {
  return err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2034';
}

/** Strip the hash, derive clientType. The only path from row to response. */
function toView(client: OidcClient): OidcClientView {
  return {
    id: client.id,
    clientId: client.clientId,
    name: client.name,
    clientType: client.clientSecretHash ? 'confidential' : 'public',
    redirectUris: client.redirectUris,
    allowedScopes: client.allowedScopes,
    tier: client.tier,
    sectorIdentifierUri: client.sectorIdentifierUri,
    idTokenSignedResponseAlg: client.idTokenSignedResponseAlg,
    createdAt: client.createdAt,
    updatedAt: client.updatedAt,
  };
}

export class OidcClientAdminService {
  constructor(private readonly prisma: PrismaClient) {}

  /**
   * Generate client credentials, mirroring AppService.generateCredentials:
   * clientId is public (`qrauth_oidc_` + 16 hex), the secret (`qrauth_oidc_
   * secret_` + 64 hex, same convention as scripts/seed-phase1-test-client.ts)
   * is shown ONCE and persisted only as its SHA-256 hash — hashString is the
   * exact digest /token compares against via constantTimeEqualString.
   */
  generateCredentials(): { clientId: string; clientSecret: string; clientSecretHash: string } {
    const clientId = `qrauth_oidc_${randomBytes(8).toString('hex')}`;
    const clientSecret = `qrauth_oidc_secret_${randomBytes(32).toString('hex')}`;
    return { clientId, clientSecret, clientSecretHash: hashString(clientSecret) };
  }

  /**
   * Create a CUSTOMER-tier client. For confidential clients the plaintext
   * secret is returned ONCE; public clients get no secret (PKCE-only — the
   * existing flow code enforces S256 for clients with a null hash).
   *
   * FINDING-002 (CWE-367): the per-org cap check and the insert run inside
   * ONE Serializable transaction, so concurrent creates cannot both observe
   * count = cap-1 and overshoot. The cap lives here, not in the route — the
   * route can no longer create without it. A serialization conflict (P2034)
   * is retried once; a second conflict surfaces as the quota/conflict
   * outcome (409 at the route), never a 500.
   */
  async createClient(
    organizationId: string,
    input: CreateOidcClientInput,
  ): Promise<CreateClientResult> {
    // FINDING-001: input-only check, deliberately ahead of the transaction.
    if (
      input.sectorIdentifierUri &&
      !sectorHostMatchesRedirects(input.sectorIdentifierUri, input.redirectUris)
    ) {
      return { outcome: 'sector_host_mismatch' };
    }

    const isConfidential = input.clientType === 'confidential';
    const credentials = this.generateCredentials();

    const attemptCreate = (): Promise<OidcClient | null> =>
      this.prisma.$transaction(
        async (tx) => {
          const count = await tx.oidcClient.count({
            where: { organizationId, tier: { not: 'FIRST_PARTY' } },
          });
          if (count >= MAX_OIDC_CLIENTS_PER_ORG) return null;
          return tx.oidcClient.create({
            data: {
              organizationId,
              clientId: credentials.clientId,
              clientSecretHash: isConfidential ? credentials.clientSecretHash : null,
              name: input.name,
              redirectUris: input.redirectUris,
              allowedScopes: input.allowedScopes,
              tier: 'CUSTOMER',
              sectorIdentifierUri: input.sectorIdentifierUri ?? null,
              idTokenSignedResponseAlg: input.idTokenSignedResponseAlg,
            },
          });
        },
        { isolationLevel: 'Serializable' },
      );

    let created: OidcClient | null;
    try {
      created = await attemptCreate();
    } catch (first: unknown) {
      if (!isSerializationFailure(first)) throw first;
      try {
        created = await attemptCreate();
      } catch (second: unknown) {
        if (!isSerializationFailure(second)) throw second;
        return { outcome: 'quota_exceeded' };
      }
    }
    if (!created) return { outcome: 'quota_exceeded' };

    return {
      outcome: 'created',
      client: toView(created),
      clientSecret: isConfidential ? credentials.clientSecret : null,
    };
  }

  async listClients(organizationId: string): Promise<OidcClientView[]> {
    const clients = await this.prisma.oidcClient.findMany({
      where: { organizationId, tier: { not: 'FIRST_PARTY' } },
      orderBy: { createdAt: 'desc' },
    });
    return clients.map(toView);
  }

  async getClient(id: string, organizationId: string): Promise<OidcClientView | null> {
    const client = await this.prisma.oidcClient.findFirst({
      where: { id, organizationId, tier: { not: 'FIRST_PARTY' } },
    });
    return client ? toView(client) : null;
  }

  /**
   * Patch mutable fields. clientId / tier / clientType are immutable via the
   * API (no public↔confidential conversion — clientSecretHash is never
   * touched here). Org scoping lives in the updateMany WHERE.
   *
   * The FINDING-001 sector/redirect host invariant is checked against the
   * POST-patch effective values (incoming field when present, else the
   * existing row's) so every path that could break it is covered: setting a
   * mismatched sector, AND changing redirectUris out from under an existing
   * sector. Clearing the sector (null) is always allowed.
   */
  async updateClient(
    id: string,
    organizationId: string,
    input: UpdateOidcClientInput,
  ): Promise<UpdateClientResult> {
    if (input.sectorIdentifierUri !== undefined || input.redirectUris !== undefined) {
      const existing = await this.prisma.oidcClient.findFirst({
        where: { id, organizationId, tier: { not: 'FIRST_PARTY' } },
        select: { sectorIdentifierUri: true, redirectUris: true },
      });
      if (!existing) return { outcome: 'not_found' };

      const effectiveSectorUri =
        input.sectorIdentifierUri !== undefined
          ? input.sectorIdentifierUri
          : existing.sectorIdentifierUri;
      const effectiveRedirectUris = input.redirectUris ?? existing.redirectUris;

      if (effectiveSectorUri && !sectorHostMatchesRedirects(effectiveSectorUri, effectiveRedirectUris)) {
        return { outcome: 'sector_host_mismatch' };
      }
    }

    const updated = await this.prisma.oidcClient.updateMany({
      where: { id, organizationId, tier: { not: 'FIRST_PARTY' } },
      data: {
        ...(input.name !== undefined ? { name: input.name } : {}),
        ...(input.redirectUris !== undefined ? { redirectUris: input.redirectUris } : {}),
        ...(input.allowedScopes !== undefined ? { allowedScopes: input.allowedScopes } : {}),
        ...(input.sectorIdentifierUri !== undefined
          ? { sectorIdentifierUri: input.sectorIdentifierUri }
          : {}),
        ...(input.idTokenSignedResponseAlg !== undefined
          ? { idTokenSignedResponseAlg: input.idTokenSignedResponseAlg }
          : {}),
      },
    });
    if (updated.count === 0) return { outcome: 'not_found' };
    const client = await this.getClient(id, organizationId);
    // Row matched the org-scoped update WHERE a moment ago; a vanishing read
    // here means a concurrent delete — treat as not found.
    if (!client) return { outcome: 'not_found' };
    return { outcome: 'updated', client };
  }

  /**
   * Rotate a confidential client's secret. Single-secret model: the old
   * secret is invalid the moment the new hash is written (no overlap
   * window). Public clients have no secret to rotate.
   */
  async rotateSecret(id: string, organizationId: string): Promise<RotateSecretResult> {
    const existing = await this.prisma.oidcClient.findFirst({
      where: { id, organizationId, tier: { not: 'FIRST_PARTY' } },
      select: { clientSecretHash: true },
    });
    if (!existing) return { outcome: 'not_found' };
    if (!existing.clientSecretHash) return { outcome: 'public_client' };

    const clientSecret = `qrauth_oidc_secret_${randomBytes(32).toString('hex')}`;
    const updated = await this.prisma.oidcClient.updateMany({
      // clientSecretHash NOT NULL re-checked in the WHERE so a concurrent
      // change can never turn a public client confidential here.
      where: { id, organizationId, tier: { not: 'FIRST_PARTY' }, clientSecretHash: { not: null } },
      data: { clientSecretHash: hashString(clientSecret) },
    });
    if (updated.count === 0) return { outcome: 'not_found' };

    return { outcome: 'rotated', clientSecret };
  }

  /**
   * Hard-delete a client. Dependent OidcAuthCode / OidcConsent /
   * OidcRefreshToken / OidcAccessToken rows are removed by the DB-level
   * ON DELETE CASCADE on their oidcClientId FKs (verified in migration
   * 20260528175757_add_oidc_models + 20260531190000), so outstanding
   * refresh/access tokens are dead the moment the row goes.
   */
  async deleteClient(id: string, organizationId: string): Promise<boolean> {
    const deleted = await this.prisma.oidcClient.deleteMany({
      where: { id, organizationId, tier: { not: 'FIRST_PARTY' } },
    });
    return deleted.count > 0;
  }
}
