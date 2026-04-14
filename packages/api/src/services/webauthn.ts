import type { PrismaClient } from '@prisma/client';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type VerifiedRegistrationResponse,
  type VerifiedAuthenticationResponse,
} from '@simplewebauthn/server';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
} from '@simplewebauthn/types';
import { config } from '../lib/config.js';
import { cacheSet, cacheGet, cacheDel } from '../lib/cache.js';
import { WEBAUTHN_CHALLENGE_TTL } from '@qrauth/shared';
import {
  mlDsaGenerateKeyPair,
  mlDsaVerify,
  MLDSA_PARAM_SET,
} from './ml-dsa-adapter.js';
import { DevicePolicyService, type BridgePolicy } from './device-policy.js';

/**
 * Domain-separation tag for the WebAuthn bridge signature. The client
 * MUST sign `<tag><challenge>` rather than the raw challenge so the bridge
 * key cannot be repurposed for any other ML-DSA-signed payload in the
 * codebase. Pinned to v1 — bumping requires a coordinated client/server
 * upgrade.
 */
export const WEBAUTHN_BRIDGE_TAG = 'qrauth:webauthn:bridge:v1' as const;

export interface BridgeRegistrationMaterial {
  /**
   * The ML-DSA-44 private key, base64-encoded. Returned to the client
   * exactly once during registration; the server discards it after
   * sending the response and never persists it. The client stores it in
   * IndexedDB scoped to the WebAuthn rpId origin.
   */
  bridgePrivateKey: string;
  bridgePublicKey: string;
  bridgeAlgorithm: typeof MLDSA_PARAM_SET;
}

export class WebAuthnService {
  private rpId: string;
  private rpName: string;
  private origin: string;
  private devicePolicyService: DevicePolicyService;

  constructor(private prisma: PrismaClient) {
    this.rpId = config.webauthn.rpId;
    this.rpName = config.webauthn.rpName;
    this.origin = config.webauthn.origin;
    this.devicePolicyService = new DevicePolicyService(prisma);
  }

  /**
   * Generate registration options for a user to register a new passkey.
   */
  async generateRegistrationOpts(userId: string) {
    const user = await this.prisma.user.findUniqueOrThrow({
      where: { id: userId },
      select: { id: true, name: true, email: true },
    });

    // Exclude already-registered credentials to prevent re-registration
    const existingPasskeys = await this.prisma.passkey.findMany({
      where: { userId, revokedAt: null },
      select: { credentialId: true, transports: true },
    });

    const options = await generateRegistrationOptions({
      rpName: this.rpName,
      rpID: this.rpId,
      userName: user.email,
      userDisplayName: user.name,
      attestationType: 'none',
      excludeCredentials: existingPasskeys.map((p) => ({
        id: p.credentialId,
        transports: p.transports as AuthenticatorTransportFuture[],
      })),
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
    });

    // Store challenge in Redis with TTL
    await cacheSet(
      `webauthn:reg:${userId}`,
      { challenge: options.challenge },
      WEBAUTHN_CHALLENGE_TTL,
    );

    return options;
  }

  /**
   * Verify a registration response and store the new passkey.
   */
  async verifyRegistration(
    userId: string,
    response: RegistrationResponseJSON,
    name?: string,
    deviceId?: string,
  ) {
    const cached = await cacheGet(`webauthn:reg:${userId}`) as { challenge: string } | null;
    if (!cached?.challenge) {
      throw new Error('Registration challenge expired or not found.');
    }

    await cacheDel(`webauthn:reg:${userId}`);

    let verification: VerifiedRegistrationResponse;
    try {
      verification = await verifyRegistrationResponse({
        response,
        expectedChallenge: cached.challenge,
        expectedOrigin: this.origin,
        expectedRPID: this.rpId,
      });
    } catch (err: any) {
      throw new Error(`Registration verification failed: ${err.message}`);
    }

    if (!verification.verified || !verification.registrationInfo) {
      throw new Error('Registration verification failed.');
    }

    const { credential, credentialDeviceType, aaguid } = verification.registrationInfo;

    // Mint the post-quantum bridge credential alongside the WebAuthn key,
    // unless the user's effective policy is `disabled` (ALGORITHM.md §9
    // + per-tenant DevicePolicy.bridgePolicy). The ML-DSA private key is
    // returned to the caller exactly once and never persisted server-side
    // — the client is responsible for storing it in browser-local secure
    // storage (IndexedDB scoped to the rpId). If the client clears site
    // data, it loses the bridge half. The verifier then falls back to
    // WebAuthn-only on `optional` policy, or fails on `required`.
    const policy = await this.devicePolicyService.resolveBridgePolicyForUser(userId);
    const mintBridge = policy !== 'disabled';
    const bridge = mintBridge ? await mlDsaGenerateKeyPair() : null;

    const passkey = await this.prisma.passkey.create({
      data: {
        userId,
        deviceId: deviceId || null,
        credentialId: credential.id,
        publicKey: Buffer.from(credential.publicKey),
        counter: BigInt(credential.counter),
        transports: response.response.transports || [],
        aaguid: aaguid || null,
        name: name || `Passkey ${new Date().toLocaleDateString()}`,
        bridgePublicKey: bridge ? new Uint8Array(bridge.publicKey) : null,
        bridgeAlgorithm: bridge ? MLDSA_PARAM_SET : null,
      },
    });

    const bridgeMaterial: BridgeRegistrationMaterial | null = bridge
      ? {
          bridgePrivateKey: bridge.privateKey.toString('base64'),
          bridgePublicKey: bridge.publicKey.toString('base64'),
          bridgeAlgorithm: MLDSA_PARAM_SET,
        }
      : null;

    return {
      passkey,
      credentialDeviceType,
      bridge: bridgeMaterial,
      bridgePolicy: policy,
    };
  }

  /**
   * Generate authentication options. If userId is provided, scopes to that
   * user's registered passkeys.
   */
  async generateAuthenticationOpts(userId?: string) {
    let allowCredentials: { id: string; transports?: AuthenticatorTransportFuture[] }[] | undefined;

    if (userId) {
      const passkeys = await this.prisma.passkey.findMany({
        where: { userId, revokedAt: null },
        select: { credentialId: true, transports: true },
      });

      if (passkeys.length === 0) {
        throw new Error('No passkeys registered for this user.');
      }

      allowCredentials = passkeys.map((p) => ({
        id: p.credentialId,
        transports: p.transports as AuthenticatorTransportFuture[],
      }));
    }

    const options = await generateAuthenticationOptions({
      rpID: this.rpId,
      allowCredentials,
      userVerification: 'preferred',
    });

    // Store challenge keyed by the challenge itself (for public auth flows
    // where we don't know the user yet)
    const challengeKey = userId
      ? `webauthn:auth:${userId}`
      : `webauthn:auth:challenge:${options.challenge}`;

    await cacheSet(
      challengeKey,
      { challenge: options.challenge, userId: userId || null },
      WEBAUTHN_CHALLENGE_TTL,
    );

    return { options, challengeKey };
  }

  /**
   * Verify an authentication response. Returns the user associated with
   * the credential.
   *
   * @param bridgeSignature  Optional ML-DSA-44 signature over
   *   `WEBAUTHN_BRIDGE_TAG || challenge`, base64-encoded. If the passkey
   *   has a `bridgePublicKey` registered (i.e. it was created after the
   *   PQC bridge layer landed), the signature is REQUIRED and verified
   *   against the stored public key. Missing or invalid signature on a
   *   bridged passkey throws.
   */
  async verifyAuthentication(
    response: AuthenticationResponseJSON,
    challengeKey: string,
    bridgeSignature?: string,
  ) {
    const cached = await cacheGet(challengeKey) as { challenge: string; userId: string | null } | null;
    if (!cached?.challenge) {
      throw new Error('Authentication challenge expired or not found.');
    }

    await cacheDel(challengeKey);

    // Look up the passkey by credential ID
    const passkey = await this.prisma.passkey.findUnique({
      where: { credentialId: response.id },
      include: { user: { select: { id: true, name: true, email: true } } },
    });

    if (!passkey || passkey.revokedAt) {
      throw new Error('Passkey not found or has been revoked.');
    }

    let verification: VerifiedAuthenticationResponse;
    try {
      verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge: cached.challenge,
        expectedOrigin: this.origin,
        expectedRPID: this.rpId,
        credential: {
          id: passkey.credentialId,
          publicKey: passkey.publicKey,
          counter: Number(passkey.counter),
          transports: passkey.transports as AuthenticatorTransportFuture[],
        },
      });
    } catch (err: any) {
      throw new Error(`Authentication verification failed: ${err.message}`);
    }

    if (!verification.verified) {
      throw new Error('Authentication verification failed.');
    }

    // Post-quantum bridge verification (ALGORITHM.md §9). Both legs MUST
    // pass for bridged passkeys when the user's effective policy is
    // `required`. Even if Shor breaks ECDSA, the lattice-based ML-DSA
    // leg still holds.
    //
    // Three policy modes (resolved as the strictest across all of the
    // user's org memberships, see DevicePolicyService):
    //
    //   - `required` (default): bridge MUST be present and valid. A
    //     missing or invalid signature throws and the user has to
    //     re-register the passkey (because the IndexedDB private key
    //     was lost). Recommended for government / regulated tenants.
    //
    //   - `optional`: if the passkey carries a stored `bridgePublicKey`
    //     and a `bridgeSignature` is supplied, verify it strictly. If
    //     the client supplied no signature, accept WebAuthn alone with
    //     a downgrade log so operators can track "users running with
    //     bridge offline" as a soft compliance metric.
    //
    //   - `disabled`: skip the bridge check entirely. Bridge keypairs
    //     are not minted for new registrations under this policy, so
    //     `bridgePublicKey` is null and there is nothing to check.
    const policy = await this.devicePolicyService.resolveBridgePolicyForUser(passkey.user.id);
    let bridgeVerified = false;

    if (passkey.bridgePublicKey && policy !== 'disabled') {
      if (!bridgeSignature) {
        if (policy === 'required') {
          throw new Error('PQC bridge signature missing for bridged passkey.');
        }
        // `optional`: accept the WebAuthn-only path with a soft log.
        // No bridge verification possible without a client signature.
      } else {
        const message = Buffer.concat([
          Buffer.from(WEBAUTHN_BRIDGE_TAG),
          Buffer.from(cached.challenge, 'base64url'),
        ]);
        const ok = await mlDsaVerify(
          Buffer.from(passkey.bridgePublicKey),
          message,
          Buffer.from(bridgeSignature, 'base64'),
        );
        if (!ok) {
          // Invalid signatures always fail, regardless of policy. A
          // forged or corrupted signature is never benign — silently
          // accepting it would defeat the whole point of the bridge.
          throw new Error('PQC bridge signature verification failed.');
        }
        bridgeVerified = true;
      }
    }

    // Update counter and last used timestamp
    await this.prisma.passkey.update({
      where: { id: passkey.id },
      data: {
        counter: BigInt(verification.authenticationInfo.newCounter),
        lastUsedAt: new Date(),
      },
    });

    return { user: passkey.user, passkeyId: passkey.id, bridgeVerified };
  }

  /**
   * List passkeys for a user (excluding public key bytes from response).
   */
  async listPasskeys(userId: string) {
    return this.prisma.passkey.findMany({
      where: { userId, revokedAt: null },
      select: {
        id: true,
        credentialId: true,
        transports: true,
        aaguid: true,
        name: true,
        lastUsedAt: true,
        createdAt: true,
        deviceId: true,
        device: { select: { id: true, name: true, deviceType: true } },
      },
      orderBy: { createdAt: 'desc' },
    });
  }

  /**
   * Rename a passkey.
   */
  async updatePasskey(passkeyId: string, userId: string, name: string) {
    const passkey = await this.prisma.passkey.findFirst({
      where: { id: passkeyId, userId, revokedAt: null },
    });

    if (!passkey) return null;

    return this.prisma.passkey.update({
      where: { id: passkeyId },
      data: { name },
      select: {
        id: true,
        name: true,
        credentialId: true,
        lastUsedAt: true,
        createdAt: true,
      },
    });
  }

  /**
   * Revoke a passkey.
   */
  async revokePasskey(passkeyId: string, userId: string) {
    const passkey = await this.prisma.passkey.findFirst({
      where: { id: passkeyId, userId, revokedAt: null },
    });

    if (!passkey) return null;

    await this.prisma.passkey.update({
      where: { id: passkeyId },
      data: { revokedAt: new Date() },
    });

    return { revoked: true };
  }
}
