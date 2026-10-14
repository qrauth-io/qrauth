import { describe, it, expect } from 'vitest';
import { createHash, createSign, generateKeyPairSync, randomBytes } from 'node:crypto';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';

/**
 * A passkey registration and sign-in, end to end, against the installed
 * @simplewebauthn/server, with the calls shaped exactly as
 * services/webauthn.ts makes them. A software authenticator (ES256, "none"
 * attestation) stands in for the device. This is the check that a library
 * upgrade still verifies real ceremonies and still reads the credential
 * shape the database stores: `credential.id`, `credential.publicKey` (COSE
 * bytes) and the counter.
 */

const RP_ID = 'qrauth.test';
const ORIGIN = 'https://qrauth.test';

const b64url = (bytes: Uint8Array | Buffer): string => Buffer.from(bytes).toString('base64url');
const sha256 = (data: Uint8Array | Buffer | string): Buffer => createHash('sha256').update(data).digest();
const uint32 = (n: number): Buffer => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const uint16 = (n: number): Buffer => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };

// --- Just enough CBOR for an attestation object and a COSE key -------------
const cborBytes = (bytes: Buffer): Buffer =>
  Buffer.concat([bytes.length < 24 ? Buffer.from([0x40 + bytes.length]) : bytes.length < 256 ? Buffer.from([0x58, bytes.length]) : Buffer.concat([Buffer.from([0x59]), uint16(bytes.length)]), bytes]);
const cborText = (text: string): Buffer => Buffer.concat([Buffer.from([0x60 + text.length]), Buffer.from(text, 'utf8')]);

function softwareAuthenticator() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const credentialId = randomBytes(32);
  // COSE_Key: {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}
  const coseKey = Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21]),
    cborBytes(Buffer.from(jwk.x as string, 'base64url')),
    Buffer.from([0x22]),
    cborBytes(Buffer.from(jwk.y as string, 'base64url')),
  ]);
  const clientData = (type: string, challenge: string, origin = ORIGIN): Buffer =>
    Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }), 'utf8');

  return {
    credentialId,
    register(challenge: string) {
      const clientDataJSON = clientData('webauthn.create', challenge);
      const authData = Buffer.concat([
        sha256(RP_ID),
        Buffer.from([0x45]), // user present, user verified, attested credential data
        uint32(0),
        Buffer.alloc(16), // aaguid
        uint16(credentialId.length),
        credentialId,
        coseKey,
      ]);
      const attestationObject = Buffer.concat([
        Buffer.from([0xa3]),
        cborText('fmt'), cborText('none'),
        cborText('attStmt'), Buffer.from([0xa0]),
        cborText('authData'), cborBytes(authData),
      ]);
      return {
        id: b64url(credentialId),
        rawId: b64url(credentialId),
        type: 'public-key' as const,
        response: {
          clientDataJSON: b64url(clientDataJSON),
          attestationObject: b64url(attestationObject),
          transports: ['internal' as const],
        },
        clientExtensionResults: {},
        authenticatorAttachment: 'platform' as const,
      };
    },
    authenticate(challenge: string, counter: number, origin = ORIGIN) {
      const clientDataJSON = clientData('webauthn.get', challenge, origin);
      const authenticatorData = Buffer.concat([sha256(RP_ID), Buffer.from([0x05]), uint32(counter)]);
      const signature = createSign('SHA256')
        .update(Buffer.concat([authenticatorData, sha256(clientDataJSON)]))
        .sign(privateKey);
      return {
        id: b64url(credentialId),
        rawId: b64url(credentialId),
        type: 'public-key' as const,
        response: {
          clientDataJSON: b64url(clientDataJSON),
          authenticatorData: b64url(authenticatorData),
          signature: b64url(signature),
        },
        clientExtensionResults: {},
        authenticatorAttachment: 'platform' as const,
      };
    },
  };
}

/** Register a new credential the way WebAuthnService.verifyRegistration does. */
async function registerCredential(device: ReturnType<typeof softwareAuthenticator>) {
  const options = await generateRegistrationOptions({
    rpName: 'QRAuth',
    rpID: RP_ID,
    userName: 'person@example.com',
    userDisplayName: 'Person',
    attestationType: 'none',
    excludeCredentials: [],
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
  });
  const verification = await verifyRegistrationResponse({
    response: device.register(options.challenge),
    expectedChallenge: options.challenge,
    expectedOrigin: ORIGIN,
    expectedRPID: RP_ID,
  });
  return verification;
}

describe('@simplewebauthn/server, as services/webauthn.ts uses it', () => {
  it('verifies a registration and returns the credential in the stored shape', async () => {
    const device = softwareAuthenticator();

    const verification = await registerCredential(device);

    expect(verification.verified).toBe(true);
    const { credential, credentialDeviceType, aaguid } = verification.registrationInfo!;
    expect(credential.id).toBe(b64url(device.credentialId));
    expect(credential.publicKey).toBeInstanceOf(Uint8Array);
    expect(credential.publicKey.length).toBeGreaterThan(60);
    expect(credential.counter).toBe(0);
    expect(['singleDevice', 'multiDevice']).toContain(credentialDeviceType);
    expect(typeof aaguid).toBe('string');
  });

  it('verifies a sign-in with the stored credential and advances the counter', async () => {
    const device = softwareAuthenticator();
    const { credential } = (await registerCredential(device)).registrationInfo!;
    // As stored and read back: bytes in a Buffer column.
    const stored = { id: credential.id, publicKey: Buffer.from(credential.publicKey), counter: 0 };
    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      allowCredentials: [{ id: stored.id, transports: ['internal'] }],
      userVerification: 'preferred',
    });

    const verification = await verifyAuthenticationResponse({
      response: device.authenticate(options.challenge, 1),
      expectedChallenge: options.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: { id: stored.id, publicKey: stored.publicKey, counter: stored.counter, transports: ['internal'] },
    });

    expect(verification.verified).toBe(true);
    expect(verification.authenticationInfo.newCounter).toBe(1);
  });

  it('rejects a sign-in made for another origin, a replayed counter and another device', async () => {
    const device = softwareAuthenticator();
    const other = softwareAuthenticator();
    const { credential } = (await registerCredential(device)).registrationInfo!;
    const verify = async (response: ReturnType<typeof device.authenticate>, challenge: string, counter = 0) =>
      verifyAuthenticationResponse({
        response,
        expectedChallenge: challenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        credential: { id: credential.id, publicKey: credential.publicKey, counter, transports: ['internal'] },
      }).then((v) => v.verified, () => false);
    const { challenge } = await generateAuthenticationOptions({ rpID: RP_ID, userVerification: 'preferred' });

    expect(await verify(device.authenticate(challenge, 1, 'https://evil.example'), challenge)).toBe(false);
    expect(await verify(device.authenticate(challenge, 5), challenge, 5)).toBe(false);
    expect(await verify({ ...other.authenticate(challenge, 1), id: credential.id, rawId: credential.id }, challenge)).toBe(false);
    expect(await verify(device.authenticate(challenge, 1), challenge)).toBe(true);
  });
});
