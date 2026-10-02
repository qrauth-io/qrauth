/**
 * Operator A/B check for OP signing changes (rs256-repair-runbook.md step 5 /
 * 6b): drives the manual half of an authorization-code flow and verifies the
 * resulting ID token against the LIVE published JWKS, the way a stock RP
 * would. Replaces the by-hand browser+jwt.io ritual.
 *
 * Flow:
 *   1. Generates PKCE (S256), state and nonce, prints the /authorize URL.
 *   2. YOU open it in a browser and complete the login (warm OP session or a
 *      Living Code scan — the interactive part that cannot be automated),
 *      then paste the full redirected URL back here. Nothing needs to be
 *      listening on the redirect URI: the browser will fail to load the
 *      page, but the address bar holds the ?code=… URL — copy that.
 *   3. The script exchanges the code and reports: id_token alg + kid, kid
 *      resolution in the live JWKS (with alg match), cryptographic
 *      verification of the signature against that published JWK (plus iss,
 *      aud, exp and nonce checks via jose), and the sub/aud/iss claims.
 *
 * Read-only posture: this script performs NO database or key-state writes.
 * (The token exchange itself has the server-side effects any real login has
 * — the auth code is consumed and an access token is minted — identical to
 * the manual A/B it replaces.)
 *
 * Redaction rules (deliberate, for log aggregation): the client secret, the
 * full id_token, and the access token are NEVER printed — kid, alg, claims
 * and pass/fail only. The secret comes from the OIDC_AB_CLIENT_SECRET env
 * var, not argv, so it stays out of shell history.
 *
 * Usage:
 *   OIDC_AB_CLIENT_SECRET=… npm run oidc:ab-check -w packages/api -- \
 *     --client-id phase1-test-client --redirect-uri http://localhost:9000/callback
 *   Optional: --issuer https://id.qrauth.io (default)
 *
 * Built for reuse: verifyIdTokenAgainstJwks() is the verification core the
 * signing-canary (mechanism 2) needs — token-shaped input in, structured
 * pass/fail out, no printing, no token retention.
 */

import { createHash, randomBytes } from 'node:crypto';
import { createInterface } from 'node:readline/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createLocalJWKSet, jwtVerify, decodeProtectedHeader } from 'jose';

interface AbCheckResult {
  alg: string | undefined;
  kid: string | undefined;
  kidInJwks: boolean;
  jwksAlgMatches: boolean;
  signatureValid: boolean;
  nonceMatches: boolean | null;
  claims: { sub?: string; aud?: unknown; iss?: string };
  failure: string | null;
}

/**
 * Verify a compact-JWS ID token against the issuer's LIVE published JWKS.
 * Never logs and never returns the raw token. Exported for the canary.
 */
export async function verifyIdTokenAgainstJwks(opts: {
  idToken: string;
  issuer: string;
  clientId: string;
  expectedNonce?: string;
}): Promise<AbCheckResult> {
  const result: AbCheckResult = {
    alg: undefined,
    kid: undefined,
    kidInJwks: false,
    jwksAlgMatches: false,
    signatureValid: false,
    nonceMatches: opts.expectedNonce === undefined ? null : false,
    claims: {},
    failure: null,
  };

  let header: { alg?: string; kid?: string };
  try {
    header = decodeProtectedHeader(opts.idToken);
  } catch {
    result.failure = 'id_token is not a parseable compact JWS';
    return result;
  }
  result.alg = header.alg;
  result.kid = header.kid;

  const jwksUrl = `${opts.issuer}/.well-known/jwks.json`;
  let jwks: { keys: Array<{ kid?: string; alg?: string }> };
  try {
    const res = await fetch(jwksUrl);
    if (!res.ok) {
      result.failure = `JWKS fetch failed: HTTP ${res.status} from ${jwksUrl}`;
      return result;
    }
    jwks = (await res.json()) as typeof jwks;
  } catch (err) {
    result.failure = `JWKS fetch failed: ${(err as Error).message}`;
    return result;
  }

  const published = jwks.keys.find((k) => k.kid === header.kid);
  result.kidInJwks = !!published;
  result.jwksAlgMatches = !!published && published.alg === header.alg;
  if (!published) {
    result.failure = `kid ${header.kid} is NOT in the published JWKS (${jwks.keys.length} keys)`;
    return result;
  }
  if (!result.jwksAlgMatches) {
    result.failure = `kid ${header.kid} is published with alg ${published.alg}, but the token header says ${header.alg}`;
    return result;
  }

  try {
    const keySet = createLocalJWKSet(jwks as Parameters<typeof createLocalJWKSet>[0]);
    const { payload } = await jwtVerify(opts.idToken, keySet, {
      issuer: opts.issuer,
      audience: opts.clientId,
    });
    result.signatureValid = true;
    result.claims = { sub: payload.sub, aud: payload.aud, iss: payload.iss };
    if (opts.expectedNonce !== undefined) {
      result.nonceMatches = payload.nonce === opts.expectedNonce;
      if (!result.nonceMatches) result.failure = 'nonce in the id_token does not match the one sent';
    }
  } catch (err) {
    result.failure = `signature/claims verification failed against the published JWK: ${(err as Error).message}`;
  }
  return result;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const fail = (step: string, msg: string): never => {
  console.error(`\n[ab-check] FAILED at ${step}: ${msg}`);
  process.exit(1);
};

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const argOf = (flag: string): string | null => {
    const i = args.indexOf(flag);
    if (i === -1) return null;
    const v = args[i + 1];
    if (!v || v.startsWith('--')) fail('arguments', `${flag} requires a value`);
    return v ?? null;
  };

  const clientId = argOf('--client-id') ?? fail('arguments', '--client-id is required');
  const redirectUri = argOf('--redirect-uri') ?? fail('arguments', '--redirect-uri is required');
  const issuer = argOf('--issuer') ?? 'https://id.qrauth.io';
  const clientSecret = process.env.OIDC_AB_CLIENT_SECRET;
  if (!clientSecret) {
    fail(
      'arguments',
      'OIDC_AB_CLIENT_SECRET is not set. Export it from your password manager — it is taken ' +
        'from the environment, never argv, so it stays out of shell history.',
    );
  }

  // --- Step 1: PKCE + state + nonce, print the authorize URL.
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier, 'ascii').digest('base64url');
  const state = randomBytes(8).toString('hex');
  const nonce = randomBytes(8).toString('hex');

  const authorizeUrl =
    `${issuer}/authorize?response_type=code` +
    `&client_id=${encodeURIComponent(clientId)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&scope=openid&state=${state}&nonce=${nonce}` +
    `&code_challenge=${codeChallenge}&code_challenge_method=S256`;

  console.log('\n[ab-check] Open this URL in your browser and complete the login:');
  console.log(`\n  ${authorizeUrl}\n`);
  console.log(
    '[ab-check] Nothing needs to listen on the redirect URI — after approval the browser will\n' +
      "           fail to load the page; copy the FULL URL from the address bar (it carries ?code=…).\n",
  );

  // --- Step 2: wait for the pasted redirect URL.
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const pasted = (await rl.question('[ab-check] Paste the full redirected URL: ')).trim();
  rl.close();
  if (!pasted) fail('redirect', 'nothing pasted');

  let redirected: URL;
  try {
    redirected = new URL(pasted);
  } catch {
    return fail('redirect', `not a parseable URL: "${pasted.slice(0, 80)}"`);
  }
  const oauthError = redirected.searchParams.get('error');
  if (oauthError) {
    fail(
      'authorize',
      `the OP returned error=${oauthError}` +
        (redirected.searchParams.get('error_description')
          ? ` (${redirected.searchParams.get('error_description')})`
          : ''),
    );
  }
  const echoedState = redirected.searchParams.get('state');
  if (echoedState !== state) {
    fail('redirect', `state mismatch: sent ${state}, got ${echoedState ?? '(none)'} — wrong tab or a replayed URL?`);
  }
  const code = redirected.searchParams.get('code');
  if (!code) fail('redirect', 'no code parameter in the pasted URL');

  // --- Step 3: token exchange (client_secret_post).
  let tokenRes: Response;
  try {
    tokenRes = await fetch(`${issuer}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code!,
        redirect_uri: redirectUri!,
        code_verifier: codeVerifier,
        client_id: clientId!,
        client_secret: clientSecret!,
      }),
    });
  } catch (err) {
    return fail('token', `request to ${issuer}/token failed: ${(err as Error).message}`);
  }
  if (!tokenRes.ok) {
    let detail = `HTTP ${tokenRes.status}`;
    try {
      const body = (await tokenRes.json()) as { error?: string; error_description?: string };
      if (body.error) detail += ` error=${body.error}`;
      if (body.error_description) detail += ` (${body.error_description})`;
    } catch {
      /* non-JSON error body — status alone */
    }
    fail('token', detail);
  }
  const tok = (await tokenRes.json()) as { id_token?: string };
  if (!tok.id_token) fail('token', 'response contained no id_token');

  // --- Step 4: verify against the live JWKS.
  const r = await verifyIdTokenAgainstJwks({
    idToken: tok.id_token!,
    issuer,
    clientId: clientId!,
    expectedNonce: nonce,
  });

  const yn = (b: boolean | null): string => (b === null ? 'n/a' : b ? 'PASS' : 'FAIL');
  console.log('\n[ab-check] Result:');
  console.log(`  id_token alg:        ${r.alg ?? '(none)'}`);
  console.log(`  id_token kid:        ${r.kid ?? '(none)'}`);
  console.log(`  kid in live JWKS:    ${yn(r.kidInJwks)}`);
  console.log(`  JWKS alg matches:    ${yn(r.jwksAlgMatches)}`);
  console.log(`  signature + claims:  ${yn(r.signatureValid)} (iss, aud, exp validated by jose)`);
  console.log(`  nonce matches:       ${yn(r.nonceMatches)}`);
  console.log(`  sub: ${r.claims.sub ?? '-'}`);
  console.log(`  aud: ${JSON.stringify(r.claims.aud) ?? '-'}`);
  console.log(`  iss: ${r.claims.iss ?? '-'}`);

  if (r.failure) fail('verification', r.failure);
  console.log('\n[ab-check] A/B PASS — the id_token verifies end to end against the published JWKS.');
}

const invokedDirectly = (() => {
  try {
    return (
      process.argv[1] !== undefined &&
      import.meta.url === pathToFileURL(resolve(process.argv[1])).href
    );
  } catch {
    return false;
  }
})();

if (invokedDirectly) {
  main().catch((err) => {
    console.error('[ab-check] FAILED:', (err as Error).message);
    process.exitCode = 1;
  });
}
