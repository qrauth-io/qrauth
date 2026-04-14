/**
 * Algorithm version policy (ALGORITHM.md §11).
 *
 * Every signed payload, every QR row, every transparency log entry carries
 * an `alg_version` string. This module is the single source of truth for
 * which versions are currently acceptable, which are sunsetting, and which
 * are forbidden. Verifiers, issuers, and SDKs all gate on `checkAlgVersion`
 * — drift between modules is the bug this file exists to prevent.
 *
 * Lifecycle of a version string:
 *
 *   unknown → ACCEPTED → DEPRECATED → REJECTED → removed
 *
 * Transitions:
 *   - New algorithms join `ACCEPTED` once the implementation lands and is
 *     covered by tests.
 *   - When superseded, an algorithm moves to `DEPRECATED`. Verifiers still
 *     accept it but log a warning so dashboards can surface a "tokens using
 *     deprecated cryptography" count to operators.
 *   - After the sunset window closes, the algorithm moves to `REJECTED`.
 *     Verifiers fail with `ALG_VERSION_REJECTED`. The string stays in the
 *     set so we never accidentally re-enable it.
 *   - Once no rows reference it, the string is removed from the file
 *     entirely (a separate cleanup audit).
 *
 * NEVER reorder or rename existing entries — they are persisted in the
 * database. Adding new entries is safe; removing requires a migration that
 * confirms no row still references the string.
 */

export const ALG_VERSION_POLICY = {
  /**
   * Accepted: full hybrid signing, currently recommended for all new QRs.
   * Both ECDSA-P256 and SLH-DSA-SHA2-128s legs are required for
   * verification (ALGORITHM.md §6.4).
   */
  hybrid: "hybrid-ecdsa-slhdsa-v1" as const,

  /**
   * Accepted: pure post-quantum mode, no ECDSA leg. Reserved for Phase 3
   * after the hybrid soak period. No code path issues this yet — added
   * here so verifiers learn to recognize it before the cutover.
   */
  pqc: "slhdsa-sha2-128s-v1" as const,

  /**
   * Accepted: high-security SLH-DSA variant. Larger signature
   * (~29 KB) and longer sign latency than `pqc`, 256-bit post-quantum
   * security target. Reserved for government-tier tenants. No code path
   * issues this yet — declared here so verifiers recognize it and
   * `ALG_VERSIONS.SLHDSA_SHA2_256S_V1` resolves to a valid policy
   * entry for SDK consumers and docs.
   */
  pqcHighSecurity: "slhdsa-sha2-256s-v1" as const,

  /**
   * Accepted: transient state for QRs whose ECDSA leg has been signed but
   * whose Merkle/SLH-DSA leg is still being processed by the BatchSigner
   * or has been queued for the reconciler. Verification falls through to
   * ECDSA + MAC alone — no weaker than legacy ECDSA-only signing, just a
   * temporary defense-in-depth gap. The reconciler upgrades the row to
   * `hybrid` within minutes.
   */
  pending: "ecdsa-pending-slhdsa-v1" as const,

  /**
   * Deprecated: pure ECDSA-P256 signing. Quantum-vulnerable (Shor's
   * algorithm derives the private key from any verified signature). New
   * QRs should not use this version; verification still accepts it for
   * legacy rows issued before the PQC migration.
   */
  legacyEcdsa: "ecdsa-p256-sha256-v1" as const,
} as const;

export type AlgVersion = (typeof ALG_VERSION_POLICY)[keyof typeof ALG_VERSION_POLICY];

/**
 * Versions that pass verification silently. New issuance MUST use one of
 * these. The `pending` state is accepted because it is a transient
 * upgrade path — see the comment on `ALG_VERSION_POLICY.pending`.
 */
export const ACCEPTED_ALG_VERSIONS: ReadonlySet<string> = new Set<string>([
  ALG_VERSION_POLICY.hybrid,
  ALG_VERSION_POLICY.pqc,
  ALG_VERSION_POLICY.pqcHighSecurity,
  ALG_VERSION_POLICY.pending,
]);

/**
 * Versions that pass verification but emit a warning. Operators see a
 * "tokens using deprecated cryptography" metric and can plan migration.
 * New issuance MUST NOT produce these.
 */
export const DEPRECATED_ALG_VERSIONS: ReadonlySet<string> = new Set<string>([
  ALG_VERSION_POLICY.legacyEcdsa,
]);

/**
 * Versions that are explicitly forbidden. Verification fails with
 * `ALG_VERSION_REJECTED`. This set is empty today — Phase 3 will move
 * `legacyEcdsa` here once the integration partners have migrated.
 */
export const REJECTED_ALG_VERSIONS: ReadonlySet<string> = new Set<string>([]);

export type AlgVersionStatus = "accepted" | "deprecated" | "rejected" | "unknown";

/**
 * Classify an `alg_version` string.
 *
 * Verifiers use this to decide whether to:
 *   - proceed silently         (`accepted`)
 *   - proceed with a warning   (`deprecated`)
 *   - fail with a hard error   (`rejected`)
 *   - fail with an unknown-alg error (`unknown` — schema violation)
 *
 * Returns `unknown` for any string not in any set, including null. This
 * is intentional: an unrecognized version is a schema violation and the
 * verifier should fail closed, not fall through to the most permissive
 * branch.
 */
export function checkAlgVersion(version: string | null | undefined): AlgVersionStatus {
  if (!version) return "unknown";
  if (ACCEPTED_ALG_VERSIONS.has(version)) return "accepted";
  if (DEPRECATED_ALG_VERSIONS.has(version)) return "deprecated";
  if (REJECTED_ALG_VERSIONS.has(version)) return "rejected";
  return "unknown";
}

// ---------------------------------------------------------------------------
// SDK-facing surface — ALG_VERSIONS alias + isAlgDeprecated helper.
//
// External consumers (node-sdk, python-sdk type stubs, docs, homepage copy)
// reference version strings by their conventional UPPER_SNAKE_CASE names.
// The alias below maps those names to the values already pinned in
// `ALG_VERSION_POLICY`. Internal code paths continue to import
// `ALG_VERSION_POLICY` and `checkAlgVersion` directly — this alias is
// deliberately additive so no existing call site needs to change.
//
// If you add a new version to `ALG_VERSION_POLICY`, add its conventional
// alias here in the same commit so the SDK-facing surface stays in sync.
// ---------------------------------------------------------------------------

export const ALG_VERSIONS = {
  ECDSA_P256_SHA256_V1: ALG_VERSION_POLICY.legacyEcdsa,
  HYBRID_ECDSA_SLHDSA_V1: ALG_VERSION_POLICY.hybrid,
  SLHDSA_SHA2_128S_V1: ALG_VERSION_POLICY.pqc,
  SLHDSA_SHA2_256S_V1: ALG_VERSION_POLICY.pqcHighSecurity,
} as const;

/**
 * Convenience boolean on top of `checkAlgVersion` for SDK consumers who
 * want a yes/no answer without importing the full classifier. Returns
 * `true` only for versions currently in `DEPRECATED_ALG_VERSIONS` —
 * unknown or rejected versions return `false` because they are not
 * deprecated, they are unsupported.
 *
 * Intended use: surface an operator warning in a dashboard when a token
 * is still running on a sunsetting algorithm. Do not surface this to
 * end users.
 */
export function isAlgDeprecated(algVersion: string): boolean {
  return checkAlgVersion(algVersion) === "deprecated";
}
