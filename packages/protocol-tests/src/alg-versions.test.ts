import { describe, it, expect } from "vitest";
import {
  ALG_VERSION_POLICY,
  ACCEPTED_ALG_VERSIONS,
  DEPRECATED_ALG_VERSIONS,
  REJECTED_ALG_VERSIONS,
  checkAlgVersion,
} from "@qrauth/shared";

describe("alg-version policy", () => {
  it("classifies hybrid as accepted", () => {
    expect(checkAlgVersion(ALG_VERSION_POLICY.hybrid)).toBe("accepted");
  });

  it("classifies the reserved PQC-only versions as rejected until a verifier exists", () => {
    expect(checkAlgVersion(ALG_VERSION_POLICY.pqc)).toBe("rejected");
    expect(checkAlgVersion(ALG_VERSION_POLICY.pqcHighSecurity)).toBe("rejected");
  });

  it("classifies the former pending state as rejected", () => {
    // No issuance path produces this version; verification refuses it.
    expect(checkAlgVersion("ecdsa-pending-slhdsa-v1")).toBe("rejected");
  });

  it("classifies legacy ECDSA as rejected (dropped by AUDIT-FINDING-011)", () => {
    // `ecdsa-p256-sha256-v1` was removed from ALG_VERSION_POLICY by the
    // canonical-form unification and then explicitly pinned into
    // REJECTED_ALG_VERSIONS so stragglers surface as `rejected` rather
    // than the softer `unknown`. Either way the verifier refuses closed.
    expect(checkAlgVersion("ecdsa-p256-sha256-v1")).toBe("rejected");
  });

  it("classifies an unknown string as unknown", () => {
    expect(checkAlgVersion("totally-made-up-v9")).toBe("unknown");
  });

  it("classifies null and undefined as unknown", () => {
    expect(checkAlgVersion(null)).toBe("unknown");
    expect(checkAlgVersion(undefined)).toBe("unknown");
    expect(checkAlgVersion("")).toBe("unknown");
  });

  it("the four sets are pairwise disjoint", () => {
    const intersection = (a: ReadonlySet<string>, b: ReadonlySet<string>) => {
      for (const x of a) if (b.has(x)) return true;
      return false;
    };
    expect(intersection(ACCEPTED_ALG_VERSIONS, DEPRECATED_ALG_VERSIONS)).toBe(false);
    expect(intersection(ACCEPTED_ALG_VERSIONS, REJECTED_ALG_VERSIONS)).toBe(false);
    expect(intersection(DEPRECATED_ALG_VERSIONS, REJECTED_ALG_VERSIONS)).toBe(false);
  });

  it("hybrid is the only accepted version", () => {
    expect([...ACCEPTED_ALG_VERSIONS]).toEqual([ALG_VERSION_POLICY.hybrid]);
  });

  it("deprecated set is empty; rejected set holds legacy ECDSA, pending and the reserved versions", () => {
    expect(DEPRECATED_ALG_VERSIONS.size).toBe(0);
    expect(REJECTED_ALG_VERSIONS.size).toBe(4);
    expect(REJECTED_ALG_VERSIONS.has("ecdsa-p256-sha256-v1")).toBe(true);
    expect(REJECTED_ALG_VERSIONS.has("ecdsa-pending-slhdsa-v1")).toBe(true);
  });
});
