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

  it("classifies pqc as accepted", () => {
    expect(checkAlgVersion(ALG_VERSION_POLICY.pqc)).toBe("accepted");
  });

  it("classifies pending as accepted", () => {
    expect(checkAlgVersion(ALG_VERSION_POLICY.pending)).toBe("accepted");
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

  it("every ALG_VERSION_POLICY entry classifies as accepted", () => {
    // After AUDIT-FINDING-011 unification dropped legacyEcdsa, every
    // remaining policy entry is in the accepted set.
    for (const version of Object.values(ALG_VERSION_POLICY)) {
      expect(checkAlgVersion(version)).toBe("accepted");
    }
  });

  it("deprecated set is empty; rejected set contains the legacy ECDSA alg", () => {
    expect(DEPRECATED_ALG_VERSIONS.size).toBe(0);
    expect(REJECTED_ALG_VERSIONS.size).toBe(1);
    expect(REJECTED_ALG_VERSIONS.has("ecdsa-p256-sha256-v1")).toBe(true);
  });
});
