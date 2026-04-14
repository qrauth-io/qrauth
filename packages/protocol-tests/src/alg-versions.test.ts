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

  it("classifies legacy ECDSA as deprecated", () => {
    expect(checkAlgVersion(ALG_VERSION_POLICY.legacyEcdsa)).toBe("deprecated");
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

  it("every ALG_VERSION_POLICY entry classifies as accepted or deprecated", () => {
    // No policy entry should sit in the rejected/unknown buckets while the
    // codebase still references it. If this fails after a Phase 3 cutover,
    // delete the constant from ALG_VERSION_POLICY at the same time.
    for (const version of Object.values(ALG_VERSION_POLICY)) {
      const status = checkAlgVersion(version);
      expect(["accepted", "deprecated"]).toContain(status);
    }
  });

  it("rejected set is currently empty (Phase 2 invariant)", () => {
    // Phase 3 will move legacyEcdsa into this set. Until then the set must
    // stay empty so this test fails loudly the moment Phase 3 lands and we
    // can review the cutover.
    expect(REJECTED_ALG_VERSIONS.size).toBe(0);
  });
});
