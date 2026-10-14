import { describe, it, expect } from "vitest";
import {
  checkNodeVersion,
  MIN_NODE_MAJOR,
} from "../../api/src/lib/node-version-check.js";

describe("checkNodeVersion", () => {
  it("pins the minimum to 22", () => {
    expect(MIN_NODE_MAJOR).toBe(22);
  });

  it("accepts the exact minimum", () => {
    expect(checkNodeVersion("22.0.0")).toBeNull();
  });

  it("accepts versions newer than the minimum", () => {
    expect(checkNodeVersion("22.15.0")).toBeNull();
    expect(checkNodeVersion("23.5.1")).toBeNull();
    expect(checkNodeVersion("24.0.0")).toBeNull();
  });

  it("rejects every Node 20.x release", () => {
    expect(checkNodeVersion("20.0.0")).not.toBeNull();
    expect(checkNodeVersion("20.19.0")).not.toBeNull();
  });

  it("rejects every Node 18.x release", () => {
    expect(checkNodeVersion("18.20.0")).not.toBeNull();
  });

  it("rejects malformed version strings", () => {
    expect(checkNodeVersion("")).not.toBeNull();
    expect(checkNodeVersion("not-a-version")).not.toBeNull();
  });

  it("the failure message names the running version", () => {
    const msg = checkNodeVersion("20.19.0");
    expect(msg).toContain("20.19.0");
    expect(msg).toContain("22");
  });
});
