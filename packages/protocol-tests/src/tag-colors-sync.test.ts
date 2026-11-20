import { describe, expect, it } from "vitest";
import { TAG_COLORS } from "@qrauth/shared";

// The Node SDK ships its own copy of the palette (it has no runtime
// dependency on @qrauth/shared); the two must not drift.
import { TAG_COLORS as SDK_TAG_COLORS } from "../../node-sdk/src/types.js";

describe("tag colour palette", () => {
  it("is the same in @qrauth/shared and the Node SDK", () => {
    expect([...SDK_TAG_COLORS]).toEqual([...TAG_COLORS]);
  });
});
