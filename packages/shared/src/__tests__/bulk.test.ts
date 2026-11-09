import { describe, expect, it } from "vitest";

import { endOfDayInTimeZone, isValidTimeZone } from "../bulk.js";

describe("isValidTimeZone", () => {
  it("accepts IANA names and refuses anything else", () => {
    expect(isValidTimeZone("Europe/Athens")).toBe(true);
    expect(isValidTimeZone("UTC")).toBe(true);
    expect(isValidTimeZone("Europe/Atlantis")).toBe(false);
    expect(isValidTimeZone("")).toBe(false);
    expect(isValidTimeZone("x".repeat(65))).toBe(false);
  });
});

describe("endOfDayInTimeZone", () => {
  it("is 23:59:59 local time, across DST changes", () => {
    expect(endOfDayInTimeZone("2027-01-15", "UTC")).toBe("2027-01-15T23:59:59.000Z");
    expect(endOfDayInTimeZone("2027-01-15", "Europe/Athens")).toBe("2027-01-15T21:59:59.000Z");
    expect(endOfDayInTimeZone("2027-03-28", "Europe/Athens")).toBe("2027-03-28T20:59:59.000Z");
    expect(endOfDayInTimeZone("2027-10-31", "Europe/Athens")).toBe("2027-10-31T21:59:59.000Z");
    expect(endOfDayInTimeZone("2027-06-30", "Asia/Kolkata")).toBe("2027-06-30T18:29:59.000Z");
    expect(endOfDayInTimeZone("2027-12-31", "Pacific/Kiritimati")).toBe("2027-12-31T09:59:59.000Z");
  });
});
