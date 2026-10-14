import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ACCEPTED_ALG_VERSIONS } from "@qrauth/shared";

// Issue #62 (62a). The schema-level DEFAULT for algVersion on QRCode and
// TransparencyLogEntry was previously `ecdsa-p256-sha256-v1`, which has
// since moved to REJECTED_ALG_VERSIONS — any row inserted under that
// default would fail every verify call silently. This test pins both
// defaults to a value that is currently in the ACCEPTED set so a future
// alg-version reshuffle that drops the default from accepted fails CI
// loudly instead of producing dead rows in prod.

const here = dirname(fileURLToPath(import.meta.url));
const SCHEMA_PATH = resolve(here, "../../api/prisma/schema.prisma");
const schema = readFileSync(SCHEMA_PATH, "utf8");

function defaultFor(model: string, field: string): string | null {
  const modelRe = new RegExp(`model\\s+${model}\\s*\\{([\\s\\S]*?)^\\}`, "m");
  const modelMatch = modelRe.exec(schema);
  if (!modelMatch) return null;
  const body = modelMatch[1];
  const fieldRe = new RegExp(
    `^\\s*${field}\\s+\\S+\\??\\s+@default\\(\\"([^"]+)\\"\\)`,
    "m",
  );
  const fieldMatch = fieldRe.exec(body);
  return fieldMatch ? fieldMatch[1] : null;
}

describe("schema algVersion defaults", () => {
  it("QRCode.algVersion defaults to an accepted alg version", () => {
    const def = defaultFor("QRCode", "algVersion");
    expect(def).not.toBeNull();
    expect(ACCEPTED_ALG_VERSIONS.has(def!)).toBe(true);
  });

  it("TransparencyLogEntry.algVersion defaults to an accepted alg version", () => {
    const def = defaultFor("TransparencyLogEntry", "algVersion");
    expect(def).not.toBeNull();
    expect(ACCEPTED_ALG_VERSIONS.has(def!)).toBe(true);
  });

  it("Defaults match each other (single source of truth)", () => {
    expect(defaultFor("QRCode", "algVersion")).toBe(
      defaultFor("TransparencyLogEntry", "algVersion"),
    );
  });
});
