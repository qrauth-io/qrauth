import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ACCEPTED_ALG_VERSIONS } from "@qrauth/shared";

// QRCode.algVersion is required with no default: every insert must state the
// version it signed, so no row can land on an implicit fallback (and no
// hybrid row can appear without the Merkle fields its version requires).
// TransparencyLogEntry.algVersion keeps a default; it must stay accepted so a
// future alg-version reshuffle fails CI instead of producing dead log rows.

const here = dirname(fileURLToPath(import.meta.url));
const SCHEMA_PATH = resolve(here, "../../api/prisma/schema.prisma");
const schema = readFileSync(SCHEMA_PATH, "utf8");

function fieldLine(model: string, field: string): string | null {
  const modelRe = new RegExp(`model\\s+${model}\\s*\\{([\\s\\S]*?)^\\}`, "m");
  const modelMatch = modelRe.exec(schema);
  if (!modelMatch) return null;
  const fieldRe = new RegExp(`^\\s*${field}\\s+.*$`, "m");
  const fieldMatch = fieldRe.exec(modelMatch[1]);
  return fieldMatch ? fieldMatch[0].trim() : null;
}

function defaultFor(model: string, field: string): string | null {
  const line = fieldLine(model, field);
  const m = line ? /@default\("([^"]+)"\)/.exec(line) : null;
  return m ? m[1] : null;
}

describe("schema algVersion", () => {
  it("QRCode.algVersion is required and has no default", () => {
    const line = fieldLine("QRCode", "algVersion");
    expect(line).not.toBeNull();
    expect(line).toMatch(/^algVersion\s+String(\s|$)/);
    expect(line).not.toMatch(/String\?/);
    expect(line).not.toMatch(/@default/);
  });

  it("TransparencyLogEntry.algVersion defaults to an accepted alg version", () => {
    const def = defaultFor("TransparencyLogEntry", "algVersion");
    expect(def).not.toBeNull();
    expect(ACCEPTED_ALG_VERSIONS.has(def!)).toBe(true);
  });
});
