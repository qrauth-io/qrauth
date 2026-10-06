# SECURITY-REVIEW-LOG — overnight pentest verification pass

- **Branch:** `fix/pentest-same-day` (tracks `origin/fix/pentest-same-day`)
- **Base commit reviewed:** `b0ef9a2` — *fix(api): harden webhook SSRF; gate auth-session PII; block org mass-assignment*
- **Findings doc:** none in repo (`.pentest/` is gitignored / server-only). **Inventory taken from the `b0ef9a2` commit message**, per task fallback.
- **Inventory:** INJ-001 (CRITICAL, webhook SSRF) · AUTH-001 (HIGH, verify-result PII) · IDOR-001 (HIGH, org mass-assignment) · INJ-005 (MEDIUM, DNS rebinding residual) · INJ-002/003 (XSS via `javascript:`/`data:` URLs — covered by committed `content-url-schemes.test.ts`)
- **Start:** 2026-05-22 ~22:30 local · **End:** 2026-05-22 ~23:10 local
- **Final status:** branch GREEN — `api` unit + full suite pass, `api` typecheck passes. 1 fix commit landed (regression tests). No code-behavior changes; no API contract changes; nothing pushed to `main`.

---

## Phase 0 note (transparency)
The first `git fetch --all` **silently failed against `origin`** (`git@github.com:aristech/vqr` — broken pipe; only the `qrauth-io` remote succeeded). With `origin` not fetched, `b0ef9a2` and `fix/pentest-same-day` were absent, and I very nearly recorded a false "Phase 0 precondition failure." A **second `git fetch origin`** succeeded, `b0ef9a2` resolved, and I proceeded normally. Lesson logged: `--all` masked a per-remote failure; verify the target ref resolves, don't trust the aggregate exit code.

---

## 1. Per-finding verdicts (independently re-derived)

### INJ-001 — Webhook SSRF — **HOLDS** ✅
`packages/api/src/lib/url-validation.ts` `isSafeWebhookUrl()` + both fetch callsites.

Independent bypass attempts (on paper **and** exercised against the real validator via unit tests):
| Vector | Result | Why |
|---|---|---|
| IPv4-mapped IPv6 `[::ffff:169.254.169.254]` / hex `[::ffff:a9fe:a9fe]` | rejected | `normalizeHostname` regex → dotted → `rejectIPv4` (169.254/16) |
| Decimal `http://2130706433/` | rejected | **WHATWG URL canonicalizes → `127.0.0.1`** → `isIP===4` → `rejectIPv4` |
| Octal `http://0177.0.0.1/`, hex `http://0x7f000001/`, `http://0xa9fea9fe/` | rejected | same canonicalization |
| Trailing dot `http://169.254.169.254./` | rejected | parser strips the trailing dot |
| `0.0.0.0` | rejected | `rejectIPv4` 0.0.0.0/8 |
| Userinfo `http://expected.com@169.254.169.254/` | rejected | authority host = `169.254.169.254` |
| IPv6 `::1`, `::`, `fe80::/10`, `fc00::/7` (`fd00::1`) | rejected | `rejectIPv6` |
| `localhost`, `*.localhost`, `metadata.google.internal` | rejected | hostname checks |
| non-http(s) (`file:`, `gopher:`) | rejected | scheme allowlist |
| 30x redirect to internal target after a passing URL | **fails closed** | `redirect:'manual'` on **both** callsites (`workers/index.ts:392`, `:591`); opaque-redirect → `status 0`, `ok:false` → failure branch, never followed |

I empirically verified the WHATWG normalization (`node -e` on `new URL(...).hostname` + `isIP`) — the integer/octal/hex/trailing-dot forms were my suspected residual bypasses; they are **not** exploitable because the parser canonicalizes them *before* the range checks run. Validator wired on the delivery path at `services/app.ts:46,133` (create/update) and re-validated at delivery in `workers/index.ts:324`.

**Residual:** INJ-005 (DNS rebinding) only — see §5.

### AUTH-001 — `POST /auth-sessions/verify-result` PII — **HOLDS & complete** ✅
`packages/api/src/routes/auth-sessions.ts:700-717`.
- `valid = cryptoValid && isApproved`; `user` is `valid && session.user ? {…} : null`; `signature` is spread only `...(valid ? {signature} : {})`. A sessionId-only caller with a bogus signature gets `valid:false`, `user:null`, **no signature**. ✔
- **Sibling-endpoint sweep (the explicit task check):** the only public, sessionId-addressable endpoint is `verify-result`. `GET /:id`, `GET /:id/sse`, `POST /:id/exchange` all require **app credentials** (`authenticateApp`), enforce `verifyAppOwnsSession(id, app.id)` (404 cross-app), and gate PII behind PKCE `code_verifier` for public clients (`auth-sessions.ts:288,302-323`). `POST /:token/approve|deny` require a user JWT. **No sibling leaks PII to a sessionId-only caller.** ✔

### IDOR-001 — Org mass-assignment — **HOLDS** ✅ (both halves)
- **Route/schema half (committed):** `PATCH /organizations/:id` now uses `selfUpdateOrganizationSchema` and no longer spreads `plan`/`trustLevel` into Prisma (`organizations.ts:96,115-124`; `shared/src/validation.ts`). `plan`/`trustLevel` remain writable only by billing/admin paths. ✔
- **Object-level / role half (independently verified — already enforced, not a new gap):** every mutating org route carries `authorize('OWNER','ADMIN')` **and** an `orgId===:id` binding (`checkOrgAccess` helper, or an inline equivalent on `:id/generate-verify-token` and `:id/verify-domain`). I mapped all 18 route declarations — all guarded.
  - **Cross-tenant test (on paper):** a member of org A holds a JWT with `orgId=A`; `PATCH /organizations/B` → `checkOrgAccess` 403. A token's `(orgId, role)` is only ever minted from a **verified Membership**: login picks the user's active membership; `POST /auth/switch-org` (`auth.ts:311-334`) looks up `Membership(userId, requestedOrg)`, 403s if absent, and signs `role = membership.role`. So a caller cannot obtain a token for an org they aren't a member of, nor a role they don't hold. ✔
  - **Adjacent sweep:** `PATCH /:id/members/:userId` (OWNER-only OWNER-promotion, last-owner-demote guard), `DELETE /:id/members/:userId`, `POST /:id/invitations`, `POST /invitations/:token/accept` (binds `request.user.email === invitation.email`, role taken from the invitation not user input) — all correctly scoped. No cross-tenant or privilege-escalation gap found. ✔

### INJ-002/003 — content-type URL XSS (`javascript:`/`data:`) — **HOLDS** (build caveat below) ✅
`httpUrl()`/`safeImageUrl()` in `packages/shared/src/http-url.ts` parse with WHATWG URL and reject non-http(s) schemes; wired into `validation.ts` (`destinationUrl`, `fileUrl`, `website`, `socialLinks`, `redemptionUrl`, `logoUrl`, `webhookUrl`). Committed `content-url-schemes.test.ts` (8 tests) passes **after rebuilding `@qrauth/shared`** — see Build caveat.

---

## 2. New findings
- **None HIGH/CRITICAL.** The in-scope surface is solid.
- **(LOW / defense-in-depth) Stale role & membership in JWT** — see §4 #1.
- **(INFO) `verify-result` still returns `status`/`appName`/`scopes` to a sessionId-only caller when `valid:false`.** Not PII; `sessionId` is a random UUID (non-enumerable) and `verify-result` is rate-limited (`rateLimitPublic`). No action recommended.
- **(BUILD, not a vuln) Stale `@qrauth/shared` dist made the suite look RED at checkout** — see Build caveat.

---

## 3. Fixes landed
| Finding | Change | Test | Commit |
|---|---|---|---|
| INJ-001 | none needed (holds); added regression guards for alternate IPv4 encodings + userinfo host-confusion | `test/unit/url-validation-ssrf.test.ts` (10 → 16 tests) | `08ae790` |

No source/behavior changes were required — all three primary findings were already correctly fixed at `b0ef9a2`. The one commit is **additive test coverage** the task explicitly requested (bypass vectors), proving the vectors are closed and pinning the WHATWG-normalization behavior against future parser swaps.

---

## 4. Decisions needed (review together)
1. **Stale role/membership in JWT (LOW, defense-in-depth).** `authorize()` + `checkOrgAccess` trust the token's `role`/`orgId` for the full access-token TTL (`JWT_EXPIRES_IN` = **15m**). A member who is demoted (e.g. ADMIN→VIEWER) or removed retains their old privileges on the affected org until the token expires. Short window, classic stateless-JWT tradeoff. **Closing it** = re-derive role from a live `Membership` lookup per mutating request (or maintain a token-version/`tokenNonce` revocation list). That adds a DB hit per request and may require test fixtures to create Membership rows. **PARKED** — needs your call on the perf/UX cost vs. the 15-minute exposure. *(Not introduced by b0ef9a2; pre-existing architecture.)*
2. **AUTH-001 route-level regression test.** The gating is verified by code reading; the only committed unit test (`auth-session-scopes.test.ts`) covers the scope schema, not the route response shaping. A proper guard is a route/integration test asserting `valid:false ⇒ user:null & no signature`, but it needs Postgres (calls `verifyApprovalSignature` → Prisma). **PARKED** — add when a DB is available in the test env. Low risk; not a vuln.
3. **`origin` remote reachability.** The first `git fetch` against `origin` failed (broken pipe). Worth confirming network/SSH health to `git@github.com:aristech/vqr` so CI/automation don't hit the same intermittent failure.

---

## 5. INJ-005 (DNS rebinding) — status & recommended approach
**Open, MEDIUM, known residual** — explicitly documented in the `isSafeWebhookUrl` doc comment and the `b0ef9a2` message. `isSafeWebhookUrl` is a string-level check; a hostname can resolve to a public IP at validation time and a private IP at connect time, and `fetch` re-resolves internally.
**Recommended fix (PARKED — needs the fetch layer restructured, beyond an autonomous same-night change):** add a shared `safeFetch(url)` helper that (a) `dns.lookup`s the host once, (b) runs the resolved IP(s) through the `rejectIPv4`/`rejectIPv6` logic, and (c) connects to that **pinned** IP (custom `undici` Agent with a `connect`/`lookup` hook, preserving SNI + `Host`). Apply at both webhook callsites. This closes the resolve↔connect gap that `redirect:'manual'` and the string check cannot. Pure-unit-testable for the IP-rejection portion; the pinning needs an integration test.

---

## 6. Verify — exact commands & results
| Command | Result |
|---|---|
| `npm run build -w packages/shared` | ✅ tsc clean (fixed stale dist) |
| `npx vitest run test/unit/` (packages/api) | ✅ 60 passed |
| `npm run test -w packages/api -- run` (full) | ✅ **29 files, 219 passed, 2 skipped** (DB integration test self-skips) |
| `npm run build -w packages/api` (tsc typecheck) | ✅ exit 0 |
| `git status` | clean except this log + pre-existing untracked `drafts/`, `marketing/` |

### Build caveat (important for CI/morning)
At checkout the suite showed **8 failures** in `content-url-schemes.test.ts` — a **false red** caused by a **stale `@qrauth/shared` dist** (the compiled package predated `http-url.ts`; tests import the built package). `npm run build -w packages/shared` resolved it and all 219 tests pass. **Recommendation:** ensure CI builds `shared` before running `api` tests (the root `npm run build` does shared→api→web, but `npm test` alone does not), or the pipeline will intermittently fail on a clean checkout.

---

## Safety rails — confirmed honored
No commits/pushes to `main`; no merges. No changes to signing/key/crypto/signer paths. No tests weakened, skipped, or deleted (only added). No force-push/rebase/history rewrite. No public API shape/contract changes. No new runtime deps installed. All work on `fix/pentest-same-day`.
