# Research: CF API Hardening Audit — Miner, Grove, Grove-Auth

**Date:** 2026-04-03
**Source:** Codebase audit of miner-server, grove Worker, and grove-auth
**Purpose:** Identify security patterns, gaps, and inconsistencies across the ecosystem's Cloudflare Worker APIs to inform grove-auth's auth design.

---

## 1. Hardening Patterns In Use

### S-001: CF Access JWT Validation (Network Layer Auth)

All three codebases implement CF Access JWT validation:
- **miner-server:** `src/auth.ts` (lines 80-219)
- **grove:** `src/worker/src/auth.ts` (lines 121-263)
- **grove-auth:** `src/middleware/cf-access.ts`

Features: JWK caching (10min TTL), RS256 validation, audience + expiration checks, CF_Authorization cookie + Cf-Access-Jwt-Assertion header support, audit logging on success/failure, optional bypass when CF_ACCESS_AUD not configured (local dev).

### S-002: CORS Origin Allowlisting

- **miner-server:** `src/index.ts` (lines 36-46) — `https://miner.meta-factory.ai`, `http://localhost:8767`
- **grove:** `src/worker/src/index.ts` (lines 36-47) — `https://grove.meta-factory.ai`, `http://localhost:8766,8765`

Env-configurable, comma-separated multi-origin, Hono CORS middleware, credentials enabled.

### S-003: Rate Limiting by Category

| Tier | Public | Read | Write | Admin |
|------|--------|------|-------|-------|
| Limit | 60/min | 120/min | 300/min | 10/min |

- **miner-server:** `src/rate-limit.ts` — KV-backed sliding window (persistent across isolates)
- **grove:** `src/worker/src/rate-limiter.ts` — in-memory counters (resets on isolate recycle)

Both extract client IP from CF-Connecting-IP / X-Forwarded-For, return 429 with Retry-After, add X-RateLimit-* headers.

### S-004: Input Validation

Both workers use parameterized D1 queries (no string concatenation), JSON parse-with-catch, explicit field validation, and boundary checks (e.g., audit log limit capped at 500).

### S-005: Audit Logging

Fire-and-forget D1 writes via `waitUntil()`. All auth events logged with action, endpoint, method, IP, identity, timestamp, detail.

### S-006: PII Scrubbing (Miner-Server Only)

`miner-server/src/scrub.ts` — regex-based scrubbing of API keys (sk-, miner_sk_, grove_sk_), Bearer tokens, env secrets, emails, file paths with usernames, IPv4 addresses, SSH/PGP keys. Applied at event/trace ingest before D1 storage. Grove does not scrub.

### S-007: API Key Authentication

Both workers use `requireApiKey()` middleware — Bearer token validated against KV namespace (MINER_KEYS / GROVE_KEYS). Key format: prefix + 48 random hex. Metadata: operator_id, name, created_at.

### S-008: GitHub Webhook HMAC (Grove Only)

`grove/src/worker/src/routes/github.ts` — HMAC-SHA256 via `@octokit/webhooks-methods`. Validates x-hub-signature-256 header. Returns 401 on signature mismatch.

---

## 2. Gaps and Inconsistencies

### Gap 1: Admin Secret is a Shared Credential

**Risk:** ADMIN_SECRET is a single shared credential — all admins are indistinguishable in audit logs ("identity: admin").
**Affected:** miner-server `requireAdmin()`, grove `requireAdmin()`
**Fix:** grove-auth replaces this with `requireRole("admin")` — admin users identified by email via CF Access JWT + D1 lookup. Both workers should migrate.
**Phase:** 1.6 (grove integration)

### Gap 2: API Key Metadata Lacks Issuer

**Risk:** No `issued_by` field on API keys — audit log says "key XYZ failed" but not "admin Alice created key XYZ".
**Affected:** Both workers' key creation endpoints.
**Fix:** Add `issued_by: userId`, `issued_at: timestamp` to OperatorKey metadata. Track key lifecycle in audit_log.
**Phase:** Future (cross-cutting improvement)

### Gap 3: Grove Rate Limiting is In-Memory

**Risk:** In-memory counters reset on isolate recycle — rate limits are ineffective under high request volume or during deployments.
**Affected:** `grove/src/worker/src/rate-limiter.ts`
**Fix:** Migrate to KV-backed sliding window (same approach as miner-server).
**Phase:** Future (grove hardening, not grove-auth scope)

### Gap 4: CF Access JWT Expiration Handling Inconsistent

**Risk:** miner-server and grove accept tokens without `exp` claim. CF Access always includes `exp`, but a crafted token without it would pass validation.
**Affected:** miner-server `src/auth.ts` (line 158-159), grove `src/worker/src/auth.ts`
**Fix:** grove-auth already implements stricter check (`if (!exp || exp < ...)`). Backport to miner-server and grove.
**Phase:** Future (backport from grove-auth)

### Gap 5: No PII Scrubbing in Grove

**Risk:** Raw emails, IPs, and file paths stored in grove's session_activity and usage_snapshots D1 tables.
**Affected:** `grove/src/worker/`
**Decision needed:** Should grove scrub like miner-server, or is raw storage acceptable for an auth/ops tool where operator emails are expected?
**Phase:** Decision in Phase 1.9 (documentation), implementation if needed in future.

### Gap 6: Audit Event Schema Inconsistent

**Risk:** Three different field names for the same concept:
- miner-server: `action` field (e.g., `api_key_success`)
- grove: `eventType` field (e.g., `api_key_auth`)
- grove-auth: `event_type` column (as in D1 schema)
**Fix:** Standardize on `event_type` (grove-auth's convention). Define canonical event taxonomy.
**Phase:** Future (cross-cutting, requires both workers to migrate)

### Gap 7: Service Token Validation Unclear

**Risk:** Both workers mention CF-Access-Client-Id/Secret headers for service tokens (CLI/bot) but don't validate them in Worker code.
**Assumption:** CF Access gateway validates service tokens before request reaches Worker.
**Fix:** Document this assumption explicitly. If Worker-level validation is needed, implement HMAC verification.
**Phase:** Decision in Phase 1.9

### Gap 8: Audit Query API Differs

**Risk:** Inconsistent parameter names — miner: `?action=X`, grove: `?type=X&result=Y`
**Fix:** grove-auth should define canonical audit query API; both workers adopt it.
**Phase:** Future (when grove-auth provides shared audit module)

---

## 3. Recommendations for Grove-Auth

### Phase 1 (current — no changes needed to auth API)

Grove-auth's existing implementation already addresses Gap 1 (role-based admin) and Gap 4 (strict JWT exp). The auth API endpoints in 1.5 use the correct patterns. No blockers.

### Phase 1.6 (grove integration)

- Replace grove's `requireAdmin()` with grove-auth's `requireRole("admin")`
- Mount grove-auth's `authRoutes` and use its CF Access validation
- This naturally resolves Gap 1 for grove

### Phase 1.9 (documentation)

Document decisions on:
- PII scrubbing policy (Gap 5)
- Service token validation assumption (Gap 7)
- Audit event taxonomy direction (Gap 6)

### Future (cross-cutting hardening)

- Gap 2: API key issuer metadata
- Gap 3: KV-backed rate limiting in grove
- Gap 6: Unified audit event schema
- Gap 8: Canonical audit query API

---

## 4. Summary Table

| Pattern | Miner-Server | Grove | Grove-Auth | Status |
|---------|-------------|-------|------------|--------|
| CF Access JWT | 10min cache, RS256 | 10min cache, RS256 | Stricter exp check | grove-auth is canonical |
| CORS Allowlist | Env-configured | Env-configured | N/A | Aligned |
| Rate Limiting | KV-backed | In-memory (Gap 3) | N/A | Grove should migrate to KV |
| Input Validation | Parameterized SQL | Parameterized SQL | Parameterized SQL | Aligned |
| Audit Logging | Fire-and-forget D1 | Fire-and-forget D1 | Reusable helper | grove-auth canonical |
| PII Scrubbing | Regex-based | None (Gap 5) | N/A | Decision needed |
| Admin Auth | Shared secret (Gap 1) | Shared secret (Gap 1) | Role-based | grove-auth fixes this |
| API Key Lifecycle | No issuer (Gap 2) | No issuer (Gap 2) | N/A | Future improvement |
