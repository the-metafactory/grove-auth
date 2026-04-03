# Iteration Plan — Phase 1: Users, Agents, Roles, and Delegation

**Tracking:** the-metafactory/grove-auth#1
**Design:** `docs/design-auth-aaa.md` (v2)
**Goal:** Ship the authorization foundation — user identity, roles, agent registry with pet/cattle classes, ownership, and delegation — so the grove dashboard can add action buttons and `admin.meta-factory.ai` can manage users and grants.

---

## Prerequisites

- [x] Design doc complete (`docs/design-auth-aaa.md` v2)
- [x] Research complete (3 research docs in `docs/research/`)
- [x] Repo onboarded (labels, webhook, bot.yaml, compass template)
- [x] Grove Worker source accessible (grove-auth is a standalone package; grove imports it)

---

## 1.1 — D1 Schema: Users + Agents + Grants ✓

**Branch:** `feat/ga-1-auth-schema` | **PR:** #5 (merged)
**Files:** `src/schema/001_auth_tables.sql`

- [x] Create `users` table (id, email, display_name, role, created_at, updated_at)
- [x] Create `agents` table (id, display_name, owner_id, class, backend, spawn_profile, created_at)
- [x] Create `agent_grants` table (id, agent_id, owner_id, grantee_id, scope, requires_stepup, expires_at, created_at, revoked_at)
- [x] Indexes: `idx_agent_owner`, `idx_grant_grantee`, `idx_grant_agent`
- [x] Foreign keys with `ON DELETE CASCADE`
- [x] CHECK constraints on role, class, scope enums
- [ ] Apply migration to dev D1 (`wrangler d1 migrations apply`) — deferred to grove integration (1.6)
- [x] Verify: schema DDL correct, constraints defined

---

## 1.2 — Seed Initial Data ✓

**Branch:** same as 1.1 | **PR:** #5 (merged)
**Files:** `src/schema/002_seed_data.sql`

- [x] Seed users: Andreas (admin), JC (operator) — emails from CF Access
- [x] Seed agents: luna (pet, local, owner: Andreas)
- [ ] Verify: `SELECT * FROM users` returns seeded data — deferred to grove integration (1.6)
- [ ] Verify: `SELECT * FROM agents` returns agent registry — deferred to grove integration (1.6)
- [x] Verify: foreign key from agents.owner_id → users.id defined correctly

---

## 1.3 — Middleware: `requireRole()` ✓

**Branch:** `feat/ga-1-auth-schema` (bundled with 1.1-1.2) | **PR:** #5 (merged)
**Files:** `src/middleware/require-role.ts`, `src/authorize.ts`

- [x] Add `requireRole(minRole: Role)` middleware function
- [x] Extract email from CF Access JWT (`getCfAccessEmail()` in `src/middleware/cf-access.ts`)
- [x] Look up user in D1 by email
- [x] Compare user.role against required role (viewer < operator < admin)
- [x] Return 403 with `{ error: "insufficient_role", required, current }` if denied
- [x] Return 401 if user not found in D1 (CF Access passed but no user record)
- [x] Set `c.set("user", userRecord)` on Hono context for downstream use
- [x] Audit log: role check (pass/fail) via `logAuditEvent()`
- [x] Pure `checkRole()` function extracted to `src/authorize.ts` (shared by middleware + tests)
- [x] Tests: role hierarchy (admin > operator > viewer) — 26 tests in total

---

## 1.4 — Middleware: `requireAgentAccess()` ✓

**Branch:** same as 1.3 | **PR:** #5 (merged)
**Files:** `src/middleware/require-agent-access.ts`, `src/authorize.ts`

- [x] Add `requireAgentAccess(scope: 'read' | 'review' | 'control')` middleware
- [x] Read `agentId` from route params
- [x] Resolution order:
  1. Is caller the agent owner? → full access
  2. Does caller have an active grant with sufficient scope? (not revoked, not expired)
  3. Is caller admin? → bypass ownership
  4. Is agent class `cattle`? → any operator can access
- [x] Return 403 with `{ error: "no_agent_access", agentId, available_scope }` if denied
- [x] Pure `checkAgentAccess()` function extracted to `src/authorize.ts` (single JOIN query)
- [x] Audit log: access check with resolution path (owner/grant/admin/cattle)
- [x] Tests: owner access, grant scopes (read < review < control), expired grant, revoked grant, admin bypass, cattle open access

---

## 1.5 — API: Auth Endpoints (in progress)

**Branch:** `feat/ga-5-auth-api` | **Worktree:** `../grove-auth-api`
**Files:** `src/routes/auth.ts`, `src/routes/auth.test.ts`, `src/index.ts`

Exported as a Hono route group (`authRoutes`) for consuming Workers to mount.

**Identity:**
- [x] `GET /api/auth/me` — current user profile + owned agents + active grants (received and given)

**User management (admin only):**
- [x] `GET /api/auth/users` — list all users
- [x] `PUT /api/auth/users/:id/role` — change user role

**Agent registry:**
- [x] `GET /api/auth/agents` — list agents filtered by caller context:
  - Operators: own agents + delegated agents + cattle (with relationship badges)
  - Admin: all agents
- [x] `GET /api/auth/agents/:id` — agent detail with ownership + grant info

**Delegation:**
- [x] `POST /api/auth/agents/:id/grants` — create grant (owner or admin only)
  - Body: `{ grantee_id, scope, requires_stepup, expires_at }`
- [x] `GET /api/auth/agents/:id/grants` — list grants for an agent
- [x] `DELETE /api/auth/grants/:id` — revoke grant (sets revoked_at, retains for audit)
- [ ] `POST /api/auth/agents/:id/request-access` — request access (notifies owner) — deferred to Phase 2 (requires notification infrastructure)

All endpoints behind inline auth middleware (CF Access JWT → D1 user lookup). All mutations audit-logged. 20 new tests (46 total), TypeScript clean.

**Status:** Code complete, committed locally. Not yet pushed / PR not yet created.

---

## 1.6 — Wire Existing Routes to Role Middleware

> **Target repo: grove** (not grove-auth) — this is the integration step where grove imports grove-auth and mounts the auth routes.

**Branch:** TBD (in grove repo)
**Files:** `grove/src/worker/src/router.ts`, `grove/src/worker/src/index.ts`

- [ ] Add grove-auth as dependency in grove Worker
- [ ] Mount `authRoutes` in grove Worker's Hono app
- [ ] Apply D1 schema (`001_auth_tables.sql`) and seed data (`002_seed_data.sql`) to grove's D1
- [ ] Identify all write endpoints currently using `requireAdmin()` or `requireApiKey()`
- [ ] Replace `requireAdmin()` with `requireRole("admin")` where appropriate
- [ ] Add `requireRole("operator")` to operator-level endpoints
- [ ] Keep `requireApiKey()` for bot/machine auth (service tokens)
- [ ] Ensure read endpoints remain accessible to `viewer` role
- [ ] Regression check: existing dashboard still loads, bot sync still works

---

## 1.7 — Dashboard: Auth Context + Agent Visibility

> **Target repo: grove** — dashboard lives in grove, not grove-auth.

**Branch:** TBD (in grove repo)
**Files:** `grove/src/dashboard/`

- [ ] Call `GET /api/auth/me` on dashboard load
- [ ] Store user context (role, owned agents, active grants) in React state
- [ ] Show user identity in header (email, role badge)
- [ ] Agent cards show relationship badge: "owner" / "delegated (scope)" / "read-only"
- [ ] Agent cards show class badge: "pet · local" / "pet · EC2" / cattle nested under parent
- [ ] Group agents: My Agents / Delegated to Me / Network (read-only)
- [ ] Toggle to hide/show network agents
- [ ] "Request Access" button on network pet agent cards
- [ ] Show available scope when grant exists but action exceeds it
- [ ] Conditionally render action buttons based on role + ownership + grant scope
- [ ] Show "Insufficient permissions" when API returns 403

---

## 1.8 — Integration Testing

> **Target repo: grove** — integration tests run against the grove Worker with grove-auth mounted.

**Branch:** TBD (in grove repo)

- [ ] Test: viewer loads dashboard, sees all agents (read-only), no action buttons
- [ ] Test: operator sees own pet agents with full action buttons
- [ ] Test: operator sees delegated agents with scoped action buttons
- [ ] Test: operator sees network pet agents with "Request Access"
- [ ] Test: operator gets 403 accessing another operator's pet agent without grant
- [ ] Test: operator with `review` grant can trigger review but not merge/stop
- [ ] Test: expired grant returns 403
- [ ] Test: cattle agents accessible to any operator (no grant needed)
- [ ] Test: admin sees all agents, can modify roles and grants
- [ ] Test: unauthenticated request (no CF Access JWT) → 401
- [ ] Test: authenticated but no D1 record → 401 with "user not provisioned"
- [ ] Test: bot service token still works for ingest endpoints

---

## 1.9 — Documentation & Release

- [ ] Update `grove-auth/README.md` with Phase 1 completion status
- [ ] Update design doc if any decisions changed during implementation
- [ ] Bump grove version (minor — new auth middleware)
- [ ] Create GitHub release with Phase 1 summary
- [ ] Update grove-auth#1 issue — tick checkboxes, add completion comment

---

## Exit Criteria

Phase 1 is done when:
1. Every dashboard API request is associated with a user identity (not just a CF Access email)
2. Write operations are gated by role (viewer cannot trigger actions)
3. Pet agent actions are gated by ownership or delegation (operators control only their own agents unless granted)
4. Cattle agents are accessible to any authorized operator (no ownership gate)
5. Delegation grants work: create, scope-check, expire, revoke
6. Dashboard shows agent relationship (own/delegated/network) with class badges and scoped action buttons
7. Admin can manage all users, agents, and grants
8. Audit log captures all auth events including delegation
9. Existing bot/machine auth (API keys, service tokens) continues to work unchanged

**Next:** Phase 2 (PassKey enrollment + step-up + admin.meta-factory.ai) — tracked in grove-auth#2
