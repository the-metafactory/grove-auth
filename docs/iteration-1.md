# Iteration Plan — Phase 1: User Table + Role-Based Authorization + Agent Ownership

**Tracking:** the-metafactory/grove-auth#1
**Design:** `docs/design-auth-aaa.md`
**Goal:** Ship the authorization foundation — user identity, roles, and agent ownership — so the Grove dashboard can build action controls on top of it.

---

## Prerequisites

- [x] Design doc complete (`docs/design-auth-aaa.md`)
- [x] Research complete (3 research docs in `docs/research/`)
- [x] Repo onboarded (labels, webhook, bot.yaml, compass template)
- [ ] Grove Worker source accessible (changes land in `grove/src/worker/`)

---

## 1.1 — D1 Schema: Users Table

**Branch:** `feat/ga-1-users-table`
**Files:** `grove/src/worker/migrations/XXXX_users.sql`

- [ ] Create D1 migration: `users` table (id, email, display_name, role, created_at, updated_at)
- [ ] Role enum: `viewer`, `operator`, `admin`
- [ ] Default role: `viewer`
- [ ] Unique constraint on email
- [ ] Apply migration to dev D1 (`wrangler d1 migrations apply`)
- [ ] Verify: `wrangler d1 execute` to confirm table exists

---

## 1.2 — D1 Schema: Agent Grants Table

**Branch:** same as 1.1
**Files:** `grove/src/worker/migrations/XXXX_agent_grants.sql`

- [ ] Create D1 migration: `agent_grants` table (agent_id, owner_id, can_delegate, created_at)
- [ ] Composite primary key: `(agent_id, owner_id)`
- [ ] Foreign key: `owner_id → users.id ON DELETE CASCADE`
- [ ] Index on `owner_id`
- [ ] Apply migration
- [ ] Verify: table exists, FK constraint works

---

## 1.3 — Seed Initial Users

**Branch:** same as 1.1
**Files:** `grove/src/worker/migrations/XXXX_seed_users.sql` or seed script

- [ ] Insert Andreas (admin role, email from CF Access)
- [ ] Insert JC (operator role) if applicable
- [ ] Insert agent grants: Andreas → luna, Andreas → other agents
- [ ] Verify: `SELECT * FROM users` returns seeded data
- [ ] Verify: `SELECT * FROM agent_grants` returns ownership mappings

---

## 1.4 — Middleware: `requireRole()`

**Branch:** `feat/ga-2-role-middleware`
**Files:** `grove/src/worker/src/auth.ts`

- [ ] Add `requireRole(minRole: Role)` middleware function
- [ ] Extract email from CF Access JWT (existing `getCfAccessEmail()`)
- [ ] Look up user in D1 by email
- [ ] Compare user.role against required role (viewer < operator < admin)
- [ ] Return 403 with `{ error: "insufficient_role", required: minRole }` if denied
- [ ] Return 401 if user not found in D1 (CF Access passed but no user record)
- [ ] Set `c.set("user", userRecord)` on Hono context for downstream use
- [ ] Audit log: log role check (pass/fail) to D1 audit_log
- [ ] Tests: role hierarchy works (admin > operator > viewer)

---

## 1.5 — Middleware: `requireAgentOwner()`

**Branch:** same as 1.4
**Files:** `grove/src/worker/src/auth.ts`

- [ ] Add `requireAgentOwner()` middleware
- [ ] Read `agentId` from route params or request body
- [ ] Check `agent_grants` table: does caller own this agent?
- [ ] Admin role bypasses ownership check
- [ ] Return 403 with `{ error: "not_agent_owner", agentId }` if denied
- [ ] Audit log: log ownership check
- [ ] Tests: operator can access own agent, cannot access others', admin can access all

---

## 1.6 — API: User Management Endpoints

**Branch:** `feat/ga-3-user-api`
**Files:** `grove/src/worker/src/router.ts` (or new `src/auth-routes.ts`)

- [ ] `GET /api/auth/me` — return current user profile (from CF Access email → D1 lookup)
- [ ] `GET /api/auth/users` — list all users (admin only)
- [ ] `PUT /api/auth/users/:id/role` — change user role (admin only)
- [ ] `GET /api/auth/agents` — list agents the caller owns (or all for admin)
- [ ] `POST /api/auth/agents/:id/grant` — grant agent access to another user (admin only)
- [ ] `DELETE /api/auth/agents/:id/grant/:userId` — revoke agent access (admin only)
- [ ] All endpoints behind `requireRole()` middleware
- [ ] All mutations logged to audit_log

---

## 1.7 — Wire Existing Routes to Role Middleware

**Branch:** same as 1.6
**Files:** `grove/src/worker/src/router.ts`

- [ ] Identify all write endpoints currently using `requireAdmin()` or `requireApiKey()`
- [ ] Replace `requireAdmin()` with `requireRole("admin")` where appropriate
- [ ] Add `requireRole("operator")` to operator-level endpoints
- [ ] Keep `requireApiKey()` for bot/machine auth (service tokens)
- [ ] Ensure read endpoints remain accessible to `viewer` role
- [ ] Regression check: existing dashboard still works (viewer can read, admin can write)

---

## 1.8 — Dashboard: Auth Context

**Branch:** `feat/ga-4-dashboard-auth`
**Files:** `grove/src/dashboard/` (new auth hook or extension of `use-grove-api.ts`)

- [ ] Add `GET /api/auth/me` call on dashboard load
- [ ] Store user context (role, owned agents) in React state
- [ ] Show user identity badge in header (email, role)
- [ ] Conditionally render action buttons based on role
- [ ] Hide agent management actions for agents the user doesn't own
- [ ] Show "Insufficient permissions" message when API returns 403

---

## 1.9 — Integration Testing

**Branch:** same as 1.8

- [ ] Test: viewer can load dashboard, sees data, no action buttons
- [ ] Test: operator sees action buttons for own agents only
- [ ] Test: operator gets 403 when accessing another operator's agent
- [ ] Test: admin sees all agents, can modify roles
- [ ] Test: unauthenticated request (no CF Access JWT) → 401
- [ ] Test: authenticated but no D1 record → 401 with "user not provisioned"
- [ ] Test: bot service token still works for ingest endpoints

---

## 1.10 — Documentation & Release

- [ ] Update `grove-auth/README.md` with Phase 1 completion status
- [ ] Update `grove-auth/docs/design-auth-aaa.md` if any decisions changed during implementation
- [ ] Bump grove version (minor — new auth middleware)
- [ ] Create GitHub release with Phase 1 summary
- [ ] Update grove-auth#1 issue — tick checkboxes, add completion comment

---

## Exit Criteria

Phase 1 is done when:
1. Every dashboard API request is associated with a user identity (not just a CF Access email)
2. Write operations are gated by role (viewer cannot trigger actions)
3. Agent management operations are gated by ownership (operators cannot touch each other's agents)
4. Admin can manage all users and agents
5. Audit log captures all auth events
6. Existing bot/machine auth (API keys, service tokens) continues to work unchanged

**Next:** Phase 2 (PassKey enrollment + step-up) — tracked in grove-auth#2
