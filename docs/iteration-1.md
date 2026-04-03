# Iteration Plan — Phase 1: Users, Agents, Roles, and Delegation

**Tracking:** the-metafactory/grove-auth#1
**Design:** `docs/design-auth-aaa.md` (v2)
**Goal:** Ship the authorization foundation — user identity, roles, agent registry with pet/cattle classes, ownership, and delegation — so the grove dashboard can add action buttons and `admin.meta-factory.ai` can manage users and grants.

---

## Prerequisites

- [x] Design doc complete (`docs/design-auth-aaa.md` v2)
- [x] Research complete (3 research docs in `docs/research/`)
- [x] Repo onboarded (labels, webhook, bot.yaml, compass template)
- [ ] Grove Worker source accessible (auth changes land in `grove/src/worker/`)

---

## 1.1 — D1 Schema: Users + Agents + Grants

**Branch:** `feat/ga-1-auth-schema`
**Files:** `grove/src/worker/migrations/XXXX_auth_tables.sql`

- [ ] Create `users` table (id, email, display_name, role, created_at, updated_at)
- [ ] Create `agents` table (id, display_name, owner_id, class, backend, spawn_profile, created_at)
- [ ] Create `agent_grants` table (id, agent_id, owner_id, grantee_id, scope, requires_stepup, expires_at, created_at, revoked_at)
- [ ] Indexes: `idx_agent_owner`, `idx_grant_grantee`, `idx_grant_agent`
- [ ] Foreign keys with `ON DELETE CASCADE`
- [ ] Apply migration to dev D1 (`wrangler d1 migrations apply`)
- [ ] Verify: all three tables exist, FK constraints work

---

## 1.2 — Seed Initial Data

**Branch:** same as 1.1

- [ ] Seed users: Andreas (admin), JC (operator) — emails from CF Access
- [ ] Seed agents: luna (pet, local, owner: Andreas)
- [ ] Verify: `SELECT * FROM users` returns seeded data
- [ ] Verify: `SELECT * FROM agents` returns agent registry
- [ ] Verify: foreign key from agents.owner_id → users.id works

---

## 1.3 — Middleware: `requireRole()`

**Branch:** `feat/ga-2-auth-middleware`
**Files:** `grove/src/worker/src/auth.ts`

- [ ] Add `requireRole(minRole: Role)` middleware function
- [ ] Extract email from CF Access JWT (existing `getCfAccessEmail()`)
- [ ] Look up user in D1 by email
- [ ] Compare user.role against required role (viewer < operator < admin)
- [ ] Return 403 with `{ error: "insufficient_role", required: minRole }` if denied
- [ ] Return 401 if user not found in D1 (CF Access passed but no user record)
- [ ] Set `c.set("user", userRecord)` on Hono context for downstream use
- [ ] Audit log: role check (pass/fail)
- [ ] Tests: role hierarchy (admin > operator > viewer)

---

## 1.4 — Middleware: `requireAgentAccess()`

**Branch:** same as 1.3
**Files:** `grove/src/worker/src/auth.ts`

- [ ] Add `requireAgentAccess(scope: 'read' | 'review' | 'control')` middleware
- [ ] Read `agentId` from route params
- [ ] Resolution order:
  1. Is caller the agent owner? → full access
  2. Does caller have an active grant with sufficient scope? (not revoked, not expired)
  3. Is caller admin? → bypass ownership
  4. Is agent class `cattle`? → any operator can access
- [ ] Return 403 with `{ error: "no_agent_access", agentId, available_scope }` if denied
- [ ] Audit log: access check with resolution path (owner/grant/admin/cattle)
- [ ] Tests: owner access, grant scopes (read < review < control), expired grant, revoked grant, admin bypass, cattle open access

---

## 1.5 — API: Auth Endpoints

**Branch:** `feat/ga-3-auth-api`
**Files:** `grove/src/worker/src/router.ts` or new `src/auth-routes.ts`

**Identity:**
- [ ] `GET /api/auth/me` — current user profile + owned agents + active grants (received and given)

**User management (admin only):**
- [ ] `GET /api/auth/users` — list all users
- [ ] `PUT /api/auth/users/:id/role` — change user role

**Agent registry:**
- [ ] `GET /api/auth/agents` — list agents filtered by caller context:
  - Operators: own agents + delegated agents + cattle (with relationship badges)
  - Admin: all agents
- [ ] `GET /api/auth/agents/:id` — agent detail with ownership + grant info

**Delegation:**
- [ ] `POST /api/auth/agents/:id/grants` — create grant (owner or admin only)
  - Body: `{ grantee_id, scope, requires_stepup, expires_at }`
- [ ] `GET /api/auth/agents/:id/grants` — list grants for an agent
- [ ] `DELETE /api/auth/grants/:id` — revoke grant (sets revoked_at, retains for audit)
- [ ] `POST /api/auth/agents/:id/request-access` — request access (notifies owner)

All endpoints behind `requireRole()`. All mutations logged to audit_log.

---

## 1.6 — Wire Existing Routes to Role Middleware

**Branch:** same as 1.5
**Files:** `grove/src/worker/src/router.ts`

- [ ] Identify all write endpoints currently using `requireAdmin()` or `requireApiKey()`
- [ ] Replace `requireAdmin()` with `requireRole("admin")` where appropriate
- [ ] Add `requireRole("operator")` to operator-level endpoints
- [ ] Keep `requireApiKey()` for bot/machine auth (service tokens)
- [ ] Ensure read endpoints remain accessible to `viewer` role
- [ ] Regression check: existing dashboard still loads, bot sync still works

---

## 1.7 — Dashboard: Auth Context + Agent Visibility

**Branch:** `feat/ga-4-dashboard-auth`
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

**Branch:** same as 1.7

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
