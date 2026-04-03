# Design: AAA — Authentication, Authorization, and Privileged Action Approval

**Status:** Research complete, design draft v2
**Scope:** Cross-stack auth for the metafactory ecosystem (dashboard, Worker, bot, CLI, spawn)
**Problem:** The grove dashboard is evolving from a monitoring wall into an operations center. Operators will manage agent lifecycles (review, continue, merge) from the browser. These actions need identity, authorization, agent-level access control, and MFA — not just a session cookie.

---

## Current Auth Landscape

| Layer | Mechanism | Protects | Limitation |
|-------|-----------|----------|------------|
| CF Access | JWT (email identity) | Dashboard read endpoints | No step-up for privileged actions |
| API Keys | Bearer token in KV | Ingest/sync (bot -> worker) | Shared per-operator, not per-user |
| Admin Secret | Shared secret | Admin endpoints (DELETE, etc.) | Single shared credential, no MFA |
| Audit Log | D1 table | All auth events logged | Logging only, no enforcement |
| Discord roles | bot.yaml role-resolver | Bot tool/dir restrictions | Discord-only, not dashboard |

**What's missing:**
- No per-user identity for privileged actions (admin is a shared secret)
- No MFA / step-up for dangerous operations
- No device trust ("remember this laptop")
- No agent-level access control (who can manage which agents)
- No delegation model (operator A granting operator B access to their agents)
- No parity between Discord access model and dashboard access model
- No approval workflow (user A requests, user B approves)

---

## Design: Layered Auth with Agent-Scoped Access

### Architecture Overview

```
                    CF Access (perimeter)
                         |
                    Identity: email
                         |
              +----------+-----------+
              |                      |
         Human (browser)       Machine (bot/CLI)
         CF_Authorization      CF-Access-Client-Id
         cookie (JWT)          CF-Access-Client-Secret
              |                      |
              v                      v
         +-----------------------------------+
         |         Grove Worker (Hono)        |
         |                                   |
         |  Layer 1: Identity (CF Access JWT) |
         |  -> email, validated via certs     |
         |                                   |
         |  Layer 2: Authorization (D1)       |
         |  -> user.role: viewer|operator|admin|
         |  -> agent ownership + delegation   |
         |  -> agent class (pet vs cattle)    |
         |                                   |
         |  Layer 3: Step-Up (WebAuthn)       |
         |  -> PassKey for privileged actions  |
         |  -> Only on agents where allowed   |
         |  -> Activity-based sliding window  |
         +-----------------------------------+
              |              |
         D1 (structured)  KV (ephemeral)
         - users           - challenges (60s TTL)
         - agents          - elevations (sliding)
         - agent_grants    - sessions (24h TTL)
         - credentials
         - audit_log
```

### The Three Layers

**Layer 1 — Identity (CF Access)**
CF Access remains the perimeter. Free for 50 users. Handles IdP integration (Google, GitHub). Every request arrives with a validated JWT containing the user's email. Service tokens handle bot/CLI auth through the same gateway.

No changes needed to this layer — it already works.

**Layer 2 — Authorization (D1 user table + agent ownership + delegation)**
Map CF Access email → user record with role. Route-level middleware checks role before proceeding.

```
viewer   -> read-only dashboard access, can see all agents in the network
operator -> can trigger non-destructive actions (sync, digest)
             can manage their OWN pet agents (review, continue, stop, merge)
             can use cattle agents (workflow-triggered, no ownership needed)
             can receive delegated access to other operators' pet agents
admin    -> can trigger destructive actions (deploy, delete, agent exec)
             can manage ALL agents across operators
             can manage users and roles (via admin.meta-factory.ai)
```

**Agent-level authorization** has two dimensions: **ownership** and **agent class**.

**Layer 3 — Step-Up (WebAuthn/PassKeys)**
Privileged actions require a PassKey assertion — but **not universally**. Step-up is contextual:

- **Own pet agents:** Step-up required for destructive actions (start session, stop, merge)
- **Delegated pet agents with `requires_stepup: true`:** Step-up required for all actions within grant scope
- **Delegated pet agents with `requires_stepup: false`:** No step-up (the granting operator made that trust decision)
- **Cattle agents:** No step-up (ephemeral, sandboxed, spawned by workflows)
- **Admin actions:** Step-up always required (user/role management, destructive operations)

The elevation uses an **activity-based sliding window** — once verified, the window extends while the user is actively performing privileged actions. Rules:
- **Initial TTL:** 5 minutes (from PassKey verification)
- **Extension:** Each privileged action resets TTL to 5 minutes from now
- **Maximum cap:** 30 minutes total (from initial verification) — forces re-auth even during active sessions
- **Idle timeout:** If no privileged action for 5 minutes, elevation expires

```
KV key: elevation:{userId}
Value:  { verifiedAt, credentialId, lastActivityAt }
TTL:    min(300s from now, 1800s from verifiedAt)
```

---

## Agent Classes

Agents in the metafactory ecosystem fall into two classes, driven by their spawn backend and risk profile:

| Class | Examples | Spawn Tier | Persistence | Risk | Dashboard Presence |
|-------|---------|-----------|-------------|------|--------------------|
| **Pet** | Luna, Ivy, Sage (named agents) | L0 (local), L1 (pet EC2) | Persistent — long-running, stateful | **High** — real repos, full tools, filesystem | First-class cards with action buttons |
| **Cattle** | review-worker, digest-worker | L2 (cattle EC2), L3 (CF Worker) | Ephemeral — spawned per task, terminated after | **Low** — sandboxed, scoped, disposable | Activity log entries under parent agent/workflow |

### Pet Agents

Named, persistent agents tied to an operator. They have full tool access, work on real repositories, and maintain session state. Examples: Luna working on grove, Ivy working on pulse.

**Access model:**
- Owner has full control (review, continue, stop, merge)
- Other operators see the agent (read-only) and can request delegated access
- Delegation grants scoped access (read/review/control) with optional conditions
- Step-up (PassKey) required for privileged actions on pet agents

### Cattle Agents

Ephemeral execution units spawned by workflows, not by operators directly. A code review step in the agent lifecycle spawns a cattle worker, it runs the review, results surface in the inbox, and the worker terminates.

**Access model:**
- No ownership — cattle agents belong to the workflow, not an operator
- Authorization is on the **triggering action** (e.g., "can this operator trigger a review on this PR?"), which traces back to their access on the pet agent or repo that owns the workflow
- No step-up needed (the workflow was already authorized when it started)
- No delegation (cattle agents aren't addressable — they're an implementation detail)

**Dashboard visibility:**
Cattle agents appear nested under the pet agent's activity, not as first-class entities:

```
MY AGENTS
  🟢 Luna (pet · local)                    [Review] [Continue] [Stop]
      └─ review-worker completed 3m ago      ✅ 4 findings, 0 critical
      └─ review-worker running               ⏳ CodeQuality lens

DELEGATED TO ME
  🟡 Ivy (JC's pet · EC2)                  [Review] [View Logs]
      scope: review | expires: 23h
      └─ review-worker completed 8m ago      ✅ passed

NETWORK (read-only)
  ⚪ Sage (JC's pet · EC2)                  [View] [Request Access]
```

### Cattle Runtime Options

Not all cattle workloads are equal. Code review with PAI's code-review skill requires a full CC session (filesystem, git, process spawning) — that's EC2 cattle, not CF Worker territory.

| Cattle Runtime | Capabilities | Use Cases | Can Run CC? |
|---------------|-------------|-----------|-------------|
| **EC2 ephemeral** (L2) | Full OS, git, CC, tools | Code review (PAI skill), implementation tasks | **Yes** |
| **CF Worker** (L3) | V8 isolate, fetch API only | Webhook processing, notification routing, light data transforms | No |
| **CF Dynamic Worker** | V8 isolate, arbitrary runtime code, 5min CPU | Claude API calls, PR diff summarization, lightweight analysis | No (API calls only, no CC) |

CF Dynamic Workers (open beta, March 2026) are an interesting middle ground — they can load arbitrary code at runtime and make Claude API calls, but they're still V8 isolates without filesystem or process spawning. Good for "call Claude with this diff" tasks, not for full multi-lens code reviews.

### Agent Class in Spawn Manifest

The agent class is declared in spawn's agent profile, which drives the auth policy:

```yaml
# spawn/profiles/luna.yaml
schema: spawn/agent/v1
name: luna
class: pet
backend: local

# spawn/profiles/review-worker.yaml
schema: spawn/agent/v1
name: review-worker
class: cattle
backend: ec2
```

---

## Agent Delegation

Operators can grant other operators access to their pet agents under controlled conditions.

### The Flow

```
1. Operator B sees "Sage" on dashboard (JC's pet agent, read-only for B)
2. B clicks "Request Access" on Sage's card
3. Request notification sent to JC (Discord DM + dashboard inbox)
4. JC reviews: "B wants access to Sage"
5. JC grants access with conditions:
   - Scope: "read" / "review" / "control"
   - Duration: "24 hours" / "until revoked" / custom
   - Step-up: "requires B's own PassKey" / "no step-up"
6. B now sees Sage in "Delegated to Me" with access badge
7. All B's actions on Sage are logged with "delegated by JC" context
```

### Implicit Delegation Trigger

Delegation can also be triggered implicitly — when Operator B tries to perform an action on an agent they don't have access to:

- B clicks [Review] on Sage → "This agent belongs to JC. You need review access. [Request Access]"
- If B already has `read` access but clicked a `review` action → "You have read access. [Request Upgrade to Review]"

This mirrors grove's existing pattern: the system tells you what you can do and offers a path to get more.

### Grant Model

```sql
CREATE TABLE agent_grants (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,            -- "luna", "sage"
  owner_id TEXT NOT NULL,            -- operator who owns the agent (grantor)
  grantee_id TEXT NOT NULL,          -- operator receiving access (recipient)
  scope TEXT NOT NULL DEFAULT 'read', -- 'read' | 'review' | 'control'
  requires_stepup INTEGER DEFAULT 1,  -- does grantee need their own PassKey?
  expires_at TEXT,                    -- null = until revoked
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at TEXT,                    -- null = active
  FOREIGN KEY (owner_id) REFERENCES users(id),
  FOREIGN KEY (grantee_id) REFERENCES users(id)
);
CREATE INDEX idx_grant_grantee ON agent_grants(grantee_id);
CREATE INDEX idx_grant_agent ON agent_grants(agent_id);
```

### Scope Levels

| Scope | Can do | Example use case |
|-------|--------|-----------------|
| `read` | View agent status, sessions, logs | "Let B see what Luna is working on" |
| `review` | Read + trigger code review on agent's PRs | "B can review Luna's work" |
| `control` | Full: start, stop, review, continue, merge | "B is covering for A while on leave" |

### Agent Class Affects Delegation Defaults

| Agent Class | Default Delegation | Rationale |
|-------------|-------------------|-----------|
| **Pet** | Restricted: requires explicit grant from owner | High risk — persistent state, real repos, full tools |
| **Cattle** | Open: any authorized operator in the network | Low risk — ephemeral, sandboxed, scoped task |

An operator doesn't need a grant to trigger a workflow that spawns cattle. They need authorization for the **action** (e.g., "review this PR"), and the cattle worker is an implementation detail of that action.

---

## Access Levels: Dashboard ↔ Discord Parity

Grove already has a context-based access model in Discord (G-300). The dashboard needs a parallel model:

| Context | Discord Equivalent | Agent Access | Tools Available | Step-up |
|---------|-------------------|-------------|-----------------|---------|
| **Dashboard (viewer)** | Guild channel (user role) | Read-only on all visible agents | View only | No |
| **Dashboard (own pet agents)** | Guild channel (operator role) | Full control on own agents | Review, continue, stop, merge | **Yes** (per agent class) |
| **Dashboard (delegated)** | N/A (new concept) | Scoped by grant conditions | Per-grant scope | Per-grant `requires_stepup` |
| **Dashboard (admin)** | Guild channel (operator role) | Full control on all agents | All actions + user management | **Yes** (always) |
| **Discord DM** | Operator DM (G-300) | Full unrestricted access to own agent | Write, Edit, Agent, Bash — everything | **Inherent** (DM is trust boundary) |

**Key insight:** DM is the highest trust tier, authenticated by Discord identity + operator ID match. The dashboard can never fully reach DM-level access because:
- Dashboard identity: CF Access email-based JWT
- DM identity: Discord platform-verified user ID + 1:1 channel isolation

**Phase 1:** Dashboard maxes at "operator" level with role + ownership + step-up. DM stays unrestricted as today — they serve different purposes. Dashboard is the "controlled operations center," DM is the "root terminal."

**Phase 2 endgame:** PassKey step-up on a trusted device is arguably equivalent to DM trust (biometric + device binding), so the gap narrows. But DM retains full tool access (Write, Edit, Bash) while dashboard operates through structured actions (review, merge) — never raw tool invocation.

---

## Admin Surface: `admin.meta-factory.ai`

User management, role assignment, and agent grant management are **ecosystem-level concerns**, not grove-specific operations. They belong in a dedicated admin interface.

### Architecture

```
admin.meta-factory.ai (CF Pages)
  ├── Users — list, create, modify roles
  ├── Agents — list all, view ownership, manage grants
  ├── Audit Log — browse all auth events
  ├── Grove — link to grove.meta-factory.ai operations dashboard
  └── Settings — ecosystem-level config (rpId, elevation caps, etc.)

grove.meta-factory.ai (CF Pages)
  ├── Agents — operational view (my agents, delegated, network)
  ├── Inbox — exception-based attention (G-900)
  ├── Activity — event timeline
  └── Blueprint — tech tree
```

**Shared backend:** Both frontends talk to the same Grove Worker API. The Worker serves both operational endpoints (`/api/agents`, `/api/sessions`) and admin endpoints (`/api/auth/users`, `/api/auth/grants`). Admin endpoints require `admin` role.

**Rationale:** Separation of concerns. An operator managing agent workflows doesn't need the user management UI cluttering their view. An admin setting up new team members doesn't need the operational dashboard.

**Implementation:** `admin.meta-factory.ai` is a separate CF Pages project, separate React app, same CF Access policy, same D1/KV backend. Simpler than grove's dashboard — mostly CRUD forms for users, roles, and grants.

---

## Privileged Actions (what requires step-up)

| Action | Role | Ownership | Agent Class | Step-up |
|--------|------|-----------|-------------|---------|
| View dashboard | viewer | — | — | No |
| View all agents (read-only) | viewer+ | — | — | No |
| Trigger sync / run digest | operator | — | — | No |
| **View own pet agent details** | operator | Own | Pet | No |
| **Review pet agent's PR** | operator | Own or delegated (`review`+) | Pet | **Per-grant config** |
| **Continue pet agent session** | operator | Own or delegated (`control`) | Pet | **Yes** |
| **Stop pet agent session** | operator | Own or delegated (`control`) | Pet | **Yes** |
| **Merge pet agent's PR** | operator | Own or delegated (`control`) | Pet | **Yes** |
| **Trigger workflow step** (spawns cattle) | operator | Own pet agent or repo access | Cattle (spawned) | **Yes** (on the trigger, not the cattle) |
| View all agents (admin) | admin | — (sees all) | — | No |
| Manage users / roles | admin | — | — | **Yes** |
| Approve deployment | admin | — | — | **Yes** |
| Delete repo from D1 | admin | — | — | **Yes** |
| Regenerate API keys | admin | — | — | **Yes** |

The principle: **step-up gates the action that has consequences, not the agent class.** Triggering a review (which spawns cattle) requires step-up because the operator is committing to code execution on a real repo. The cattle worker itself doesn't need step-up — it's already authorized by the triggering action.

---

## Primary Use Case: Agent Lifecycle Management from UI

This is the concrete scenario driving the auth system. The grove dashboard will enable managing the full pet agent lifecycle from the browser.

### The Flow

```
1. Operator opens grove dashboard → sees Luna completed implementation
2. Operator clicks "Review" on Luna's card
   → Auth: CF Access (identity) + role (operator) + ownership (own agent)
   → Step-up: PassKey verification (Touch ID)
   → Elevation window starts (5min sliding, 30min cap)
3. Dashboard triggers review workflow
   → EC2 cattle worker spawns, runs arc-skill-code-review against the PR
   → Results surface in the dashboard inbox (G-900)
   → Cattle worker terminates, appears as nested activity under Luna
4. Operator reads review, clicks "Continue with Feedback"
   → Auth: ownership + elevation still active (no re-auth, sliding window)
   → Luna (pet agent) resumes with review feedback injected
5. Luna updates PR, pushes changes
6. Operator clicks "Re-Review"
   → Auth: elevation still active (within sliding window)
   → Another cattle review worker spawns, runs review
7. Review passes. Operator clicks "Merge"
   → Auth: elevation still active OR re-prompt if window expired
   → PR merged via GitHub API
8. Post-merge: versioning SOP triggered automatically
```

### Why Auth is Required

Each step triggers real code execution on real repositories. Without auth:
- Anyone with dashboard access could start agent sessions (resource cost, code changes)
- One operator could interfere with another's pet agent workflow
- Merges could happen without verified identity (audit trail broken)
- No distinction between "looking at the dashboard" and "executing actions"
- Cattle workers would spawn without authorization checks (compute cost, API token burn)

---

## D1 Schema

```sql
-- User identity (maps CF Access email to app-level role)
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  display_name TEXT,
  role TEXT NOT NULL DEFAULT 'viewer',  -- viewer | operator | admin
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Agent registry (pet agents only — cattle are ephemeral, not registered)
CREATE TABLE agents (
  id TEXT PRIMARY KEY,               -- "luna", "ivy", "sage"
  display_name TEXT NOT NULL,        -- "Luna"
  owner_id TEXT NOT NULL,            -- operator who owns this agent
  class TEXT NOT NULL DEFAULT 'pet', -- 'pet' | 'cattle' (cattle rarely stored)
  backend TEXT,                      -- 'local' | 'ec2' | 'worker'
  spawn_profile TEXT,                -- spawn manifest reference: "luna.yaml"
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (owner_id) REFERENCES users(id)
);
CREATE INDEX idx_agent_owner ON agents(owner_id);

-- Agent delegation grants (operator A grants operator B access)
CREATE TABLE agent_grants (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  owner_id TEXT NOT NULL,             -- grantor (must own the agent)
  grantee_id TEXT NOT NULL,           -- recipient
  scope TEXT NOT NULL DEFAULT 'read', -- 'read' | 'review' | 'control'
  requires_stepup INTEGER DEFAULT 1,  -- does grantee need PassKey?
  expires_at TEXT,                    -- null = until revoked
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at TEXT,                    -- null = active
  FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE,
  FOREIGN KEY (owner_id) REFERENCES users(id),
  FOREIGN KEY (grantee_id) REFERENCES users(id)
);
CREATE INDEX idx_grant_grantee ON agent_grants(grantee_id);
CREATE INDEX idx_grant_agent ON agent_grants(agent_id);

-- WebAuthn credentials (multiple per user — laptop, phone, hardware key)
CREATE TABLE passkey_credentials (
  credential_id TEXT PRIMARY KEY,       -- base64url credential ID
  user_id TEXT NOT NULL,
  public_key TEXT NOT NULL,             -- base64url COSE public key
  algorithm INTEGER NOT NULL DEFAULT -7, -- COSE alg: -7=ES256, -257=RS256
  sign_count INTEGER NOT NULL DEFAULT 0, -- replay protection counter
  transports TEXT,                       -- JSON array: ["internal","hybrid"]
  device_name TEXT,                      -- "Andreas's MacBook Pro"
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_passkey_user ON passkey_credentials(user_id);

-- Extends existing audit_log with auth events
-- (audit_log table already exists in grove Worker)
```

**KV keys:**

| Key pattern | Value | TTL | Purpose |
|-------------|-------|-----|---------|
| `challenge:{id}` | `{challenge, userId, type}` | 60s | WebAuthn registration/auth challenge |
| `elevation:{userId}` | `{verifiedAt, credentialId, lastActivityAt}` | 300s (sliding, 1800s hard cap) | Step-up elevation window |

---

## Integration with Spawn (SecretResolver)

grove-auth and spawn's SecretResolver are **independent layers** that intersect at the action token:

| Concern | System | What it does |
|---------|--------|-------------|
| **Human authorization** | grove-auth | "Is this person allowed to trigger this action?" |
| **Infrastructure credentials** | spawn SecretResolver + AWS SSM | "What API keys does the agent runtime need?" |

```
Human clicks "Review" on dashboard
  → grove-auth: verify identity + role + ownership + step-up
  → grove-auth: mint action token (signed JWT, act.type: "agent-review")
  → grove-bot / spawn: receives action token
  → spawn: verify action token signature (trusts grove-auth as issuer)
  → spawn: provision EC2 cattle runtime
  → spawn: SecretResolver injects CLAUDE_CODE_OAUTH_TOKEN from SSM
  → cattle agent runs code-review skill
  → results returned, cattle terminated
```

grove-auth answers **"who can do what."** Spawn's SSM answers **"with what credentials."** The action token is the handshake — grove-auth signs it, spawn verifies it before provisioning.

No changes needed to spawn's SecretResolver for grove-auth. The integration is the action token verification that spawn has planned in its Iteration 4 (S-010).

---

## PassKey Flow

### Device Enrollment (one-time)

```
User clicks "Register Device" in admin.meta-factory.ai settings
  -> Worker: generateRegistrationOptions()
     - rpId: "meta-factory.ai"
     - rpName: "metafactory"
     - challenge stored in KV (60s TTL)
  -> Browser: navigator.credentials.create(options)
     - Touch ID / Windows Hello / phone biometric
  -> Worker: verifyRegistrationResponse()
     - Validate challenge, origin, rpId
     - Store credential (publicKey, credentialId, counter) in D1
  -> "Device registered" confirmation
```

### Privileged Action Approval (each time)

```
User clicks "Review" on own pet agent (privileged action)
  -> Worker: check KV for active elevation
     - If elevation:{userId} exists and not expired -> proceed (extend TTL)
     - If no elevation -> return 403 with { requireStepUp: true }
  -> Frontend: show "Confirm with PassKey" dialog
  -> Worker: generateAuthenticationOptions()
     - challenge stored in KV (60s TTL)
  -> Browser: navigator.credentials.get(options)
     - Touch ID prompt (~1 second)
  -> Worker: verifyAuthenticationResponse()
     - Validate signature against stored public key
     - Update sign counter (replay protection)
  -> Worker: store elevation:{userId} in KV (sliding TTL)
  -> Original action proceeds with elevation proof
```

### rpId Configuration

```typescript
const RP_ID = "meta-factory.ai";
const RP_NAME = "metafactory";
const EXPECTED_ORIGINS = [
  "https://grove.meta-factory.ai",
  "https://admin.meta-factory.ai",
];
```

Setting rpId to `meta-factory.ai` (the registrable domain) means passkeys work across all subdomains. One enrollment covers grove, admin, miner, and any future ecosystem dashboard.

### UX

On macOS: Touch ID dialog slides down. Finger on sensor. ~1 second. Done.
On Windows: Windows Hello prompt (fingerprint, face, or PIN).
On mobile: Face ID or fingerprint.

No codes. No authenticator apps. No SMS. Just biometric confirmation.

---

## Action Tokens (per-action authorization)

Step-up elevation windows ("sudo mode") are convenient but coarse — they grant a time window, not per-action authorization. For the highest-value actions, mint a scoped action token after PassKey verification:

```typescript
interface ActionTokenClaims {
  // Standard JWT
  iss: "grove-worker.meta-factory.ai";
  sub: string;          // user ID
  aud: "grove-agent-executor";
  iat: number;
  exp: number;          // iat + 300 (5 min)
  jti: string;          // UUIDv4 nonce (stored in KV for replay prevention)

  // What was approved
  act: {
    type: string;       // "agent-review" | "agent-merge" | "deploy" | "delete-repo"
    target: string;     // "luna:grove#48" | "grove:v0.16.0"
    agent_class: string; // "pet" | "cattle"
    params: Record<string, string>;
  };

  // How it was approved
  authz: {
    method: "webauthn" | "delegation";
    credential_id?: string;   // for webauthn
    grant_id?: string;        // for delegated access
    delegated_by?: string;    // owner who granted access
  };
}
```

Signed with HMAC-SHA256 via Web Crypto API (`crypto.subtle`). The `jti` is stored in KV with matching TTL — on use, check-and-delete for one-time semantics.

**Two tiers:**
- **Elevation window** (Phase 2): sudo mode, 5 min sliding (30 min hard cap), covers multiple actions. Good enough for most operations.
- **Action tokens** (Phase 3): per-action signed JWT, single-use. For agent execution and deployments. Consumed by spawn to authorize provisioning.

---

## Discord Approval Flow (Phase 3)

For sensitive actions, add human-in-the-loop approval via Discord (Atlantis-style):

```
1. Admin clicks "Deploy v0.16.0" in dashboard
2. Dashboard calls Worker with PassKey step-up
3. Worker posts to Discord #deployments:
   "Deploy Grove v0.16.0 requested by @andreas"
   [Approve] [Reject] buttons
4. Different team member clicks [Approve]
5. Bot verifies: approver != requester, approver has admin role
6. Bot calls Worker with approval context
7. Worker mints action token, execution proceeds
8. Result posted back to Discord thread
```

**Rules:**
- Requester cannot approve their own action (two-person rule)
- Approval expires after 15 minutes
- Both request and approval are logged to D1 audit_log
- The Discord thread serves as an audit trail the team already reads

This is optional per-action — not every privileged action needs team approval. Configure which actions require it:

| Action | Step-up only | Team approval |
|--------|-------------|---------------|
| Delete repo | Step-up | No |
| Modify user roles | Step-up | No |
| Trigger pet agent session | Step-up | **Yes** |
| Production deploy | Step-up | **Yes** |

---

## Implementation Stack

| Concern | Library/Service | Why |
|---------|----------------|-----|
| Perimeter auth | CF Access (existing) | Free, battle-tested, handles IdP |
| Machine auth | CF Access service tokens (existing) | Same JWT format as human auth |
| WebAuthn ceremony | `@simplewebauthn/server` | Most popular, TypeScript-first, Workers-compatible |
| WebAuthn browser | `@simplewebauthn/browser` | Companion to server package |
| JWT validation | `hono/jwt` or `@hono/cloudflare-access` | Already in our stack |
| Credential storage | D1 (existing binding) | Structured, relational, consistent |
| Challenge/session cache | KV (existing binding: GROVE_KEYS) | Fast, ephemeral, TTL support |
| Rate limiting | CF WAF Advanced Rate Limiting | No code needed for brute-force protection |
| Audit logging | D1 audit_log (existing) | Already in place |
| Action token verification | spawn (Iteration 4) | Validates JWT before provisioning |

---

## Cross-Stack Usage

PassKeys enrolled via `admin.meta-factory.ai` can be verified by any Worker on `*.meta-factory.ai`:

| Surface | Auth flow |
|---------|-----------|
| **grove dashboard** (browser) | CF Access JWT + role + ownership + step-up for privileged actions |
| **admin dashboard** (browser) | CF Access JWT + admin role + step-up for user management |
| **miner dashboard** (browser) | Same CF Access + same PassKey (shared rpId) |
| **grove-bot** (Discord DM) | Discord identity. No PassKey — DM is the trust boundary. Full tool access. |
| **grove-bot** (Discord guild) | Discord identity + role-resolver. Restricted tools/dirs per role. |
| **CLI** (terminal) | Service token or API key. PassKey possible via browser redirect flow |
| **spawn** (agent provisioning) | Action token verification — signed by grove-auth, verified by spawn |

---

## Security Properties

1. **Phishing resistant** — PassKeys are bound to rpId. A phishing site on a different domain cannot trigger the credential.
2. **Replay resistant** — Sign counter increments on each use. Counter decrease = cloned credential = reject.
3. **Device-bound** — Private key never leaves the authenticator (Secure Enclave/TPM). Cannot be exported or intercepted.
4. **Activity-scoped elevation** — sliding 5-minute window (30-minute hard cap) prevents session-hijacking from escalating while avoiding MFA fatigue during active work.
5. **Agent-scoped authorization** — operators control only their own pet agents. Delegation is explicit, scoped, audited.
6. **Class-aware policy** — pet agents require ownership + step-up. Cattle agents are authorized by the triggering action, not directly.
7. **Audit trail** — Every step-up event, delegation grant, and agent action logged to D1 with userId, agentId, action, timestamp, IP.

---

## Recovery

For a 5-10 person team:
- **Lost device:** User logs in via CF Access (Google/GitHub), re-enrolls a new PassKey from their new device. Old credential can be revoked by admin.
- **All devices lost:** Admin removes user's credentials from D1, user re-enrolls after CF Access login.
- **Admin lockout:** Seed a break-glass admin credential at initial setup (hardware key stored securely).
- **Delegation cleanup:** Expired grants are automatically inactive (query filters by `expires_at`). Revoked grants retained for audit trail.

---

## Implementation Phases

### Phase 1: User table + role-based authorization + agent registry + delegation model
- D1 migration: `users`, `agents`, `agent_grants` tables
- Middleware: `requireRole("operator")` — CF Access JWT email → D1 user lookup → role check
- Middleware: `requireAgentAccess(agentId, scope)` — ownership OR active grant OR admin
- Seed initial users (team emails + roles) and agents (luna, etc.)
- Auth API: `/api/auth/me`, `/api/auth/users`, `/api/auth/agents`, `/api/auth/grants`
- Agent delegation: request, grant, revoke, list grants
- No PassKeys yet — just role + ownership + delegation enforcement
- **Prerequisite for:** grove dashboard action buttons, admin.meta-factory.ai

### Phase 2: PassKey enrollment + step-up with sliding elevation
- D1 migration: `passkey_credentials` table
- Install `@simplewebauthn/server` + `@simplewebauthn/browser`
- Worker routes: `/auth/passkey/register`, `/auth/passkey/verify`
- Dashboard: "Register Device" in settings, step-up dialog on privileged actions
- KV: challenge storage (60s TTL) + elevation storage (5min sliding, 30min hard cap)
- Contextual step-up: enforce based on agent class + grant config
- `admin.meta-factory.ai`: user/agent/grant management UI
- **Enables:** Full agent lifecycle management from dashboard

### Phase 3: Action tokens + cross-ecosystem + approval workflows
- Per-action signed JWTs for highest-stakes operations
- Spawn integration: action token verification before provisioning (spawn S-010)
- Share passkey verification across miner-server Worker
- Discord approval flows (two-person rule for deploys and agent sessions)
- Cross-operator delegation workflows with notification routing

---

## Reference Implementations

| Project | Relevance |
|---------|-----------|
| [FabioDiCeglie/Passkey](https://github.com/FabioDiCeglie/Passkey) | React + Hono + CF Workers — closest to our stack |
| [nealfennimore/passkeys](https://github.com/nealfennimore/passkeys) | D1 + KV split pattern |
| [horiuchi/passkey-cloudflare](https://github.com/horiuchi/passkey-cloudflare) | Remix + D1 + KV + drizzle + SimpleWebAuthn |
| [@passwordless-id/webauthn](https://webauthn.passwordless.id/) | Zero-dep alternative to SimpleWebAuthn |

---

## Open Questions

1. ~~**Elevation window duration**~~ — **Resolved:** Activity-based sliding window. 5-minute idle timeout, 30-minute hard cap.
2. **Multiple passkeys per user** — allow unlimited? Cap at 5? UI for managing enrolled devices?
3. **Synced vs device-bound passkeys** — synced (iCloud Keychain) is more convenient but less secure. Enforce device-bound for admin role?
4. **Bot-initiated privileged actions** — if the bot needs to do something privileged (e.g., emergency deploy), how does it authenticate? Separate service token with admin scope?
5. **Better Auth vs surgical SimpleWebAuthn** — Better Auth v1.5 has native D1 + passkey support. More batteries-included but heavier. Worth evaluating for Phase 2.
6. ~~**Agent delegation model**~~ — **Resolved:** Scoped grants with read/review/control, optional step-up, optional expiry. Owner-initiated.
7. **CF Dynamic Workers as cattle runtime** — worth adding as a spawn backend tier for lightweight Claude API tasks? Or premature?
8. **Review agent identity** — when operator triggers a review from UI, the cattle review agent runs under spawn's service credentials. Audit trail records "triggered by operator X" — is that sufficient, or should the action token propagate the operator's identity into the cattle session?
9. **Admin dashboard scope** — should `admin.meta-factory.ai` manage only auth concerns (users, roles, grants), or also ecosystem-level config (webhook secrets, Worker settings, repo registry)?
