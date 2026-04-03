# Design: AAA — Authentication, Authorization, and Privileged Action Approval

**Status:** Research complete, design draft
**Scope:** Cross-stack auth for Grove ecosystem (dashboard, Worker, bot, CLI)
**Problem:** The dashboard is evolving toward triggering agent execution and approving deployments from the UI. These privileged actions need MFA and device trust — not just a session cookie.

---

## Current Auth Landscape

| Layer | Mechanism | Protects | Limitation |
|-------|-----------|----------|------------|
| CF Access | JWT (email identity) | Dashboard read endpoints | No step-up for privileged actions |
| API Keys | Bearer token in KV | Ingest/sync (bot -> worker) | Shared per-operator, not per-user |
| Admin Secret | Shared secret | Admin endpoints (DELETE, etc.) | Single shared credential, no MFA |
| Audit Log | D1 table | All auth events logged | Logging only, no enforcement |

**What's missing:**
- No per-user identity for privileged actions (admin is a shared secret)
- No MFA / step-up for dangerous operations
- No device trust ("remember this laptop")
- No approval workflow (user A requests, user B approves)

---

## Design: Layered Auth with PassKey Step-Up

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
         |  -> route-level permission checks  |
         |                                   |
         |  Layer 3: Step-Up (WebAuthn)       |
         |  -> PassKey assertion for          |
         |     privileged actions only        |
         |  -> Time-scoped elevation (5 min)  |
         +-----------------------------------+
              |              |
         D1 (structured)  KV (ephemeral)
         - users           - challenges (60s TTL)
         - credentials     - sessions (24h TTL)
         - audit_log       - elevations (5m TTL)
         - trusted_devices
```

### The Three Layers

**Layer 1 — Identity (CF Access)**
CF Access remains the perimeter. Free for 50 users. Handles IdP integration (Google, GitHub). Every request arrives with a validated JWT containing the user's email. Service tokens handle bot/CLI auth through the same gateway.

No changes needed to this layer — it already works.

**Layer 2 — Authorization (D1 user table + agent ownership)**
New. Map CF Access email -> user record with role. Route-level middleware checks role before proceeding.

```
viewer   -> read-only dashboard access
operator -> can trigger non-destructive actions (sync, digest)
             can manage their OWN agents (start, stop, review, merge)
admin    -> can trigger destructive actions (deploy, delete, agent exec)
             can manage ALL agents across operators
```

**Agent-level authorization:** Each operator owns agents they spawn. The dashboard filters agent lists by authenticated user — operators see and control only their own agents. An operator cannot start, stop, or approve actions for another operator's agents without explicit delegation or admin role. This is enforced at the API layer:

```
GET  /api/agents          → returns only agents owned by caller (unless admin)
POST /api/agents/:id/stop → 403 if caller != owner AND caller.role != admin
POST /api/agents/:id/review → 403 if caller != owner AND caller.role != admin
```

Agent ownership is tracked via an `owner_id` column on agent/session records in D1, set at spawn time from the authenticated user's ID.

**Layer 3 — Step-Up (WebAuthn/PassKeys)**
New. Privileged actions require a PassKey assertion even if the user is already logged in. The elevation uses an **activity-based sliding window** — once verified, the window extends while the user is actively performing privileged actions.

This is the "Touch ID to confirm" pattern used by GitHub (sudo mode) and Cloudflare dashboard (sensitive settings), but with UX improvements to prevent MFA fatigue during active work sessions.

**Activity-based elevation window:** Instead of a fixed 5-minute timeout that forces re-authentication even during active use, the elevation KV entry's TTL is reset on each privileged action. Rules:
- **Initial TTL:** 5 minutes (from PassKey verification)
- **Extension:** Each privileged action resets TTL to 5 minutes from now
- **Maximum cap:** 30 minutes total (from initial verification) — forces re-auth even during active sessions
- **Idle timeout:** If no privileged action for 5 minutes, elevation expires

This means: verify once with Touch ID, work actively for up to 30 minutes managing agents, reviewing PRs, approving deploys. Only re-prompted if you step away for 5+ minutes or hit the 30-minute hard cap.

```
KV key: elevation:{userId}
Value:  { verifiedAt, credentialId, lastActivityAt }
TTL:    min(300s from now, 1800s from verifiedAt)
```

---

## PassKey Flow

### Device Enrollment (one-time)

```
User clicks "Register Device" in dashboard settings
  -> Worker: generateRegistrationOptions()
     - rpId: "meta-factory.ai"
     - rpName: "Grove Dashboard"
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
User clicks "Deploy v0.16.0" (privileged action)
  -> Worker: check KV for active elevation
     - If elevation:{userId} exists and not expired -> proceed
     - If no elevation -> return 403 with { requireStepUp: true }
  -> Frontend: show "Confirm with PassKey" dialog
  -> Worker: generateAuthenticationOptions()
     - challenge stored in KV (60s TTL)
  -> Browser: navigator.credentials.get(options)
     - Touch ID prompt (~1 second)
  -> Worker: verifyAuthenticationResponse()
     - Validate signature against stored public key
     - Update sign counter (replay protection)
  -> Worker: store elevation:{userId} in KV (5 min TTL)
  -> Original action proceeds with elevation proof
```

### UX

On macOS: Touch ID dialog slides down. Finger on sensor. ~1 second. Done.
On Windows: Windows Hello prompt (fingerprint, face, or PIN).
On mobile: Face ID or fingerprint.

No codes. No authenticator apps. No SMS. Just biometric confirmation.

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

-- Agent ownership (which operator owns which agents)
CREATE TABLE agent_grants (
  agent_id TEXT NOT NULL,          -- agent identifier (e.g., "luna", "ivy")
  owner_id TEXT NOT NULL,          -- user ID of the owning operator
  can_delegate INTEGER DEFAULT 0,  -- can this owner grant access to others?
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (agent_id, owner_id),
  FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_agent_owner ON agent_grants(owner_id);

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

-- Extends existing audit_log with step-up events
-- (audit_log table already exists)
```

**KV keys:**

| Key pattern | Value | TTL | Purpose |
|-------------|-------|-----|---------|
| `challenge:{id}` | `{challenge, userId, type}` | 60s | WebAuthn registration/auth challenge |
| `elevation:{userId}` | `{verifiedAt, credentialId, lastActivityAt}` | 300s (sliding, 1800s hard cap) | Step-up elevation window |

---

## Privileged Actions (what requires step-up)

| Action | Role required | Ownership check | Step-up required |
|--------|--------------|----------------|-----------------|
| View dashboard | viewer | No | No |
| Trigger sync | operator | No | No |
| Run digest | operator | No | No |
| **View own agents** | operator | **Yes** (own only) | No |
| **Start agent session** | operator | **Yes** (own only) | **Yes** |
| **Stop agent session** | operator | **Yes** (own only) | **Yes** |
| **Trigger agent review** | operator | **Yes** (own only) | **Yes** |
| **Approve agent PR merge** | operator | **Yes** (own only) | **Yes** |
| View all agents | admin | No (sees all) | No |
| Trigger agent execution | admin | No (any agent) | **Yes** |
| Approve deployment | admin | No | **Yes** |
| Delete repo from D1 | admin | No | **Yes** |
| Modify user roles | admin | No | **Yes** |
| Regenerate API keys | admin | No | **Yes** |

The classification: if an action has side effects that are hard to reverse or affect shared systems, it requires step-up. Agent management actions always require step-up because they trigger code execution on real repositories. Ownership checks ensure operators can only manage their own agents — admins bypass ownership checks.

---

## Primary Use Case: Agent Lifecycle Management from UI

This is the concrete scenario driving the auth system. The Grove dashboard will enable managing the full agent lifecycle from the browser — triggering implementation, reviews, feedback loops, and merges without touching a terminal.

### The Flow

```
1. Operator opens Grove dashboard → sees agent session completed implementation
2. Operator clicks "Review" on the agent card
   → Auth: CF Access (identity) + role check (operator) + ownership check (own agent)
   → Step-up: PassKey verification (Touch ID)
   → Elevation window starts (5min sliding, 30min cap)
3. Dashboard triggers a SEPARATE review agent
   → Review agent runs arc-skill-code-review against the PR
   → Results surface in the dashboard inbox (G-900)
4. Operator reads review, clicks "Apply Feedback"
   → Auth: ownership check + elevation still active (no re-auth, sliding window)
   → Implementation agent resumes with review feedback injected
5. Agent updates PR, pushes changes
6. Operator clicks "Re-Review"
   → Auth: elevation still active (still within sliding window)
   → New review cycle runs
7. Review passes. Operator clicks "Merge"
   → Auth: elevation still active OR re-prompt if window expired
   → PR merged via GitHub API
8. Post-merge: versioning SOP triggered automatically
```

### Why Auth is Required

Each step in this flow triggers real code execution on real repositories. Without auth:
- Anyone with dashboard access could start agent sessions (resource cost, code changes)
- One operator could interfere with another's agent workflow
- Merges could happen without verified identity (audit trail broken)
- No distinction between "looking at the dashboard" and "executing actions"

### Grove Dashboard Evolution

The Grove dashboard is evolving from a monitoring wall into an operations center. The current dashboard (G-200 series) is read-only — it shows agent state but can't trigger actions. The next phase adds:
- Agent action buttons (start, stop, review, merge)
- Exception-based inbox (G-900)
- Approval gates (G-902)
- Agent lifecycle cards with state machine visualization

Auth is a **prerequisite** for these UI capabilities — action buttons are pointless without verified identity and authorization. Implementation order: grove-auth Phase 1 → Grove dashboard actions → grove-auth Phase 2 (PassKeys for step-up).

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
    type: string;       // "deploy" | "agent-session" | "delete-repo"
    target: string;     // "grove:v0.16.0" | "claude-session:thread-123"
    params: Record<string, string>;
  };

  // How it was approved
  authz: {
    method: "webauthn";
    credential_id: string;
  };
}
```

Signed with HMAC-SHA256 via Web Crypto API (`crypto.subtle`). The `jti` is stored in KV with matching TTL — on use, check-and-delete for one-time semantics.

**Two tiers:**
- **Elevation window** (Phase 2): sudo mode, 5 min sliding (30 min hard cap), covers multiple actions. Good enough for most operations.
- **Action tokens** (Phase 3): per-action signed JWT, single-use. For agent execution and deployments.

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
| Trigger agent session | Step-up | **Yes** |
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

### rpId Configuration

```typescript
const RP_ID = "meta-factory.ai";
const RP_NAME = "metafactory";
const EXPECTED_ORIGIN = "https://grove.meta-factory.ai";
```

Setting rpId to `meta-factory.ai` (the registrable domain) means passkeys work across all subdomains — `grove.meta-factory.ai`, `miner.meta-factory.ai`, etc. One enrollment covers the whole ecosystem.

---

## Cross-Stack Usage

PassKeys enrolled via the Grove dashboard can be verified by any Worker on `*.meta-factory.ai`:

| Surface | Auth flow |
|---------|-----------|
| **Grove dashboard** (browser) | CF Access JWT + PassKey step-up for privileged actions |
| **Miner dashboard** (browser) | Same CF Access + same PassKey (shared rpId) |
| **grove-bot** (Discord) | Service token. No PassKey (Discord is the trust boundary) |
| **CLI** (terminal) | Service token or API key. PassKey possible via browser redirect flow |
| **Agent execution** | Triggered by privileged action in dashboard — requires PassKey proof |

---

## Security Properties

1. **Phishing resistant** — PassKeys are bound to rpId. A phishing site on a different domain cannot trigger the credential.
2. **Replay resistant** — Sign counter increments on each use. Counter decrease = cloned credential = reject.
3. **Device-bound** — Private key never leaves the authenticator (Secure Enclave/TPM). Cannot be exported or intercepted.
4. **Activity-scoped elevation** — sliding 5-minute window (30-minute hard cap) prevents session-hijacking from escalating while avoiding MFA fatigue during active work.
5. **Audit trail** — Every step-up event logged to D1 with userId, credentialId, action, timestamp, IP.

---

## Recovery

For a 5-10 person team:
- **Lost device:** User logs in via CF Access (Google/GitHub), re-enrolls a new PassKey from their new device. Old credential can be revoked by admin.
- **All devices lost:** Admin removes user's credentials from D1, user re-enrolls after CF Access login.
- **Admin lockout:** Seed a break-glass admin credential at initial setup (hardware key stored securely).

---

## Implementation Phases

### Phase 1: User table + role-based authorization + agent ownership
- D1 migration: `users` table + `agent_grants` table
- Middleware: `requireRole("operator")` that reads CF Access JWT email → D1 user lookup → role check
- Middleware: `requireAgentOwner(agentId)` that checks caller owns the agent (or is admin)
- Seed initial users (team emails + roles + agent assignments)
- Agent management API endpoints with ownership enforcement
- No PassKeys yet — just role + ownership enforcement
- **Prerequisite for:** Grove dashboard actions (action buttons need auth API to call)

### Phase 2: PassKey enrollment + step-up with sliding elevation
- D1 migration: `passkey_credentials` table
- Install `@simplewebauthn/server` + `@simplewebauthn/browser`
- Worker routes: `/auth/passkey/register`, `/auth/passkey/verify`
- Dashboard: "Register Device" in settings, step-up dialog on privileged actions
- KV: challenge storage (60s TTL) + elevation storage (5min sliding, 30min hard cap)
- Activity-based elevation extension: reset TTL on each privileged action
- **Enables:** Agent lifecycle management from dashboard (start → review → merge flow)

### Phase 3: Action tokens + cross-ecosystem + approval workflows
- Per-action signed JWTs for highest-stakes operations
- Share passkey verification across miner-server Worker
- Add approval flows: user A requests action, user B (admin) approves with PassKey
- Discord integration: bot posts approval request, admin approves via dashboard
- Agent delegation: operator grants another operator temporary access to their agents

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

1. ~~**Elevation window duration**~~ — **Resolved:** Activity-based sliding window. 5-minute idle timeout, 30-minute hard cap. Extends while actively working.
2. **Multiple passkeys per user** — allow unlimited? Cap at 5? UI for managing enrolled devices?
3. **Synced vs device-bound passkeys** — synced (iCloud Keychain) is more convenient but less secure. Do we enforce device-bound for admin role?
4. **Bot-initiated privileged actions** — if the bot needs to do something privileged (e.g., emergency deploy), how does it authenticate? Separate service token with admin scope?
5. **Better Auth vs surgical SimpleWebAuthn** — Better Auth v1.5 has native D1 + passkey support. More batteries-included but heavier. Worth evaluating for Phase 2.
6. **Agent delegation model** — when an operator is on leave, how do they delegate agent access? Temporary grant with expiry? Or always route through admin?
7. **Grove dashboard sequencing** — Phase 1 auth is a prerequisite for dashboard actions, but the action UI needs auth to be useful. Ship auth API first, then UI, or develop in parallel?
8. **Review agent identity** — when operator triggers a review from UI, the review agent runs under grove-bot's service token. Should it inherit the operator's identity for audit trail, or is "triggered by operator X" sufficient?
