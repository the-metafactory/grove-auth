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

**Layer 2 — Authorization (D1 user table)**
New. Map CF Access email -> user record with role. Route-level middleware checks role before proceeding.

```
viewer   -> read-only dashboard access
operator -> can trigger non-destructive actions (sync, digest)
admin    -> can trigger destructive actions (deploy, delete, agent exec)
```

**Layer 3 — Step-Up (WebAuthn/PassKeys)**
New. Privileged actions require a PassKey assertion even if the user is already logged in. The elevation is time-scoped — once verified, the user can perform privileged actions for 5 minutes without re-prompting.

This is the "Touch ID to confirm" pattern used by GitHub (sudo mode) and Cloudflare dashboard (sensitive settings).

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
| `elevation:{userId}` | `{verifiedAt, credentialId}` | 300s | Step-up elevation window |

---

## Privileged Actions (what requires step-up)

| Action | Role required | Step-up required |
|--------|--------------|-----------------|
| View dashboard | viewer | No |
| Trigger sync | operator | No |
| Run digest | operator | No |
| Trigger agent execution | admin | **Yes** |
| Approve deployment | admin | **Yes** |
| Delete repo from D1 | admin | **Yes** |
| Modify user roles | admin | **Yes** |
| Regenerate API keys | admin | **Yes** |

The classification: if an action has side effects that are hard to reverse or affect shared systems, it requires step-up.

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
- **Elevation window** (Phase 2): sudo mode, 5 min, covers multiple actions. Good enough for most operations.
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
4. **Time-scoped elevation** — 5-minute window prevents session-hijacking from escalating to privileged access without biometric.
5. **Audit trail** — Every step-up event logged to D1 with userId, credentialId, action, timestamp, IP.

---

## Recovery

For a 5-10 person team:
- **Lost device:** User logs in via CF Access (Google/GitHub), re-enrolls a new PassKey from their new device. Old credential can be revoked by admin.
- **All devices lost:** Admin removes user's credentials from D1, user re-enrolls after CF Access login.
- **Admin lockout:** Seed a break-glass admin credential at initial setup (hardware key stored securely).

---

## Implementation Phases

### Phase 1: User table + role-based authorization
- D1 migration: `users` table
- Middleware: `requireRole("admin")` that reads CF Access JWT email -> D1 user lookup -> role check
- Seed initial users (team emails + roles)
- No PassKeys yet — just role enforcement

### Phase 2: PassKey enrollment + step-up
- D1 migration: `passkey_credentials` table
- Install `@simplewebauthn/server` + `@simplewebauthn/browser`
- Worker routes: `/auth/passkey/register`, `/auth/passkey/verify`
- Dashboard: "Register Device" in settings, step-up dialog on privileged actions
- KV: challenge and elevation storage

### Phase 3: Cross-ecosystem + approval workflows
- Share passkey verification across miner-server Worker
- Add approval flows: user A requests action, user B (admin) approves with PassKey
- Discord integration: bot posts approval request, admin approves via dashboard

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

1. **Elevation window duration** — 5 minutes is a guess. Too short = MFA fatigue. Too long = security gap. Should it be configurable per-action?
2. **Multiple passkeys per user** — allow unlimited? Cap at 5? UI for managing enrolled devices?
3. **Synced vs device-bound passkeys** — synced (iCloud Keychain) is more convenient but less secure. Do we enforce device-bound for admin role?
4. **Bot-initiated privileged actions** — if the bot needs to do something privileged (e.g., emergency deploy), how does it authenticate? Separate service token with admin scope?
5. **Better Auth vs surgical SimpleWebAuthn** — Better Auth v1.5 has native D1 + passkey support. More batteries-included but heavier. Worth evaluating for Phase 2.
