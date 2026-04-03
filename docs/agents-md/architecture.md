## Architecture

grove-auth provides three-layer authentication and authorization for the metafactory ecosystem, with agent-scoped access control and cross-operator delegation.

- **Layer 1 — Identity (CF Access):** Cloudflare Access provides perimeter authentication. Users log in via Google/GitHub IdP. Workers receive signed JWTs with email identity. Service tokens handle bot/CLI machine auth.
- **Layer 2 — Authorization (D1 user table + agent ownership + delegation):** Maps CF Access email to app-level roles (`viewer`, `operator`, `admin`). Operators own **pet agents** (named, persistent) and can delegate scoped access to other operators. **Cattle agents** (ephemeral, workflow-triggered) are open to any authorized operator. Route-level middleware enforces role + ownership + grant checks.
- **Layer 3 — Step-Up (WebAuthn/PassKeys):** Privileged actions on pet agents require biometric verification via PassKeys. Activity-based sliding elevation window (5 min idle, 30 min hard cap). Step-up is contextual — only on agents/actions where the operator is allowed to elevate. Per-action signed JWTs for highest-stakes operations.

### Agent Classes

- **Pet agents** (Luna, Ivy, Sage): Named, persistent, full tool access, ownership-gated. Require explicit delegation for cross-operator access.
- **Cattle agents** (review-worker, etc.): Ephemeral, spawned by workflows, sandboxed. Authorization is on the triggering action, not the cattle instance.

### Key Components (planned)

- `src/middleware/` — Hono middleware: `requireRole()`, `requireAgentAccess(scope)`, `requireStepUp()`, `requireActionToken()`
- `src/webauthn/` — PassKey registration and assertion verification (SimpleWebAuthn)
- `src/tokens/` — Scoped action token minting and verification (Web Crypto API)
- `src/schema/` — D1 migration scripts for users, agents, agent_grants, passkey_credentials tables

### Integration Points

- **Grove Worker** — imports middleware and WebAuthn handlers
- **Grove dashboard** (`grove.meta-factory.ai`) — agent lifecycle management with ownership-scoped action buttons
- **Admin dashboard** (`admin.meta-factory.ai`) — user/role/agent/grant management
- **Miner Server Worker** — same middleware, shared rpId (`meta-factory.ai`)
- **Spawn** — action token verification before agent provisioning (grove-auth signs, spawn verifies)
- **Dashboard SPA** — `@simplewebauthn/browser` for PassKey ceremonies
- **Discord bot** — approval flow buttons for team-gated actions; DM remains highest trust tier

### Design Docs

- `docs/design-auth-aaa.md` — Full design specification (v2: agent classes, delegation, admin surface, spawn integration)
- `docs/iteration-1.md` — Phase 1 iteration plan with checkboxes
- `docs/research/` — Research findings from PassKeys, OAuth, CF Workers auth investigations
