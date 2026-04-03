## Architecture

grove-auth provides three-layer authentication and authorization for the metafactory ecosystem:

- **Layer 1 — Identity (CF Access):** Cloudflare Access provides perimeter authentication. Users log in via Google/GitHub IdP. Workers receive signed JWTs with email identity. Service tokens handle bot/CLI machine auth.
- **Layer 2 — Authorization (D1 user table):** Maps CF Access email to app-level roles (`viewer`, `operator`, `admin`). Route-level middleware enforces permissions.
- **Layer 3 — Step-Up (WebAuthn/PassKeys):** Privileged actions require biometric verification via PassKeys. Time-scoped elevation windows (5 min) prevent MFA fatigue. Per-action signed JWTs for highest-stakes operations.

### Key Components

- `src/webauthn/` — PassKey registration and assertion verification (SimpleWebAuthn)
- `src/middleware/` — Hono middleware: `requireRole()`, `requireStepUp()`, `requireActionToken()`
- `src/tokens/` — Scoped action token minting and verification (Web Crypto API)
- `src/schema/` — D1 migration scripts for users, passkey_credentials tables

### Integration Points

- **Grove Worker** — imports middleware and WebAuthn handlers
- **Miner Server Worker** — same middleware, shared rpId (`meta-factory.ai`)
- **Dashboard SPA** — `@simplewebauthn/browser` for PassKey ceremonies
- **Discord bot** — approval flow buttons for team-gated actions

### Design Docs

- `docs/design-auth-aaa.md` — Full design specification
- `docs/research/` — Research findings from PassKeys, OAuth, CF Workers auth investigations
