# grove-auth

Authentication, authorization, and device trust for the metafactory ecosystem.

## What is this?

grove-auth provides a three-layer auth system for the metafactory dashboard and API infrastructure:

1. **Identity** (CF Access) -- perimeter authentication via Google/GitHub IdP
2. **Authorization** (D1 user roles) -- per-user role enforcement (viewer/operator/admin)
3. **Step-Up** (WebAuthn/PassKeys) -- biometric verification for privileged actions

## Why?

The Grove dashboard is evolving from a read-only view into an operations center that can trigger agent execution, approve deployments, and manage infrastructure. These privileged actions need MFA and device trust -- not just a session cookie.

## Status

**Research complete, design drafted.** See `docs/design-auth-aaa.md` for the full design.

## Key Design Decisions

- **PassKeys over TOTP** -- phishing-resistant, device-bound, ~1 second UX (Touch ID)
- **CF Access as base layer** -- free for 50 users, battle-tested, handles IdP integration
- **`rpId: meta-factory.ai`** -- one PassKey enrollment covers all ecosystem dashboards
- **Elevation windows** -- 5-minute sudo mode, not per-request MFA (prevents fatigue)
- **Action tokens for highest-stakes ops** -- per-action signed JWTs, single-use

## Implementation Phases

1. **User table + role-based authorization** -- D1 migration, `requireRole()` middleware
2. **PassKey enrollment + step-up** -- WebAuthn registration/verification, elevation windows
3. **Cross-ecosystem + approval workflows** -- shared auth across Workers, Discord approval buttons

## License

MIT
