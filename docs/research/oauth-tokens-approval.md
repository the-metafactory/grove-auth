# Research: OAuth, Token Patterns, and Approval Flows

**Date:** 2026-04-03
**Source:** PAI research agent (ClaudeResearcher)

## Research Report: Authentication Patterns for Privileged Agent Action Approval

### 1. OAuth 2.0 Device Authorization Grant -- Relevance Assessment

**Verdict: Not the right fit for your dashboard-to-agent flow. But a related variant is.**

The Device Authorization Grant (RFC 8628) is designed for input-constrained devices (smart TVs, IoT) that lack a browser. The flow works by displaying a code on the device, the user visits a URL on a separate device with a browser, enters the code, and the original device polls until authorization completes.

Your architecture is the inverse -- you have a rich browser-based dashboard initiating actions. The Device Auth Grant solves "how does a device without a browser get the user to authorize it," not "how does a browser-based app get step-up authorization for a dangerous action."

**Where it becomes relevant:** If you ever need CLI-initiated agent execution (a terminal session requesting dashboard approval), then a Device-Auth-Grant-like flow makes sense -- the CLI displays a code, the user approves on the dashboard, the CLI polls and proceeds. There is also a new draft specification (draft-parecki-oauth-dpop-device-flow) that combines DPoP with Device Auth Grant, binding the device flow to a specific key pair for stronger security.

**Strategic recommendation:** Skip this for the dashboard flow. Keep it in your back pocket for a future CLI-to-dashboard approval path.

### 2. Short-Lived Action Tokens

**This is the core pattern you want. Three approaches work in CF Workers.**

The concept: when a user approves a privileged action, the system mints a cryptographically signed, time-limited, scope-limited token that authorizes that specific action and nothing else. This is fundamentally different from a session token -- it is an "authorization receipt."

**Pattern A -- Single-Use JWT (recommended for your architecture):**
```
Claims: {
  sub: "user-id",
  act: "deploy:grove:v0.15.0",     // specific action
  iat: 1712160000,
  exp: 1712160300,                  // 5 min TTL
  jti: "unique-nonce",             // replay prevention
  aud: "grove-worker-api",
  device_fp: "sha256-of-binding"   // see section 7
}
```
The token is signed with HMAC-SHA256 or RS256 via the Web Crypto API (`crypto.subtle`), which is fully available in CF Workers. The `jose` library by panva works cleanly in Workers for both signing and verification.

**Pattern B -- State-invalidating secret:** For truly one-time tokens (password resets, single-action approvals), you can use a value derived from application state as part of the signing secret. Once the action executes and the state changes, the same token can never verify again. This is elegant but harder to implement across distributed Workers.

**Pattern C -- KV-backed nonce tracking:** Store the `jti` in Cloudflare KV with a TTL matching the token expiry. On use, check-and-delete atomically. This gives you explicit one-time-use semantics. KV's eventual consistency is acceptable here because the window is tiny and the worst case is a brief double-acceptance (mitigated by idempotent action handlers).

**Workers compatibility:** Full. Web Crypto API provides `crypto.subtle.sign()`, `crypto.subtle.verify()`, `crypto.subtle.importKey()`. The `jose` library works without Node.js native modules. KV provides persistence for nonce tracking.

### 3. Step-Up Authentication -- How the Big Three Do It

**GitHub "Sudo Mode":**
GitHub's approach is the closest analog to your needs. When a user performs a sensitive action (adding SSH keys, creating PATs, authorizing OAuth apps), GitHub requires re-authentication even though the user has an active session. After re-auth, the user enters "sudo mode" for 2 hours, during which further sensitive actions don't require re-auth. Authentication methods include password, passkey, security key, GitHub Mobile, or TOTP.

Key design insight: GitHub separates "session authentication" (you are logged in) from "action authorization" (you have recently proven you are you). The sudo mode timer resets on each sensitive action.

**AWS MFA-Protected API Calls:**
AWS implements step-up at the IAM policy level using condition keys. Policies include `Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } }`. The flow: user has base credentials with limited permissions, calls `sts:GetSessionToken` with MFA token code, receives temporary credentials with elevated permissions. The temporary credentials carry MFA context in their request metadata.

Key design insight: AWS makes step-up a credential property, not a session property. The elevated credential is itself time-limited (configurable, default 12 hours).

**Cloudflare Access MFA Policies:**
Cloudflare Access allows per-application MFA requirements. You can require hardware keys (WebAuthn/FIDO2) for high-security applications while allowing TOTP for lower-security ones. Cloudflare's approach operates at the network edge, independent of the IdP, introducing a second authority that must sign off.

Key design insight: Cloudflare separates the MFA requirement from the IdP, allowing different MFA strength per application.

**Recommended pattern for your system:**
Combine GitHub's "sudo mode" concept with short-lived action tokens. The dashboard session (via CF Access) proves identity. When a privileged action is triggered, the frontend calls `navigator.credentials.get()` (WebAuthn) for step-up. On success, the Worker mints an action token. This gives you: session (CF Access) + step-up (WebAuthn) + action authorization (signed JWT).

### 4. Cloudflare Access + mTLS + WebAuthn Layered Architecture

**This is your strongest architectural option. Three layers, each independently verifiable.**

**Layer 1 -- Cloudflare Access (base session):**
CF Access sits in front of your Worker and Pages deployment. It authenticates users via your IdP (Google, GitHub, etc.) and injects a `Cf-Access-Jwt-Assertion` header and `CF_Authorization` cookie on every request. Your Worker validates this JWT against your team's public keys at `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`.

Claims available in the CF Access JWT include: user email, identity nonce, auth method (including which MFA was used), and custom SAML/OIDC claims. You can configure Access policies to require specific MFA methods (e.g., hardware keys only for the dashboard).

**Layer 2 -- WebAuthn step-up for privileged actions:**
When a user clicks "Deploy" or "Start Agent Session," the React dashboard calls `navigator.credentials.get()` to trigger a WebAuthn assertion. This proves the user is physically present at the device with access to their authenticator (biometric, hardware key). The assertion is sent to the Worker, which verifies it against the stored public key.

Google's WebAuthn re-authentication codelab demonstrates exactly this pattern -- a user is already logged in, and the app calls `navigator.credentials.get()` with `allowCredentials` set to the user's registered credentials for re-verification before a sensitive operation.

**Layer 3 -- Action token (scoped authorization):**
After the Worker verifies both the CF Access JWT and the WebAuthn assertion, it mints a short-lived action token (see section 2) that encodes exactly what was approved. This token travels with the action through the pipeline (Worker -> Discord bot -> local agent).

**mTLS for service-to-service:**
Between your Worker and any backend services (the Discord bot, agent execution), use CF's mTLS support. Workers can present client certificates when connecting to mTLS-protected origins. This ensures that even if someone intercepts the action token, they cannot present it to the agent execution endpoint without the Worker's client certificate.

**Workers compatibility:** All three layers are native to the CF ecosystem. Access JWT validation uses `jose` + Web Crypto. WebAuthn verification uses the `@simplewebauthn/server` library (pure JS, no native modules). mTLS is a Workers binding.

### 5. JWT with Scoped Claims -- Action Authorization Encoding

**The specific claim schema for encoding "user X approved action Y at time Z."**

Building on the emerging pattern of JWTs for AI agent authorization (which is gaining attention as a distinct problem space in 2025-2026), here is a recommended claim structure:

```typescript
interface ActionToken {
  // Standard claims
  iss: string;          // "grove-worker.meta-factory.ai"
  sub: string;          // user ID from CF Access
  aud: string;          // "grove-agent-executor"
  iat: number;          // issued-at timestamp
  exp: number;          // expiry (iat + 300 for 5 min)
  jti: string;          // unique nonce (UUIDv4)

  // Action-specific claims
  act: {
    type: string;       // "deploy" | "agent-session" | "command"
    target: string;     // "grove:v0.15.0" | "claude-session:thread-123"
    params: Record<string, string>;  // action-specific parameters
  };

  // Authorization context
  authz: {
    method: string;     // "webauthn" | "totp" | "passkey"
    amr: string[];      // authentication methods reference
    acr: string;        // authentication context class
  };

  // Binding claims (see section 7)
  cnf: {
    jkt: string;        // JWK thumbprint for DPoP binding
  };
}
```

**Signing in Workers:**
```typescript
const key = await crypto.subtle.importKey(
  "raw",
  encoder.encode(env.ACTION_TOKEN_SECRET),
  { name: "HMAC", hash: "SHA-256" },
  false,
  ["sign"]
);
const token = await new jose.SignJWT(claims)
  .setProtectedHeader({ alg: "HS256" })
  .sign(key);
```

For asymmetric signing (RS256/ES256), use `crypto.subtle.generateKey()` to create key pairs and store the private key in Workers Secrets. The public key can be published as a JWKS endpoint for downstream verification.

**Verification at the agent executor:**
The Discord bot or local agent verifies the action token before executing. It checks: signature validity, expiry, audience matches, jti has not been seen (replay check), and action type matches what is being executed.

### 6. Approval Flows in ChatOps

**Three proven patterns from production ChatOps systems, mapped to your architecture.**

**Pattern A -- Atlantis (Terraform apply approval):**
Atlantis requires PR approval before `terraform apply` can execute. The flow: (1) PR opened with infrastructure changes, (2) Atlantis runs `plan` and posts the diff as a comment, (3) A different user must approve the PR, (4) Only then does `atlantis apply` succeed. Configuration via `repos.yaml` with `apply_requirements: [approved]`.

Mapped to your system: Agent execution requests could post a "plan" to a Discord thread (what will be executed, with what permissions, targeting what). A team member approves via reaction or button. Only then does execution proceed.

**Pattern B -- Slack Interactive Approval Buttons:**
Slack's approval workflow pattern uses Block Kit with primary/danger-styled buttons and confirmation dialogs. The flow: (1) Bot posts an action request with Approve/Reject buttons, (2) Button clicks trigger a POST to the bot's interaction endpoint, (3) The bot validates the approver's identity and permissions, (4) On approval, action executes and the message updates to show status.

Slack's "Verified User Access" ensures only designated approvers can click the buttons. Discord doesn't have native equivalent, but you can implement it via: (a) checking the interaction user against an allowed-approvers list, (b) using Discord's button components with custom IDs that encode the action, (c) requiring the approver to be a different user than the requester.

**Pattern C -- Two-person rule (dual authorization):**
For the most sensitive actions (production deployments, agent sessions with broad permissions), require two distinct users to approve. User A requests, User B approves. This is standard in financial services and is implemented by Atlantis (PR author cannot approve their own apply).

**Recommended implementation for your Discord bot:**

```
1. Dashboard user triggers "Deploy v0.15.0"
2. Worker posts to Discord: "Deploy v0.15.0 requested by @andreas"
   [Approve] [Reject] buttons
3. Authorized user clicks [Approve] in Discord
4. Bot verifies: approver != requester, approver has role, within time window
5. Bot calls Worker API with approval context
6. Worker mints action token, execution proceeds
```

This gives you an audit trail in Discord, human-in-the-loop approval, and separation between requester and approver.

### 7. Session Binding -- Preventing Token Theft and Replay

**Three approaches, from practical-today to emerging-standard.**

**Approach A -- DPoP (Demonstrating Proof of Possession) -- recommended:**
DPoP (RFC 9449) is the strongest practical approach available today that works in browsers. The client generates a key pair (via `crypto.subtle.generateKey()`), sends the public key with authorization requests, and creates a signed "DPoP proof" JWT for each request that includes: the HTTP method (`htm`), the request URI (`htu`), an access token hash (`ath`), and a unique `jti`.

The server binds tokens to the client's public key via a `cnf.jkt` claim (JWK thumbprint). When the token is used, the server verifies both the token signature AND the DPoP proof signature, confirming the presenter possesses the private key.

**Workers compatibility:** Full. `crypto.subtle.generateKey("ECDSA", ...)` on the client, verification via `crypto.subtle.verify()` in the Worker. No native modules needed.

**Approach B -- Device Bound Session Credentials (DBSC) -- emerging:**
Chrome's DBSC (now in Chrome 145 on Windows, origin trial expanding) binds sessions to device-specific TPM-backed key pairs. The browser creates a key pair during login, stores the private key in the TPM, and proves possession on each cookie refresh. This operates at the HTTP layer (not TLS layer, unlike the failed Token Binding spec), making it CDN-compatible.

This is the future-state answer, but it is not yet universally available. Chrome-only as of mid-2026, no Firefox/Safari support yet. Watch this space but do not depend on it today.

**Approach C -- Contextual binding (practical today):**
Bind the session to observable device characteristics: IP address, User-Agent, Accept-Language, screen dimensions (via JS). Hash these into a fingerprint stored in the session. On each request, recompute and compare. A mismatch triggers re-authentication.

This is weaker than cryptographic binding (fingerprints can be spoofed by a sophisticated attacker) but it catches the common case of stolen cookies being replayed from a different machine. Combined with short-lived action tokens (section 2), the window of vulnerability is tiny.

**Recommended layered approach:**

| Layer | Mechanism | Protects Against |
|-------|-----------|------------------|
| Base | CF Access session cookie (HttpOnly, Secure, SameSite) | XSS cookie theft |
| Binding | DPoP proof on privileged requests | Token replay from different client |
| Freshness | WebAuthn step-up for actions | Stolen session without physical access |
| Scope | Action token with 5-min TTL and jti nonce | Broad token misuse, replay |

---

## Strategic Synthesis: The Recommended Architecture

Considering second-order effects and how these seven patterns interact, here is the recommended architecture for your specific system (React on CF Pages, Worker API, Discord bot, local agent execution, 5-10 users):

```
[React Dashboard on CF Pages]
        |
        | (1) CF Access provides base session
        | (Cf-Access-Jwt-Assertion header on all requests)
        |
[Cloudflare Worker API]
        |
        | (2) For privileged actions: Worker challenges for WebAuthn
        |     Dashboard calls navigator.credentials.get()
        |     Worker verifies assertion
        |
        | (3) Worker mints action token (short-lived JWT, scoped claims)
        |     Signs with crypto.subtle, 5-min TTL, unique jti
        |     Stores jti in KV for replay prevention
        |
        | (4) Optional: Posts to Discord for team approval
        |     Interactive buttons, different-user requirement
        |
        | (5) Action token sent to Discord bot / agent executor
        |     mTLS between Worker and execution backend
        |
[Discord Bot / Local Agent]
        |
        | (6) Verifies action token signature, expiry, jti, scope
        |     Executes only the approved action
        |     Reports result back through pipeline
```

**Why this works for a small team:**
- CF Access handles IdP integration (no custom auth to build)
- WebAuthn step-up is phishing-resistant and fast (touch your YubiKey)
- Action tokens are stateless verification (Workers can be ephemeral)
- Discord approval gives you an audit trail your team already reads
- KV-based nonce tracking scales to any number of concurrent actions
- The entire stack runs on CF infrastructure you already use

**Second-order effects to consider:**
1. **Latency budget:** WebAuthn adds ~1-3 seconds of user interaction. Action token minting adds ~5ms in the Worker. Total overhead for a privileged action: ~2 seconds. Acceptable for deploy/agent-launch flows.
2. **Key management:** The action token signing key is the crown jewel. Store it as a Workers Secret, rotate quarterly. Consider using asymmetric keys (ES256) so the public key can be distributed to the agent executor without exposing the signing key.
3. **Failure mode:** If CF Access goes down, nothing works (by design). If WebAuthn fails (device not available), fall back to TOTP as a degraded step-up. Never fall back to "no step-up."
4. **Audit completeness:** Every action token mint event should be logged with: who, what, when, which auth methods, which device. This gives you a complete forensic trail.

## Sources

- [RFC 8628 - OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [OAuth 2.0 DPoP - RFC 9449](https://oauth.net/2/dpop/)
- [DPoP for Device Authorization Grant (draft)](https://datatracker.ietf.org/doc/draft-parecki-oauth-dpop-device-flow/)
- [Token Lifetimes and Security in OAuth 2.0 - IDPro](https://bok.idpro.org/article/id/108/)
- [Single-Use JWT Pattern](https://www.janbrennenstuhl.eu/howto-single-use-jwt/)
- [JWTs for AI Agents: Authenticating Non-Human Identities](https://securityboulevard.com/2025/11/jwts-for-ai-agents-authenticating-non-human-identities/)
- [GitHub Sudo Mode](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/sudo-mode)
- [AWS Step-Up Authentication with Cognito (Part 1)](https://aws.amazon.com/blogs/security/implement-step-up-authentication-with-amazon-cognito-part-1-solution-overview/)
- [AWS MFA-Protected API Calls](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_configure-api-require.html)
- [Cloudflare Enforce MFA Policies](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/mfa-requirements/)
- [Cloudflare mTLS for Workers](https://blog.cloudflare.com/mtls-workers/)
- [Cloudflare Workers Web Crypto API](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)
- [Validate CF Access JWTs](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)
- [Cloudflare FIDO2 and Zero Trust Implementation](https://blog.cloudflare.com/how-cloudflare-implemented-fido2-and-zero-trust/)
- [JWT Verification in Cloudflare Workers (Kinde)](https://www.kinde.com/blog/engineering/verifying-jwts-in-cloudflare-workers/)
- [JWT Validation at the Edge with CF Workers](https://ssojet.com/blog/how-to-validate-jwts-efficiently-at-the-edge-with-cloudflare-workers-and-vercel)
- [Microservices AuthN/AuthZ Part 3 - JWT Authorization](https://microservices.io/post/architecture/2025/07/22/microservices-authn-authz-part-3-jwt-authorization.html)
- [RFC 9068 - JWT Profile for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/html/rfc9068)
- [Atlantis Apply Requirements](https://www.runatlantis.io/docs/apply-requirements.html)
- [Atlantis Command Requirements](https://www.runatlantis.io/docs/command-requirements)
- [Slack Approval Workflows Best Practices](https://api.slack.com/best-practices/blueprints/approval-workflows)
- [PagerDuty ChatOps Documentation](https://response.pagerduty.com/resources/chatops/)
- [Device Bound Session Credentials (Chrome)](https://developer.chrome.com/docs/web-platform/device-bound-session-credentials)
- [DBSC Explained (Corbado)](https://www.corbado.com/blog/device-bound-session-credentials-dbsc)
- [Token Replay Attacks: Detection and Prevention](https://www.obsidiansecurity.com/blog/token-replay-attacks-detection-prevention)
- [Token Replay Prevention (WorkOS)](https://workos.com/blog/token-replay-attacks)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [DPoP Complete Guide (Authgear)](https://www.authgear.com/post/demonstrating-proof-of-possession-dpop)
- [WebAuthn Guide](https://webauthn.guide/)
- [Google WebAuthn Re-authentication Codelab](https://developers.google.com/codelabs/webauthn-reauth)
- [W3C Web Authentication Level 3 Spec](https://www.w3.org/TR/webauthn-3/)
