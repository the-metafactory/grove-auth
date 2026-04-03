# Research: Cloudflare Workers Authentication Implementation

**Date:** 2026-04-03
**Source:** PAI research agent (ClaudeResearcher)

## 1. Cloudflare Access as a Zero-Trust Gateway

**How it works:** CF Access sits in front of your Worker (or any HTTP origin) as an identity-aware reverse proxy. Before a request reaches your Worker, Access checks it against policies you define in the Zero Trust dashboard. If the user has not authenticated, Access redirects them to your configured Identity Provider (Google, GitHub, SAML, OIDC, etc.). After successful IdP login, Access issues a signed JWT.

**The JWT flow:**
- Access injects the JWT into the `Cf-Access-Jwt-Assertion` request header (and as a `CF_Authorization` cookie for browser sessions)
- Your Worker validates this JWT against Access's public signing keys at `https://<team-name>.cloudflareaccess.com/cdn-cgi/access/certs`
- The JWT contains the user's identity (`email`), the Access application audience (`aud`), and standard claims (`iss`, `iat`, `exp`)
- Cloudflare rotates signing keys every 6 weeks; previous keys remain valid for 7 days. Match the `kid` in the JWT to the corresponding cert rather than hardcoding

**Authentication vs. Authorization separation:**
This is exactly the pattern Access is designed for. Access handles authentication (proving identity). Your Worker reads the JWT claims and decides authorization (can this user perform this action?). For your dashboard, this means:

- Access ensures only team members reach the Worker at all
- Your Worker reads the `email` claim from the JWT, looks up the user's role in D1, and enforces permissions per route

**Strategic consideration:** Access is free for up to 50 users on the Zero Trust free tier. For a small team dashboard, this eliminates the entire login/password/session infrastructure burden for the human authentication path.

Sources:
- [Validate JWTs - Cloudflare One docs](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)
- [Cloudflare Access product page](https://www.cloudflare.com/zero-trust/products/access/)
- [Identity - Cloudflare Zero Trust](https://developers.cloudflare.com/cloudflare-one/identity/)

---

## 2. CF Access + Service Tokens (Machine-to-Machine)

**How service tokens work:**
Access generates a Client ID and Client Secret pair. Your bot or CLI sends these as HTTP headers:

```
CF-Access-Client-Id: <CLIENT_ID>
CF-Access-Client-Secret: <CLIENT_SECRET>
```

If valid, Access generates a JWT scoped to the application (same `Cf-Access-Jwt-Assertion` header your Worker already validates for human users).

**Critical configuration detail:** The Access policy for machine clients must use a **Service Auth** action, not the default Allow action. Service Auth bypasses the IdP login redirect and instead validates the service token headers directly. You can combine both in a single application:

- Policy 1: Allow -- for human users via IdP (e.g., Google Workspace)
- Policy 2: Service Auth -- for bot/CLI via service token

**Your Worker sees the same JWT format either way.** The difference is the `identity` claim: human JWTs contain an email; service token JWTs identify the service. Your authorization layer distinguishes them by checking claims.

**For your stack:**
- `grove-bot` to Worker: Service token in headers. The bot includes `CF-Access-Client-Id` / `CF-Access-Client-Secret` on every API call.
- CLI to Worker: Same pattern. The CLI stores the service token credentials and sends them with requests.
- Dashboard SPA (browser): CF Access handles the redirect flow automatically via cookie.

**Second-order effect:** Service tokens do not expire by default, but you can set expiration in the dashboard and rotate them. Plan for rotation from day one -- store the token credentials in a secret manager (or CF Worker secrets via `wrangler secret`), not hardcoded.

Sources:
- [Service tokens - Cloudflare One docs](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/)
- [Give your automated services credentials with Access service tokens](https://blog.cloudflare.com/give-your-automated-services-credentials-with-access-service-tokens/)

---

## 3. D1 as a Credential Store

**Schema pattern for WebAuthn + sessions:**

Based on real implementations (nealfennimore/passkeys, Auth.js D1 adapter, Better Auth), a practical D1 schema looks like:

```sql
-- Users table
CREATE TABLE users (
  id TEXT PRIMARY KEY,          -- UUID
  email TEXT UNIQUE NOT NULL,
  display_name TEXT,
  role TEXT DEFAULT 'viewer',   -- viewer | operator | admin
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- WebAuthn credentials (multiple per user for device trust)
CREATE TABLE webauthn_credentials (
  credential_id TEXT PRIMARY KEY,    -- base64url-encoded credential ID
  user_id TEXT NOT NULL REFERENCES users(id),
  public_key TEXT NOT NULL,          -- base64url-encoded COSE public key
  algorithm INTEGER NOT NULL,        -- COSE algorithm ID (-7 for ES256, -257 for RS256)
  sign_count INTEGER DEFAULT 0,      -- replay protection counter
  transports TEXT,                   -- JSON array: ["internal", "hybrid", "usb"]
  device_name TEXT,                  -- user-friendly label
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Device trust records
CREATE TABLE trusted_devices (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  device_fingerprint TEXT NOT NULL,
  trust_level TEXT DEFAULT 'standard', -- standard | elevated
  last_verified_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
```

**D1 session support:** D1 now supports Sessions that maintain sequential consistency among queries executed on the same session object. This is important for auth operations where you register a credential and immediately need to read it back.

**Pattern: D1 for structured data, KV for ephemeral state** (more on this in section 6).

Sources:
- [nealfennimore/passkeys - GitHub](https://github.com/nealfennimore/passkeys)
- [Cloudflare D1 Adapter - Auth.js](https://authjs.dev/getting-started/adapters/d1)
- [Authentication using D1 example - GitHub](https://github.com/G4brym/authentication-using-d1-example)
- [D1 Database - Cloudflare docs](https://developers.cloudflare.com/d1/worker-api/d1-database/)

---

## 4. Worker-Compatible Crypto Libraries

### 4a. WebAuthn Assertion Verification (CBOR + Signatures)

The Workers runtime implements the **Web Crypto API** with support for the algorithms WebAuthn needs:

| Algorithm | Workers Support | WebAuthn Use |
|-----------|----------------|--------------|
| ECDSA P-256 (ES256) | Yes | Most common passkey algorithm |
| ECDSA P-384/P-521 | Yes | Less common authenticators |
| RSA-PSS (PS256) | Yes | Windows Hello, some security keys |
| Ed25519 | Yes (via NODE-ED25519) | Emerging, not yet widespread |
| HMAC SHA-256 | Yes | Action tokens, session MACs |

**CBOR parsing:** WebAuthn attestation and assertion responses contain CBOR-encoded data (the `attestationObject` and `authenticatorData`). The Web Crypto API does not handle CBOR; you need a library. Options:

- **cbor-x** / **cbor-web** -- lightweight CBOR decoders that work in Workers (no Node-specific dependencies)
- **@simplewebauthn/server** -- handles CBOR parsing internally; confirmed Workers-compatible
- **@passwordless-id/webauthn** -- also handles CBOR internally; explicitly lists Workers as a supported runtime

**Recommendation:** Use a WebAuthn library (section 5) rather than parsing CBOR yourself. The attestation format has edge cases (packed vs. none vs. fido-u2f) that are easy to get wrong.

### 4b. JWT Signing and Verification

Multiple proven options:

| Library | Dependencies | Algorithms | Notes |
|---------|-------------|------------|-------|
| **@tsndr/cloudflare-worker-jwt** | Zero | HS256, HS384, HS512, RS256, RS384, RS512 | Purpose-built for Workers. Very lightweight. |
| **jose** (by panva) | Zero | Full suite including EdDSA | Production-grade, used by Auth.js. Confirmed Workers-compatible. |
| **Hono built-in JWT** | Part of Hono | HS256-512, RS256-512, PS256-512, ES256-512, EdDSA | Already in your stack. |
| **Web Crypto API directly** | None | All supported algorithms | More code, but zero dependency. |

For your Hono stack, the built-in `hono/jwt` middleware or helper is the path of least resistance. For CF Access JWT validation specifically, there is `@hono/cloudflare-access` middleware that handles the full validation flow including cert fetching.

### 4c. HMAC for Action Tokens

This is native to Workers -- no library needed:

```typescript
// Sign an action token
const key = await crypto.subtle.importKey(
  'raw',
  new TextEncoder().encode(env.ACTION_TOKEN_SECRET),
  { name: 'HMAC', hash: 'SHA-256' },
  false,
  ['sign', 'verify']
);
const signature = await crypto.subtle.sign(
  'HMAC', key,
  new TextEncoder().encode(`${action}:${userId}:${timestamp}`)
);
```

Sources:
- [Web Crypto - Cloudflare Workers docs](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)
- [Node.js crypto - Cloudflare Workers docs](https://developers.cloudflare.com/workers/runtime-apis/nodejs/crypto/)
- [cloudflare-worker-jwt - GitHub](https://github.com/tsndr/cloudflare-worker-jwt)
- [jose Cloudflare Workers Support - GitHub](https://github.com/panva/jose/issues/265)
- [Hono JWT Auth Middleware](https://hono.dev/docs/middleware/builtin/jwt)
- [@hono/cloudflare-access - npm](https://www.npmjs.com/package/@hono/cloudflare-access)

---

## 5. Open-Source WebAuthn/Passkey Projects on CF Workers

### Libraries

| Library | Workers-Compatible | Notes |
|---------|-------------------|-------|
| **@simplewebauthn/server** | Yes | Most popular. Handles registration, verification, CBOR parsing. Used by multiple CF Workers projects. |
| **@passwordless-id/webauthn** | Yes (explicitly) | Supports NodeJS 19+, Cloudflare Workers, and all WebCrypto-capable runtimes. Lighter than SimpleWebAuthn. |

### Complete Reference Implementations

1. **[FabioDiCeglie/Passkey](https://github.com/FabioDiCeglie/Passkey)** -- React frontend + Hono backend on CF Workers. Uses `@simplewebauthn/browser` and `@simplewebauthn/server`. KV for storage. **This is the closest to your stack** (React SPA + Hono + CF Workers).

2. **[nealfennimore/passkeys](https://github.com/nealfennimore/passkeys)** -- CF Workers + KV (challenges, sessions) + D1 (public keys, users). **Uses the D1+KV split pattern** you're considering. Schema stores `credential_id`, `pubkey`, `attestation_data`, `cose_algorithm`, `sign_counter`. Challenges expire in 5 minutes, sessions in 24 hours.

3. **[atpons/idp](https://github.com/atpons/idp)** -- CF Pages + D1 + KV + WebAuthn. A full identity provider example using SimpleWebAuthn.

4. **[horiuchi/passkey-cloudflare](https://github.com/horiuchi/passkey-cloudflare)** -- Another passkey implementation on Cloudflare, using Remix + D1 + KV + drizzle-orm + SimpleWebAuthn.

5. **[worker-tools/webauthn-example](https://github.com/worker-tools/webauthn-example)** -- WebAuthn on Worker runtimes (Workers + Deno). Uses Worker Tools framework.

6. **[AprilNEA/webauthn-workers](https://github.com/AprilNEA/webauthn-workers)** -- WebAuthn in CF Workers with Yubico support.

### Full Auth Frameworks

**Better Auth** (better-auth.com) deserves special attention:
- As of v1.5 (February 2026), native Cloudflare D1 support with auto-detection of D1 bindings
- Includes a `passkey()` plugin for WebAuthn
- Works with Hono via `@better-auth/cloudflare`
- A [better-auth-cloudflare](https://github.com/zpg6/better-auth-cloudflare) CLI tool handles project generation, resource provisioning, and DB migrations
- Hono integration guide: [Better Auth on Cloudflare - Hono](https://hono.dev/examples/better-auth-on-cloudflare)

**Strategic assessment:** Better Auth is the highest-leverage option if you want a batteries-included framework. SimpleWebAuthn is the best option if you want surgical control over just the WebAuthn ceremony while handling sessions/authorization yourself.

Sources:
- [SimpleWebAuthn - GitHub](https://github.com/MasterKale/SimpleWebAuthn/tree/master)
- [@passwordless-id/webauthn](https://webauthn.passwordless.id/)
- [Better Auth 1.5 release](https://better-auth.com/blog/1-5)
- All GitHub repos linked above

---

## 6. KV vs D1 for Auth State

This is one of the most important architectural decisions. The answer is: **use both, for different things.**

| Concern | Use KV | Use D1 | Why |
|---------|--------|--------|-----|
| **Sessions** | Yes | No | Sessions are read-heavy, write-once, ephemeral. KV's global edge caching gives sub-10ms reads. Set TTL for auto-expiry. |
| **WebAuthn credentials** | No | Yes | Structured data with relationships (user has many credentials). Need `sign_count` updates with consistency. |
| **Challenges (registration/auth)** | Yes | No | Short-lived (5 min TTL). Write-once, read-once, delete. Perfect KV use case. |
| **User profiles/roles** | No | Yes | Relational data. Need queries like "find user by email." |
| **Device trust records** | No | Yes | Need structured queries, expiration checks, audit trail. |
| **Rate limit counters** | Neither | Neither | Use Durable Objects (section 7). KV has a minimum 60s TTL which is too coarse. |

**KV characteristics:**
- Eventually consistent (writes propagate globally over seconds/minutes)
- Reads from edge cache: ~500us to 10ms typical latency
- String values only (JSON.stringify for structured data)
- TTL support for auto-expiry (minimum 60 seconds)
- Free tier: 100k reads/day, 1k writes/day

**D1 characteristics:**
- Strong consistency within a session
- SQL queries with JOINs, indexes, aggregations
- Sub-millisecond reads for small tables
- Free tier: 5M rows read/day, 100k rows written/day

**Practical pattern:**

```
Login flow:
1. User hits /auth/webauthn/start
2. Worker generates challenge, stores in KV: challenge:{id} -> {challenge, userId} (TTL: 300s)
3. Browser performs WebAuthn ceremony
4. User sends assertion to /auth/webauthn/verify
5. Worker reads challenge from KV, reads credential public key from D1
6. Verifies signature with Web Crypto
7. Creates session, stores in KV: session:{token} -> {userId, role, exp} (TTL: 86400s)
8. Returns session token as HttpOnly cookie
```

Sources:
- [Choosing a storage product - Cloudflare Workers docs](https://developers.cloudflare.com/workers/platform/storage-options/)
- [Better Auth + Cloudflare Workers integration guide](https://medium.com/@senioro.valentino/better-auth-cloudflare-workers-the-integration-guide-nobody-wrote-8480331d805f)
- [workers-users - GitHub](https://github.com/devondragon/workers-users)

---

## 7. Durable Objects for Rate Limiting

**Why DOs, not KV or D1:**
- KV's eventual consistency means concurrent requests can bypass limits (read stale count, both increment)
- KV's minimum 60s TTL is too coarse for sliding windows
- D1 writes have latency and no atomic increment guarantees across global requests
- DOs provide a **single-threaded, globally-consistent** coordination point

**Sliding window pattern:**

```typescript
export class AuthRateLimiter implements DurableObject {
  private timestamps: Map<string, number[]> = new Map();

  async fetch(request: Request): Promise<Response> {
    const { key, limit, windowMs } = await request.json();
    const now = Date.now();
    const window = this.timestamps.get(key) ?? [];

    // Filter to sliding window
    const active = window.filter(ts => ts > now - windowMs);

    if (active.length >= limit) {
      const retryAfter = Math.ceil((active[0] + windowMs - now) / 1000);
      return Response.json({ allowed: false, retryAfter }, { status: 429 });
    }

    active.push(now);
    this.timestamps.set(key, active);
    return Response.json({ allowed: true, remaining: limit - active.length });
  }
}
```

**Architecture for auth endpoints:**

```
POST /auth/webauthn/verify
  -> Worker extracts IP or userId
  -> Worker calls DO: AuthRateLimiter.get(id)
  -> DO checks sliding window (5 attempts per 5 minutes)
  -> If blocked: return 429 with Retry-After
  -> If allowed: proceed with WebAuthn verification
```

**Scaling:** A single DO handles ~500-1000 req/s. For auth rate limiting on a small team dashboard, a single DO partitioned by user ID or IP is more than sufficient. If you needed to scale, you shard by hashing the key to multiple DO instances.

**Alternative: Cloudflare's built-in Advanced Rate Limiting** is available in the WAF and can count by headers, cookies, or query parameters. For a "protect your login" use case, you can configure it in the dashboard without any code: block after 5 POST requests to `/auth/*` within 5 minutes from the same IP. This covers brute-force protection without DOs. Reserve DOs for more nuanced per-user or per-action throttling.

Sources:
- [Rate Limiting AI APIs with Durable Objects](https://shivekkhurana.com/blog/global-rate-limiter-durable-objects/)
- [worker-rate-limiter - GitHub](https://github.com/Leon338/worker-rate-limiter)
- [Building a Simple Rate Limiter with Workers and Durable Objects](https://yudax.substack.com/p/building-a-simple-rate-limiter-with)
- [Advanced Rate Limiting - Cloudflare](https://www.cloudflare.com/application-services/products/rate-limiting/)
- [Durable Objects limits](https://developers.cloudflare.com/durable-objects/platform/limits/)

---

## 8. Real-World Examples and Reference Implementations

| Project | Stack | Auth Method | Storage | Link |
|---------|-------|-------------|---------|------|
| **FabioDiCeglie/Passkey** | React + Hono + CF Workers | WebAuthn/Passkeys via SimpleWebAuthn | KV | [GitHub](https://github.com/FabioDiCeglie/Passkey) |
| **nealfennimore/passkeys** | CF Workers + GitHub Pages | WebAuthn with custom FIDO2 | D1 + KV | [GitHub](https://github.com/nealfennimore/passkeys) |
| **atpons/idp** | CF Pages + Workers | WebAuthn via SimpleWebAuthn | D1 + KV | [GitHub](https://github.com/atpons/idp) |
| **horiuchi/passkey-cloudflare** | Remix + CF Pages | Passkeys via SimpleWebAuthn + drizzle | D1 + KV | [GitHub](https://github.com/horiuchi/passkey-cloudflare) |
| **AprilNEA/webauthn-workers** | CF Workers | WebAuthn with Yubico | -- | [GitHub](https://github.com/AprilNEA/webauthn-workers) |
| **worker-tools/webauthn-example** | Worker Tools | WebAuthn | SQLite | [GitHub](https://github.com/worker-tools/webauthn-example) |
| **G4brym/authentication-using-d1** | CF Workers | Password + sessions | D1 | [GitHub](https://github.com/G4brym/authentication-using-d1-example) |
| **devondragon/workers-users** | CF Workers | User management framework | D1 + KV | [GitHub](https://github.com/devondragon/workers-users) |
| **zpg6/better-auth-cloudflare** | Better Auth + Hono | Multiple (incl. Passkey plugin) | D1 | [GitHub](https://github.com/zpg6/better-auth-cloudflare) |

---

## Strategic Synthesis: Recommended Architecture

Three scenarios emerge for your upgrade path:

### Scenario A: Minimal Change (CF Access + App Authorization)
Keep CF Access as the identity layer. Add D1 tables for user roles and permissions. Your Worker validates the Access JWT, extracts the email, looks up permissions in D1, and enforces them. Add WebAuthn as an MFA step-up for privileged actions only (e.g., "confirm with passkey before deploying").

- **Effort:** Low
- **Complexity:** Low
- **Trade-off:** Tied to CF Access for primary identity. No standalone auth.

### Scenario B: Hybrid (CF Access + SimpleWebAuthn)
CF Access remains the perimeter guard. Add SimpleWebAuthn for MFA on privileged actions. D1 stores credentials, KV stores sessions and challenges. You own the WebAuthn ceremony but delegate primary authentication to Access.

- **Effort:** Medium
- **Complexity:** Medium
- **Trade-off:** Best of both worlds. CF Access handles IdP integration; you handle the passkey layer.

### Scenario C: Full Ownership (Better Auth)
Replace CF Access with Better Auth running on your Hono Worker. Native D1 support, passkey plugin, session management, and role-based access all in one framework. CF Access becomes optional (you could keep it as a defense-in-depth layer or remove it).

- **Effort:** Higher upfront
- **Complexity:** Higher
- **Trade-off:** Full control, no CF Access dependency, but you own the entire auth surface.

**Recommendation: Scenario B.** It gives you per-user auth with MFA without rebuilding the login flow from scratch. CF Access is free, battle-tested, and handles the messy IdP/SAML/OIDC integration. SimpleWebAuthn on your Worker handles the passkey ceremony for elevated actions. Service tokens continue working for bot/CLI. When the team grows beyond CF Access's capabilities (or you want fully portable auth), you migrate to Scenario C.

**Second-order effects to consider:**
1. **Key recovery:** If a user loses their only passkey device, you need a recovery path. With CF Access as primary auth, recovery is just "log in via Google, re-register a new passkey." Without it, you need backup codes or admin-initiated recovery.
2. **Cross-origin concerns:** CF Pages (your SPA) and CF Workers (your API) may be on different subdomains. WebAuthn's `rpId` (relying party ID) must match or be a registrable suffix of the origin. Set `rpId` to the parent domain (e.g., `meta-factory.ai`) so credentials work across subdomains.
3. **Service token rotation:** Plan automated rotation from day one. A leaked service token with no expiry is a persistent backdoor.
