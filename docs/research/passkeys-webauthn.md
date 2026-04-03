# Research: WebAuthn and PassKeys for Device Trust

**Date:** 2026-04-03
**Source:** PAI research agent (ClaudeResearcher)

## Research Report: WebAuthn and PassKeys for Persistent Device Trust

### Query Decomposition

The research was decomposed into seven parallel search tracks: (1) device trust persistence mechanics, (2) resident vs non-resident credentials, (3) Cloudflare Workers runtime compatibility, (4) cross-origin domain considerations for your specific architecture, (5) terminology clarification, (6) browser/UX surface, and (7) attestation/assertion flows. A second round targeted the specific implementation libraries and step-up authentication patterns relevant to your use case.

---

### 1. Terminology: PassKeys vs FIDO2 vs WebAuthn

These terms form a hierarchy, not competing standards:

- **FIDO2** is the umbrella standard. It consists of two components: WebAuthn (the browser API) and CTAP (Client to Authenticator Protocol, for hardware keys communicating over USB/NFC/Bluetooth).
- **WebAuthn** is the W3C JavaScript API that websites call. It is what you code against. `navigator.credentials.create()` for registration, `navigator.credentials.get()` for authentication.
- **CTAP** is the wire protocol between an external authenticator (YubiKey) and the client device. For platform authenticators (Touch ID, Windows Hello), CTAP is not involved -- the OS handles it directly.
- **Passkeys** is the consumer-facing brand introduced jointly by Apple, Google, and Microsoft. A passkey is a WebAuthn discoverable credential. There are two flavors:
  - **Synced passkeys**: backed up to cloud (iCloud Keychain, Google Password Manager, 1Password). Survive device loss. This is what most consumers use.
  - **Device-bound passkeys**: tied to a single device's TPM/Secure Enclave. Cannot be extracted. Higher security, but lost if device is lost.

**For your use case (5-10 person team, privileged actions):** You want synced passkeys for convenience (team members can register from any of their devices) combined with a step-up authentication pattern for dangerous operations. The term you will use in code is WebAuthn; the term you will use with your team is "passkeys."

---

### 2. Resident vs Non-Resident Credentials (Device Trust Persistence)

This distinction is critical for the "remember this device" flow you described:

**Resident keys (discoverable credentials):**
- The private key and user handle are stored persistently on the authenticator (Secure Enclave, TPM, or password manager).
- Enable username-less login -- the authenticator itself knows which credential belongs to which relying party.
- Support Conditional UI (passkey autofill in browser fields).
- This is what passkeys are. When you set `residentKey: "required"` in your registration options, you get a discoverable credential.
- Storage limit on hardware keys: 8-100 slots. Not a concern for platform authenticators (Touch ID/Windows Hello) or password managers, which have effectively unlimited storage.

**Non-resident keys (server-side credentials):**
- The credential ID is stored server-side. During authentication, the server must provide the credential ID so the authenticator can locate the key.
- Require the user to identify themselves first (username, then authenticate).
- Cannot do Conditional UI or username-less flows.

**For your use case:** Use resident keys (`residentKey: "required"`, `requireResidentKey: true`). This gives you the "enrolled device" pattern you want. Once a team member registers their passkey, their device is trusted. Future privileged actions trigger a biometric prompt (Touch ID, face, PIN) but not a full login flow. The credential persists on their device/password manager indefinitely.

The registration options would look like:

```typescript
authenticatorSelection: {
  residentKey: "required",
  requireResidentKey: true,
  userVerification: "required",  // forces biometric/PIN
  authenticatorAttachment: "platform"  // or omit for cross-platform
}
```

Setting `authenticatorAttachment: "platform"` restricts to the built-in authenticator (Touch ID, Windows Hello). Omitting it also allows hardware keys (YubiKeys).

---

### 3. Attestation (Registration) vs Assertion (Authentication)

**Registration flow (one-time enrollment):**

1. User clicks "Register device" on your dashboard.
2. Your Worker API calls `generateRegistrationOptions()` -- produces a challenge, rpID, user info, and authenticator preferences. Stores the challenge temporarily (KV, with 60s TTL).
3. Frontend calls `navigator.credentials.create(options)` -- the browser prompts the user's authenticator (Touch ID dialog, Windows Hello, etc.).
4. User verifies (fingerprint/face/PIN). The authenticator generates a new key pair, stores the private key locally, returns the public key + attestation to the browser.
5. Frontend sends the `AuthenticatorAttestationResponse` to the Worker.
6. Worker calls `verifyRegistrationResponse()` -- validates the challenge, origin, rpID, and extracts the public key + credential ID. Stores these in D1.

**Authentication flow (subsequent verification):**

1. User triggers a privileged action (e.g., "approve deployment").
2. Worker calls `generateAuthenticationOptions()` -- produces a challenge. Optionally includes `allowCredentials` (list of credential IDs for this user), but with discoverable credentials you can omit this for a cleaner UX.
3. Frontend calls `navigator.credentials.get(options)` -- browser prompts biometric.
4. User taps Touch ID. Authenticator signs the challenge with the private key.
5. Frontend sends the `AuthenticatorAssertionResponse` to the Worker.
6. Worker calls `verifyAuthenticationResponse()` -- verifies the signature against the stored public key, validates challenge/origin/rpID, checks the sign counter (replay protection).

**For privileged actions (step-up auth):** You do not need a full login-logout cycle. The pattern is:
- User is already authenticated (session cookie, JWT, whatever).
- They trigger a dangerous action.
- Frontend initiates a WebAuthn assertion (step 2-6 above).
- If the assertion verifies, the action proceeds. The elevated assurance can be time-bounded (e.g., valid for 5 minutes).
- This avoids MFA fatigue -- routine dashboard browsing is normal, only dangerous operations trigger the biometric prompt.

**Attestation type:** For a small team, use `attestationType: "none"`. You do not need to verify the make/model of the authenticator. Attestation verification adds complexity and is only relevant for high-compliance environments (government, banking).

---

### 4. Cloudflare Workers Compatibility

This is the most architecturally significant finding. Two libraries work in the Workers runtime:

**@passwordless-id/webauthn** ([docs](https://webauthn.passwordless.id/), [GitHub](https://github.com/passwordless-id/webauthn))
- Explicitly supports Cloudflare Workers.
- Zero dependencies. Uses Web Crypto API (`crypto.subtle`) natively -- no Node.js crypto required.
- Provides both client (`@passwordless-id/webauthn/client`) and server (`@passwordless-id/webauthn/server`) modules.
- Server provides `verifyRegistration()` and `verifyAuthentication()`.
- Opinionated, minimal API surface. Good for your use case (small team, not building a full identity platform).

**SimpleWebAuthn** ([docs](https://simplewebauthn.dev/), [GitHub](https://github.com/MasterKale/SimpleWebAuthn))
- TypeScript-first. More comprehensive API with `generateRegistrationOptions()`, `verifyRegistrationResponse()`, `generateAuthenticationOptions()`, `verifyAuthenticationResponse()`.
- More widely used, better documented, more active maintenance.
- May require `nodejs_compat` compatibility flag in your `wrangler.toml` if it uses any Node.js crypto internals. This is a standard Cloudflare flag, not a hack.

**Existing reference implementations on CF Workers:**
- [FabioDiCeglie/Passkey](https://github.com/FabioDiCeglie/Passkey) -- React frontend + Hono backend on Workers. Uses KV for session state.
- [nealfennimore/passkeys](https://github.com/nealfennimore/passkeys) -- Workers + KV (challenge cache) + D1 (credential storage). Full working demo.
- [worker-tools/webauthn-example](https://github.com/worker-tools/webauthn-example) -- Workers + Deno dual-target example.

**Storage architecture for your Worker:**
- **KV**: Store registration/authentication challenges with short TTL (60-120 seconds). Challenges are ephemeral and must be verified exactly once.
- **D1**: Store user credential records (userId, credentialId, publicKey, counter, createdAt, lastUsedAt). This is your "enrolled devices" table.

**Recommended:** `@passwordless-id/webauthn` for simplicity given your use case. It has explicit Workers support with no compatibility flag needed. If you find you need more control over options, SimpleWebAuthn with `nodejs_compat` is the fallback.

---

### 5. Cross-Origin Considerations (Your Specific Architecture)

Your architecture: dashboard on `grove.meta-factory.ai` (CF Pages), API Worker on a different origin.

**The critical concept is the Relying Party ID (rpID).** Every passkey is cryptographically bound to an rpID at creation time.

**Scenario A: Same registrable domain (recommended)**
If both your dashboard and API are subdomains of `meta-factory.ai`:
- Dashboard: `grove.meta-factory.ai`
- API: `api.meta-factory.ai` (or `grove-api.meta-factory.ai`)

Set `rpID: "meta-factory.ai"` in both registration and authentication options. WebAuthn's scoping rules allow any subdomain to use a parent domain as its rpID. A passkey registered on `grove.meta-factory.ai` with rpID `meta-factory.ai` can be verified from any subdomain of `meta-factory.ai`.

This is the simplest path. No Related Origin Requests needed. Works in all browsers today.

**Scenario B: Different registrable domains**
If your API is on a completely different domain (e.g., `grove-api.workers.dev`), you need Related Origin Requests (ROR):
- Host a `.well-known/webauthn` JSON file at `https://meta-factory.ai/.well-known/webauthn` containing `{"origins": ["https://grove-api.workers.dev"]}`.
- Browser support: Chrome 129+, Safari 18+, Firefox has no implementation yet (positive standards position issued March 2026).
- Limit of 5 registrable domains in the allowlist.

**However:** The WebAuthn ceremony (create/get) happens entirely between the browser and the frontend origin. The API Worker only needs to verify the attestation/assertion server-side. So the actual flow is:

1. Frontend (`grove.meta-factory.ai`) calls `navigator.credentials.create/get()` -- this is a browser API call, bound to the frontend's origin and the rpID.
2. Frontend sends the result to your API Worker via a normal fetch request.
3. Worker verifies the response, checking that the origin matches and the rpID matches.

**The rpID and origin checking happens in your verification code, not in the browser-to-Worker connection.** So as long as you set `rpID: "meta-factory.ai"` and your verification code expects `origin: "https://grove.meta-factory.ai"`, it works regardless of where the API Worker is hosted.

**Strategic recommendation:** Put your Worker on a `meta-factory.ai` subdomain (e.g., `api.meta-factory.ai` via CF custom domain routing). This keeps everything on the same registrable domain, avoids ROR entirely, and works in all browsers including Firefox.

---

### 6. Browser Support and User Experience

What the user actually sees:

**macOS (Safari/Chrome/Edge):**
- Touch ID dialog slides down from the top of the screen. User places finger on Touch ID sensor. Takes ~1 second.
- If no Touch ID (older Mac), falls back to system password or linked iPhone/Apple Watch.

**Windows (Edge/Chrome):**
- Windows Hello prompt appears. Options depend on hardware: fingerprint sensor, face recognition (IR camera), or PIN fallback.
- Starting 2025, Microsoft made passkeys the default sign-in method for new accounts (1.5B+ users).

**iOS/Android (mobile browsers):**
- Face ID / fingerprint prompt, native OS dialog. Seamless.

**Cross-device (QR code flow):**
- If a user is on a device without their passkey, the browser can show a QR code. User scans with their phone (which has the passkey), authenticates there, and the session is established on the original device via Bluetooth proximity.
- This is the "hybrid" transport. Requires Bluetooth to be on, on both devices.

**Browser support matrix (as of 2026):**
- Chrome/Edge 67+ (full passkey support from 108+)
- Safari 14+ (full passkey support from 16+, synced passkeys from 16+)
- Firefox 60+ (basic WebAuthn), passkey support still catching up

**Password manager integration:**
- 1Password, Bitwarden, Dashlane all support storing passkeys.
- Windows 11 has a plug-in model for third-party passkey providers (shipped 2024).
- On macOS/iOS, iCloud Keychain stores passkeys natively and syncs across Apple devices.

**For your team (5-10 users, likely all on Mac):** The experience is: click "Register" once, Touch ID prompt, done. For every privileged action thereafter: Touch ID prompt, ~1 second, action proceeds. No codes, no authenticator apps, no SMS.

---

### 7. Strategic Insights and Second-Order Effects

**Three scenarios emerge from this research:**

**Scenario 1 (Recommended): Lightweight step-up auth**
- Users log into the dashboard via existing mechanism (session cookie, CF Access, whatever you have now).
- Register their passkey once (enrollment flow).
- Privileged actions (trigger agent execution, approve deployments, modify configuration) require a WebAuthn assertion -- Touch ID prompt.
- Assertion validity is time-scoped (e.g., 5 minutes). Multiple privileged actions within the window don't re-prompt.
- Storage: D1 for credentials, KV for challenge cache.
- Library: `@passwordless-id/webauthn` on the Worker.

**Scenario 2: Full passkey-based authentication**
- Replace your current auth entirely with passkeys. No passwords, no CF Access.
- Higher implementation effort. Need to handle account recovery, device loss, multiple device registration.
- Overkill for 5-10 users.

**Scenario 3: Hardware key requirement (maximum security)**
- Require device-bound passkeys on hardware security keys (YubiKey).
- Most secure (credentials cannot be synced/extracted), but worst UX (must carry key).
- Set `authenticatorAttachment: "cross-platform"` to require external authenticator.
- Worth considering only if you have adversarial threat model.

**Second-order effects to consider:**

1. **Device loss recovery**: Synced passkeys survive device loss (iCloud backup). But if a user loses all their devices, you need an admin recovery path. For 5-10 users, this can be a manual "admin resets user's credentials" flow.

2. **Credential sprawl**: Users can register multiple passkeys (laptop, phone, hardware key). Your D1 table should support multiple credentials per user. Show a "manage devices" UI.

3. **Sign counter drift**: WebAuthn tracks a sign counter for replay protection. If a credential is cloned (shouldn't happen with TPM-backed keys), the counter will be out of sync. Your verification should flag counter decreases as suspicious.

4. **Future-proofing**: WebAuthn Level 3 spec (Working Draft January 2025, expected finalization by Q2 2026) adds features like device-bound key attestation improvements and better cross-device flows. The W3C Web Authentication Working Group is chartered through April 2026.

---

### Recommended Implementation Architecture

```
grove.meta-factory.ai (CF Pages)          api.meta-factory.ai (CF Worker)
     |                                           |
     |  1. User clicks "Register Device"         |
     |  ---------------------------------------->|
     |                 2. generateRegistrationOptions()
     |                    store challenge in KV (60s TTL)
     |  <----------------------------------------|
     |                 3. Return options JSON     |
     |                                           |
     |  4. navigator.credentials.create(options) |
     |     [Touch ID / Windows Hello prompt]      |
     |                                           |
     |  5. Send attestation response             |
     |  ---------------------------------------->|
     |                 6. verifyRegistration()    |
     |                    store credential in D1  |
     |  <----------------------------------------|
     |                 7. "Device registered"      |
     |                                           |
     |  === Later: privileged action ===          |
     |                                           |
     |  8. "Approve deployment" clicked           |
     |  ---------------------------------------->|
     |                 9. generateAuthenticationOptions()
     |                    store challenge in KV   |
     |  <----------------------------------------|
     |  10. navigator.credentials.get(options)   |
     |      [Touch ID prompt - 1 second]          |
     |  ---------------------------------------->|
     |                 11. verifyAuthentication() |
     |                     check signature vs D1  |
     |                     execute privileged action
     |  <----------------------------------------|
     |                 12. Action result           |
```

**D1 schema:**
```sql
CREATE TABLE passkey_credentials (
  id TEXT PRIMARY KEY,           -- credential ID (base64url)
  user_id TEXT NOT NULL,         -- your internal user ID
  public_key TEXT NOT NULL,      -- stored public key (base64url)
  counter INTEGER DEFAULT 0,    -- sign counter for replay detection
  transports TEXT,               -- JSON array of transports
  created_at TEXT NOT NULL,
  last_used_at TEXT
);
CREATE INDEX idx_cred_user ON passkey_credentials(user_id);
```

**rpID configuration:**
```typescript
const RP_ID = "meta-factory.ai";
const RP_NAME = "Grove Dashboard";
const EXPECTED_ORIGIN = "https://grove.meta-factory.ai";
```

---

### Sources

- [WebAuthn Resident Key: Discoverable Credentials as Passkeys](https://www.corbado.com/blog/webauthn-resident-key-discoverable-credentials-passkeys)
- [Discoverable Credentials / Resident Keys - Yubico](https://developers.yubico.com/WebAuthn/WebAuthn_Developer_Guide/Resident_Keys.html)
- [Discoverable Credentials Deep Dive - web.dev](https://web.dev/articles/webauthn-discoverable-credentials)
- [@passwordless-id/webauthn](https://webauthn.passwordless.id/)
- [@passwordless-id/webauthn - GitHub](https://github.com/passwordless-id/webauthn)
- [SimpleWebAuthn - Server Package](https://simplewebauthn.dev/docs/packages/server)
- [SimpleWebAuthn - Browser Package](https://simplewebauthn.dev/docs/packages/browser)
- [Passkeys Demo: Cloudflare Workers, KV, D1](https://github.com/nealfennimore/passkeys)
- [Passkey with React + Hono on CF Workers](https://github.com/FabioDiCeglie/Passkey)
- [WebAuthn Related Origins (ROR) Guide](https://www.corbado.com/blog/webauthn-related-origins-cross-domain-passkeys)
- [Related Origin Requests - passkeys.dev](https://passkeys.dev/docs/advanced/related-origins/)
- [Allow Passkey Reuse with Related Origin Requests - web.dev](https://web.dev/articles/webauthn-related-origin-requests)
- [WebAuthn Relying Party ID & Passkeys](https://www.corbado.com/blog/webauthn-relying-party-id-rpid-passkeys)
- [Passkeys Updates in Chrome 129](https://developer.chrome.com/blog/passkeys-updates-chrome-129)
- [FIDO Alliance - Passkeys](https://fidoalliance.org/passkeys/)
- [Understanding FIDO2, WebAuthn, and Passkeys](https://alflokken.github.io/posts/understanding-fido2-passkeys/)
- [WebAuthn vs CTAP vs FIDO2](https://www.corbado.com/blog/webauthn-vs-ctap-vs-fido2)
- [Attestation and Assertion - MDN](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Attestation_and_Assertion)
- [Implementing Passkeys with TypeScript and Web APIs](https://pilcrow.vercel.app/blog/passkeys-typescript-web-api)
- [Step-Up Authentication - Yubico](https://developers.yubico.com/WebAuthn/Concepts/Authenticator_Management/Implementation_Guidance/Step_Up_Authentication.html)
- [Web Crypto - Cloudflare Workers docs](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)
- [Windows Passkey Support - Microsoft](https://learn.microsoft.com/en-us/windows/security/identity-protection/passkeys/)
- [Passkeys in the Real World 2025](https://motasemhamdan.medium.com/passkeys-in-the-real-world-how-passwordless-actually-performs-in-2025-59b4ace29754)
- [WebAuthn Guide](https://webauthn.guide/)
- [Worker-Tools WebAuthn Example](https://github.com/worker-tools/webauthn-example)
