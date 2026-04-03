<!-- Generated from metafactory ecosystem template. Customize sections marked with {PLACEHOLDER}. -->

# grove-auth -- Authentication, authorization, and device trust for the metafactory ecosystem

Authentication, authorization, and device trust for the metafactory ecosystem

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


## Naming

- **metafactory** -- always lowercase, one word. Not "Metafactory", not "Meta Factory". The GitHub org is `the-metafactory`, the repo name may be hyphenated (technical constraint), and the domains are `meta-factory.ai/.dev/.io` (DNS constraint). But the brand name is always `metafactory`.

## Critical Rules

- NEVER describe code you haven't read. Use Read/Glob/Grep to verify before making claims.
- NEVER fabricate file names, class names, or architecture. If unsure, read the source.
- Fix ALL errors found during type checks, tests, or linting -- even if pre-existing or introduced by another developer. Never dismiss errors as "not from our changes." If you see it, fix it.
- Before fixing a bug or implementing a feature, ALWAYS check open PRs (`gh pr list`) and issues (`gh issue list`) first. Someone may already be working on it, or there may be a PR ready to merge that addresses it. Don't duplicate work -- review what exists before racing to write code.

- NEVER store private keys, secrets, or credentials in code or config files. Use CF Worker Secrets and KV.
- NEVER skip step-up verification for privileged actions, even in development. Use a test authenticator if needed.
- NEVER fall back to "no auth" if a verification step fails. Fail closed, not open.
- WebAuthn challenges MUST be single-use. Always delete from KV after verification.
- Action tokens MUST have both expiry (exp) and nonce (jti). Verify both on every use.


## GitHub Labels (ecosystem standard)

All metafactory ecosystem repos use a shared label set. Do not create ad-hoc labels.

| Label | Description | Color | Purpose |
|-------|-------------|-------|---------|
| `bug` | Something isn't working | `#d73a4a` | Defect tracking |
| `documentation` | Improvements or additions to documentation | `#0075ca` | Docs work |
| `feature` | Feature specification | `#1D76DB` | Feature work |
| `infrastructure` | Cross-cutting infrastructure work | `#5319E7` | Infra/tooling |
| `now` | Currently being worked | `#0E8A16` | Priority: active |
| `next` | Next up after current work | `#FBCA04` | Priority: queued |
| `future` | Planned but not yet scheduled | `#C5DEF5` | Priority: backlog |
| `handover` | NZ/EU timezone bridge -- work session summary | `#F9D0C4` | Async handoffs |



Every issue must have at least one type label (`bug`, `feature`, `infrastructure`, `documentation`) and one priority label (`now`, `next`, `future`) if open.

## GitHub Issue Tracking
When working on a GitHub issue in this repo, keep the issue updated as you work. This is default agent behavior, not optional.

**On starting work:**
- Comment on the issue: what you're working on, which sub-task
- Example: `gh issue comment 1 --body "Starting: implement initial project structure"`

**During work:**
- When a sub-task checkbox is completed, tick it on the issue
- When you create a PR, link it to the issue (use `closes #N` or `gh pr create` with issue reference)

**On completing work:**
- Comment with a summary: what was done, what changed, any follow-up needed
- Tick completed checkboxes on both the GitHub issue AND any iteration plans
- If all checkboxes are done, close the issue

**Why:** GitHub is the shared collaboration surface. Team members and agents all read it. If you do work but don't update the issue, it looks like nothing happened.

## Standard Operating Procedures

This repo follows ecosystem SOPs defined in [compass](https://github.com/the-metafactory/compass). **Before starting work, identify which SOPs apply and Read them. Output the pre-flight line from each loaded SOP.**

| SOP | Activate when | File |
|-----|--------------|------|
| **Dev pipeline** | Creating branches, making PRs, starting any feature/fix work | `compass/sops/dev-pipeline.md` |
| **Versioning** | After merging PRs, before deploying, any version bump | `compass/sops/versioning.md` |
| **Worktree discipline** | Starting feature work (always — even solo) | `compass/sops/worktree-discipline.md` |
| **Design process** | Creating specs, design docs, or research docs | `compass/sops/design-process.md` |
| **Retrospective** | Post-work review, extracting process patterns | `compass/sops/retrospective-and-process-mining.md` |
| **New repo** | Bootstrapping a new repository in the ecosystem | `compass/sops/new-repo.md` |
| **PR review** | Reviewing a PR, before approving or merging | `compass/sops/pr-review.md` |

### Examples

**Starting a feature:**
```
Task: "Add a dashboard panel"
→ Activate: dev-pipeline + worktree
→ Read both SOPs
→ Output: "SOP: dev-pipeline | Branch: feat/g-300-panel | Prefix: feat:"
→ Output: "SOP: worktree | Worktree: ../grove-auth-panel | Branch: feat/g-300-panel | Main: untouched"
```

**After merging a PR:**
```
Task: "Merge PR #42"
→ After merge, activate: versioning
→ Read SOP
→ Output: "SOP: versioning | Current: v0.2.0 | Bump: patch → v0.2.1"
```


## Blueprint-Driven Development

All ecosystem repos track features in `blueprint.yaml`. Before starting feature work, check the dependency graph:

```bash
# What's ready to work on? (dependencies satisfied)
blueprint ready

# Claim a feature
blueprint update grove-auth:{ID} --status in-progress

# After PR merges
blueprint update grove-auth:{ID} --status done
blueprint lint   # Validate graph integrity
```

**Statuses:** Only `planned`, `in-progress`, and `done` are settable. `ready`, `blocked`, and `next` are computed from the dependency graph.

**Cross-repo dependencies:** Use `{repo}:{ID}` format (e.g., `grove:G-200`, `arc:A-100`). A feature is `blocked` if any dependency in another repo isn't `done`.

## Versioning & Releases

See `compass/sops/versioning.md` for the full procedure. Key repo-specific details:

- Version source of truth: `arc-manifest.yaml`
- Release title format: `"grove-auth vX.Y.Z -- Short Description"`
- Deploy command: `arc upgrade grove-auth`


## Multi-Agent Worktree Discipline

See `compass/sops/worktree-discipline.md` for the full procedure. Key repo-specific details:

- Worktree directory pattern: `../grove-auth-{slug}`
- Example: `git worktree add ../grove-auth-feature -b feat/{branch-name} main`

## Bun

Default to using Bun instead of Node.js.

- Use `bun <file>` instead of `node <file>` or `ts-node <file>`
- Use `bun test` instead of `jest` or `vitest`
- Use `bun build` instead of `webpack` or `esbuild`
- Use `bun install` instead of `npm install` or `yarn install` or `pnpm install`
- Use `bun run <script>` instead of `npm run <script>`
- Use `bunx <package> <command>` instead of `npx <package> <command>`
- Bun automatically loads .env, so don't use dotenv.
