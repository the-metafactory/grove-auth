/**
 * GA-1: Tests for authorization logic and middleware integration.
 * Tests exercise the actual checkRole() and checkAgentAccess() functions
 * from authorize.ts — the same code paths used by production middleware.
 */

import { describe, test, expect, beforeEach } from "bun:test";
import { Hono } from "hono";
import { checkRole, checkAgentAccess } from "../authorize";
import type { Role, GrantScope, UserRecord, AgentClass } from "../types";

// =============================================================================
// Unit tests: checkRole() — pure function from authorize.ts
// =============================================================================

describe("checkRole", () => {
  test("admin meets admin requirement", () => {
    const result = checkRole("admin", "admin");
    expect(result.allowed).toBe(true);
  });

  test("admin meets operator requirement", () => {
    const result = checkRole("admin", "operator");
    expect(result.allowed).toBe(true);
  });

  test("admin meets viewer requirement", () => {
    const result = checkRole("admin", "viewer");
    expect(result.allowed).toBe(true);
  });

  test("operator meets operator requirement", () => {
    const result = checkRole("operator", "operator");
    expect(result.allowed).toBe(true);
  });

  test("operator does not meet admin requirement", () => {
    const result = checkRole("operator", "admin");
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.error).toBe("insufficient_role");
      expect(result.required).toBe("admin");
      expect(result.current).toBe("operator");
    }
  });

  test("viewer meets viewer requirement", () => {
    const result = checkRole("viewer", "viewer");
    expect(result.allowed).toBe(true);
  });

  test("viewer does not meet operator requirement", () => {
    const result = checkRole("viewer", "operator");
    expect(result.allowed).toBe(false);
  });

  test("viewer does not meet admin requirement", () => {
    const result = checkRole("viewer", "admin");
    expect(result.allowed).toBe(false);
  });
});

// =============================================================================
// Unit tests: checkAgentAccess() — pure function from authorize.ts
// =============================================================================

describe("checkAgentAccess", () => {
  test("owner has full access to own pet agent", () => {
    const result = checkAgentAccess({
      userId: "andreas", userRole: "operator",
      agentOwnerId: "andreas", agentClass: "pet",
      grantScope: null, requiredScope: "control",
    });
    expect(result.allowed).toBe(true);
    if (result.allowed) {
      expect(result.resolution).toBe("owner");
      expect(result.availableScope).toBe("control");
    }
  });

  test("grantee with review scope can read", () => {
    const result = checkAgentAccess({
      userId: "jc", userRole: "operator",
      agentOwnerId: "andreas", agentClass: "pet",
      grantScope: "review", requiredScope: "read",
    });
    expect(result.allowed).toBe(true);
    if (result.allowed) expect(result.resolution).toBe("grant");
  });

  test("grantee with review scope can review", () => {
    const result = checkAgentAccess({
      userId: "jc", userRole: "operator",
      agentOwnerId: "andreas", agentClass: "pet",
      grantScope: "review", requiredScope: "review",
    });
    expect(result.allowed).toBe(true);
    if (result.allowed) expect(result.resolution).toBe("grant");
  });

  test("grantee with review scope cannot control", () => {
    const result = checkAgentAccess({
      userId: "jc", userRole: "operator",
      agentOwnerId: "andreas", agentClass: "pet",
      grantScope: "review", requiredScope: "control",
    });
    expect(result.allowed).toBe(false);
    if (!result.allowed) expect(result.availableScope).toBe("review");
  });

  test("admin bypasses ownership", () => {
    const result = checkAgentAccess({
      userId: "andreas", userRole: "admin",
      agentOwnerId: "jc", agentClass: "pet",
      grantScope: null, requiredScope: "control",
    });
    expect(result.allowed).toBe(true);
    if (result.allowed) expect(result.resolution).toBe("admin");
  });

  test("cattle agent accessible to any operator", () => {
    const result = checkAgentAccess({
      userId: "jc", userRole: "operator",
      agentOwnerId: "andreas", agentClass: "cattle",
      grantScope: null, requiredScope: "control",
    });
    expect(result.allowed).toBe(true);
    if (result.allowed) expect(result.resolution).toBe("cattle");
  });

  test("cattle agent NOT accessible to viewer", () => {
    const result = checkAgentAccess({
      userId: "viewer1", userRole: "viewer",
      agentOwnerId: "andreas", agentClass: "cattle",
      grantScope: null, requiredScope: "read",
    });
    expect(result.allowed).toBe(false);
  });

  test("no grant on pet agent → denied", () => {
    const result = checkAgentAccess({
      userId: "jc", userRole: "operator",
      agentOwnerId: "andreas", agentClass: "pet",
      grantScope: null, requiredScope: "read",
    });
    expect(result.allowed).toBe(false);
    if (!result.allowed) expect(result.availableScope).toBeNull();
  });

  test("grant with read scope cannot review", () => {
    const result = checkAgentAccess({
      userId: "jc", userRole: "operator",
      agentOwnerId: "andreas", agentClass: "pet",
      grantScope: "read", requiredScope: "review",
    });
    expect(result.allowed).toBe(false);
    if (!result.allowed) expect(result.availableScope).toBe("read");
  });

  test("control grant gives full access", () => {
    const result = checkAgentAccess({
      userId: "jc", userRole: "operator",
      agentOwnerId: "andreas", agentClass: "pet",
      grantScope: "control", requiredScope: "control",
    });
    expect(result.allowed).toBe(true);
    if (result.allowed) {
      expect(result.resolution).toBe("grant");
      expect(result.availableScope).toBe("control");
    }
  });
});

// =============================================================================
// Integration tests: middleware wiring with Hono test app
// Uses checkRole/checkAgentAccess from production code via mock middleware
// =============================================================================

interface MockStore {
  users: UserRecord[];
  agents: Array<{ id: string; owner_id: string; class: AgentClass }>;
  grants: Array<{ agent_id: string; grantee_id: string; scope: GrantScope; expires_at: string | null; revoked_at: string | null }>;
}

function buildTestApp(store: MockStore) {
  const app = new Hono();

  // Role middleware using production checkRole()
  const roleMiddleware = (minRole: Role) => async (c: any, next: any) => {
    const email = c.req.header("X-Test-Email");
    if (!email) return c.json({ error: "authentication required" }, 401);
    const user = store.users.find((u) => u.email === email);
    if (!user) return c.json({ error: "user not provisioned", email }, 401);
    const result = checkRole(user.role, minRole);
    if (!result.allowed) return c.json({ error: result.error, required: result.required, current: result.current }, 403);
    c.set("user", user);
    await next();
  };

  // Agent middleware using production checkAgentAccess()
  const agentMiddleware = (requiredScope: GrantScope) => async (c: any, next: any) => {
    const user = c.get("user") as UserRecord;
    const agentId = c.req.param("agentId");
    const agent = store.agents.find((a) => a.id === agentId);
    if (!agent) return c.json({ error: "agent_not_found", agentId }, 404);

    const now = new Date().toISOString();
    const bestGrant = store.grants
      .filter((g) => g.agent_id === agentId && g.grantee_id === user.id && !g.revoked_at && (!g.expires_at || g.expires_at > now))
      .sort((a, b) => { const o: Record<string, number> = { control: 2, review: 1, read: 0 }; return (o[b.scope] ?? -1) - (o[a.scope] ?? -1); })[0];

    const result = checkAgentAccess({
      userId: user.id, userRole: user.role,
      agentOwnerId: agent.owner_id, agentClass: agent.class,
      grantScope: bestGrant?.scope ?? null, requiredScope,
    });

    if (!result.allowed) return c.json({ error: result.error, agentId, required_scope: requiredScope, available_scope: result.availableScope }, 403);
    await next();
  };

  app.get("/admin-endpoint", roleMiddleware("admin"), (c) => c.json({ ok: true }));
  app.get("/operator-endpoint", roleMiddleware("operator"), (c) => c.json({ ok: true }));
  app.get("/viewer-endpoint", roleMiddleware("viewer"), (c) => c.json({ ok: true }));
  app.get("/agents/:agentId/control", roleMiddleware("operator"), agentMiddleware("control"), (c) => c.json({ ok: true }));
  app.get("/agents/:agentId/review", roleMiddleware("viewer"), agentMiddleware("review"), (c) => c.json({ ok: true }));
  app.get("/agents/:agentId/read", roleMiddleware("viewer"), agentMiddleware("read"), (c) => c.json({ ok: true }));

  return app;
}

describe("middleware integration", () => {
  const store: MockStore = {
    users: [
      { id: "andreas", email: "andreas@meta-factory.ai", display_name: "Andreas", role: "admin", created_at: "2026-01-01", updated_at: "2026-01-01" },
      { id: "jc", email: "jc@meta-factory.ai", display_name: "JC", role: "operator", created_at: "2026-01-01", updated_at: "2026-01-01" },
      { id: "viewer1", email: "viewer@meta-factory.ai", display_name: "Viewer", role: "viewer", created_at: "2026-01-01", updated_at: "2026-01-01" },
    ],
    agents: [
      { id: "luna", owner_id: "andreas", class: "pet" },
      { id: "review-worker-1", owner_id: "andreas", class: "cattle" },
    ],
    grants: [
      { agent_id: "luna", grantee_id: "jc", scope: "review", expires_at: null, revoked_at: null },
    ],
  };

  let app: ReturnType<typeof buildTestApp>;
  beforeEach(() => { app = buildTestApp(JSON.parse(JSON.stringify(store))); });

  test("no email → 401", async () => {
    expect((await app.request("/viewer-endpoint")).status).toBe(401);
  });

  test("unknown email → 401", async () => {
    expect((await app.request("/viewer-endpoint", { headers: { "X-Test-Email": "nobody@x.com" } })).status).toBe(401);
  });

  test("operator → admin endpoint → 403", async () => {
    expect((await app.request("/admin-endpoint", { headers: { "X-Test-Email": "jc@meta-factory.ai" } })).status).toBe(403);
  });

  test("owner controls own pet agent", async () => {
    expect((await app.request("/agents/luna/control", { headers: { "X-Test-Email": "andreas@meta-factory.ai" } })).status).toBe(200);
  });

  test("grantee reviews delegated pet agent", async () => {
    expect((await app.request("/agents/luna/review", { headers: { "X-Test-Email": "jc@meta-factory.ai" } })).status).toBe(200);
  });

  test("grantee cannot control delegated pet agent", async () => {
    expect((await app.request("/agents/luna/control", { headers: { "X-Test-Email": "jc@meta-factory.ai" } })).status).toBe(403);
  });

  test("operator accesses cattle agent", async () => {
    expect((await app.request("/agents/review-worker-1/control", { headers: { "X-Test-Email": "jc@meta-factory.ai" } })).status).toBe(200);
  });

  test("viewer cannot access cattle agent", async () => {
    expect((await app.request("/agents/review-worker-1/read", { headers: { "X-Test-Email": "viewer@meta-factory.ai" } })).status).toBe(403);
  });
});
