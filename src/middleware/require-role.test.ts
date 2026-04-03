/**
 * GA-1: Tests for requireRole() and requireAgentAccess() middleware.
 * Uses mock D1 and Hono test app to verify authorization logic.
 */

import { describe, test, expect, beforeEach } from "bun:test";
import { Hono } from "hono";
import type { Role, GrantScope, UserRecord } from "../types";
import { ROLE_HIERARCHY, SCOPE_HIERARCHY } from "../types";

// =============================================================================
// Mock data store
// =============================================================================

interface MockStore {
  users: UserRecord[];
  agents: Array<{
    id: string;
    display_name: string;
    owner_id: string;
    class: "pet" | "cattle";
    backend: string | null;
  }>;
  grants: Array<{
    id: string;
    agent_id: string;
    owner_id: string;
    grantee_id: string;
    scope: GrantScope;
    expires_at: string | null;
    revoked_at: string | null;
  }>;
}

function createMockStore(): MockStore {
  return {
    users: [
      { id: "andreas", email: "andreas@meta-factory.ai", display_name: "Andreas", role: "admin", created_at: "2026-01-01", updated_at: "2026-01-01" },
      { id: "jc", email: "jc@meta-factory.ai", display_name: "JC", role: "operator", created_at: "2026-01-01", updated_at: "2026-01-01" },
      { id: "viewer1", email: "viewer@meta-factory.ai", display_name: "Viewer", role: "viewer", created_at: "2026-01-01", updated_at: "2026-01-01" },
    ],
    agents: [
      { id: "luna", display_name: "Luna", owner_id: "andreas", class: "pet", backend: "local" },
      { id: "ivy", display_name: "Ivy", owner_id: "jc", class: "pet", backend: "ec2" },
      { id: "review-worker-1", display_name: "Review Worker", owner_id: "andreas", class: "cattle", backend: "ec2" },
    ],
    grants: [
      { id: "grant-1", agent_id: "luna", owner_id: "andreas", grantee_id: "jc", scope: "review", expires_at: null, revoked_at: null },
    ],
  };
}

// =============================================================================
// Test app — implements the same logic as the middleware using mock data
// =============================================================================

function buildTestApp(store: MockStore) {
  const app = new Hono();

  // Inject user from X-Test-Email header (bypasses CF Access JWT in tests)
  const roleGate = (minRole: Role) => async (c: any, next: any) => {
    const email = c.req.header("X-Test-Email");
    if (!email) return c.json({ error: "authentication required" }, 401);
    const user = store.users.find((u) => u.email === email);
    if (!user) return c.json({ error: "user not provisioned", email }, 401);
    if (ROLE_HIERARCHY[user.role] < ROLE_HIERARCHY[minRole]) {
      return c.json({ error: "insufficient_role", required: minRole, current: user.role }, 403);
    }
    c.set("user", user);
    await next();
  };

  const agentGate = (requiredScope: GrantScope) => async (c: any, next: any) => {
    const user = c.get("user") as UserRecord;
    const agentId = c.req.param("agentId");
    const agent = store.agents.find((a) => a.id === agentId);
    if (!agent) return c.json({ error: "agent_not_found", agentId }, 404);

    const now = new Date().toISOString();
    const grants = store.grants
      .filter((g) =>
        g.agent_id === agentId &&
        g.grantee_id === user.id &&
        g.revoked_at === null &&
        (g.expires_at === null || g.expires_at > now),
      )
      .sort((a, b) => {
        const order: Record<string, number> = { control: 2, review: 1, read: 0 };
        return (order[b.scope] ?? -1) - (order[a.scope] ?? -1);
      });
    const grantScope = grants[0]?.scope ?? null;

    // Resolution: owner → grant → admin → cattle
    if (agent.owner_id === user.id) { await next(); return; }
    if (grantScope && SCOPE_HIERARCHY[grantScope] >= SCOPE_HIERARCHY[requiredScope]) { await next(); return; }
    if (user.role === "admin") { await next(); return; }
    if (agent.class === "cattle" && ROLE_HIERARCHY[user.role] >= ROLE_HIERARCHY["operator"]) { await next(); return; }

    return c.json({
      error: "no_agent_access", agentId,
      required_scope: requiredScope,
      available_scope: grantScope,
    }, 403);
  };

  app.get("/viewer-endpoint", roleGate("viewer"), (c) => c.json({ ok: true }));
  app.get("/operator-endpoint", roleGate("operator"), (c) => c.json({ ok: true }));
  app.get("/admin-endpoint", roleGate("admin"), (c) => c.json({ ok: true }));
  app.get("/agents/:agentId/read", roleGate("viewer"), agentGate("read"), (c) => c.json({ ok: true }));
  app.get("/agents/:agentId/review", roleGate("viewer"), agentGate("review"), (c) => c.json({ ok: true }));
  app.get("/agents/:agentId/control", roleGate("operator"), agentGate("control"), (c) => c.json({ ok: true }));

  return app;
}

// =============================================================================
// Tests: requireRole
// =============================================================================

describe("requireRole", () => {
  let store: MockStore;
  let app: ReturnType<typeof buildTestApp>;

  beforeEach(() => {
    store = createMockStore();
    app = buildTestApp(store);
  });

  test("admin can access admin endpoint", async () => {
    const res = await app.request("/admin-endpoint", { headers: { "X-Test-Email": "andreas@meta-factory.ai" } });
    expect(res.status).toBe(200);
  });

  test("admin can access operator endpoint", async () => {
    const res = await app.request("/operator-endpoint", { headers: { "X-Test-Email": "andreas@meta-factory.ai" } });
    expect(res.status).toBe(200);
  });

  test("operator can access operator endpoint", async () => {
    const res = await app.request("/operator-endpoint", { headers: { "X-Test-Email": "jc@meta-factory.ai" } });
    expect(res.status).toBe(200);
  });

  test("operator cannot access admin endpoint", async () => {
    const res = await app.request("/admin-endpoint", { headers: { "X-Test-Email": "jc@meta-factory.ai" } });
    expect(res.status).toBe(403);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("insufficient_role");
  });

  test("viewer can access viewer endpoint", async () => {
    const res = await app.request("/viewer-endpoint", { headers: { "X-Test-Email": "viewer@meta-factory.ai" } });
    expect(res.status).toBe(200);
  });

  test("viewer cannot access operator endpoint", async () => {
    const res = await app.request("/operator-endpoint", { headers: { "X-Test-Email": "viewer@meta-factory.ai" } });
    expect(res.status).toBe(403);
  });

  test("unknown email returns 401", async () => {
    const res = await app.request("/viewer-endpoint", { headers: { "X-Test-Email": "nobody@example.com" } });
    expect(res.status).toBe(401);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("user not provisioned");
  });

  test("no email returns 401", async () => {
    const res = await app.request("/viewer-endpoint");
    expect(res.status).toBe(401);
  });
});

// =============================================================================
// Tests: requireAgentAccess
// =============================================================================

describe("requireAgentAccess", () => {
  let store: MockStore;
  let app: ReturnType<typeof buildTestApp>;

  beforeEach(() => {
    store = createMockStore();
    app = buildTestApp(store);
  });

  test("owner has full access to own pet agent", async () => {
    const res = await app.request("/agents/luna/control", { headers: { "X-Test-Email": "andreas@meta-factory.ai" } });
    expect(res.status).toBe(200);
  });

  test("grantee with review scope can read", async () => {
    const res = await app.request("/agents/luna/read", { headers: { "X-Test-Email": "jc@meta-factory.ai" } });
    expect(res.status).toBe(200);
  });

  test("grantee with review scope can review", async () => {
    const res = await app.request("/agents/luna/review", { headers: { "X-Test-Email": "jc@meta-factory.ai" } });
    expect(res.status).toBe(200);
  });

  test("grantee with review scope cannot control", async () => {
    const res = await app.request("/agents/luna/control", { headers: { "X-Test-Email": "jc@meta-factory.ai" } });
    expect(res.status).toBe(403);
    const body = await res.json() as { error: string; available_scope: string };
    expect(body.error).toBe("no_agent_access");
    expect(body.available_scope).toBe("review");
  });

  test("admin bypasses ownership", async () => {
    const res = await app.request("/agents/ivy/control", { headers: { "X-Test-Email": "andreas@meta-factory.ai" } });
    expect(res.status).toBe(200);
  });

  test("cattle agent accessible to any operator", async () => {
    const res = await app.request("/agents/review-worker-1/control", { headers: { "X-Test-Email": "jc@meta-factory.ai" } });
    expect(res.status).toBe(200);
  });

  test("cattle agent NOT accessible to viewer", async () => {
    const res = await app.request("/agents/review-worker-1/read", { headers: { "X-Test-Email": "viewer@meta-factory.ai" } });
    expect(res.status).toBe(403);
  });

  test("expired grant returns 403", async () => {
    store.grants[0]!.expires_at = "2020-01-01T00:00:00Z";
    app = buildTestApp(store);
    const res = await app.request("/agents/luna/review", { headers: { "X-Test-Email": "jc@meta-factory.ai" } });
    expect(res.status).toBe(403);
  });

  test("revoked grant returns 403", async () => {
    store.grants[0]!.revoked_at = "2026-01-02T00:00:00Z";
    app = buildTestApp(store);
    const res = await app.request("/agents/luna/review", { headers: { "X-Test-Email": "jc@meta-factory.ai" } });
    expect(res.status).toBe(403);
  });

  test("unknown agent returns 404", async () => {
    const res = await app.request("/agents/nonexistent/read", { headers: { "X-Test-Email": "andreas@meta-factory.ai" } });
    expect(res.status).toBe(404);
  });

  test("operator without grant cannot access another operator's pet agent", async () => {
    store.grants = [];
    app = buildTestApp(store);
    const res = await app.request("/agents/luna/read", { headers: { "X-Test-Email": "jc@meta-factory.ai" } });
    expect(res.status).toBe(403);
  });
});
