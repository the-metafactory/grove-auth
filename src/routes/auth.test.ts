/**
 * GA-1 (1.5): Tests for auth API route group.
 * Uses a mock D1 and injects user identity via X-Test-Email header.
 */

import { describe, test, expect, beforeEach } from "bun:test";
import { Hono } from "hono";
import type { UserRecord, GrantScope } from "../types";
import { checkRole } from "../authorize";

// =============================================================================
// Mock data store + test app
// =============================================================================

interface MockStore {
  users: UserRecord[];
  agents: Array<{ id: string; display_name: string; owner_id: string; class: "pet" | "cattle"; backend: string | null; spawn_profile: string | null; created_at: string }>;
  grants: Array<{ id: string; agent_id: string; owner_id: string; grantee_id: string; scope: GrantScope; requires_stepup: number; expires_at: string | null; created_at: string; revoked_at: string | null }>;
}

function defaultStore(): MockStore {
  return {
    users: [
      { id: "andreas", email: "andreas@meta-factory.ai", display_name: "Andreas", role: "admin", created_at: "2026-01-01", updated_at: "2026-01-01" },
      { id: "jc", email: "jc@meta-factory.ai", display_name: "JC", role: "operator", created_at: "2026-01-01", updated_at: "2026-01-01" },
      { id: "viewer1", email: "viewer@meta-factory.ai", display_name: "Viewer", role: "viewer", created_at: "2026-01-01", updated_at: "2026-01-01" },
    ],
    agents: [
      { id: "luna", display_name: "Luna", owner_id: "andreas", class: "pet", backend: "local", spawn_profile: null, created_at: "2026-01-01" },
      { id: "ivy", display_name: "Ivy", owner_id: "jc", class: "pet", backend: "ec2", spawn_profile: null, created_at: "2026-01-01" },
      { id: "review-worker", display_name: "Review Worker", owner_id: "andreas", class: "cattle", backend: "ec2", spawn_profile: null, created_at: "2026-01-01" },
    ],
    grants: [
      { id: "grant-1", agent_id: "luna", owner_id: "andreas", grantee_id: "jc", scope: "review", requires_stepup: 1, expires_at: null, created_at: "2026-01-01", revoked_at: null },
    ],
  };
}

/**
 * Build a test Hono app that mirrors the auth route logic using the mock store.
 * This tests the actual route structure and uses checkRole() from production code.
 */
function buildTestApp(store: MockStore) {
  const app = new Hono();

  // Auth middleware — inject user from X-Test-Email
  app.use("/api/auth/*", async (c: any, next: any) => {
    const email = c.req.header("X-Test-Email");
    if (!email) return c.json({ error: "authentication required" }, 401);
    const user = store.users.find((u) => u.email === email);
    if (!user) return c.json({ error: "user not provisioned", email }, 401);
    c.set("user", user);
    await next();
  });

  // GET /api/auth/me
  app.get("/api/auth/me", (c: any) => {
    const user = c.get("user") as UserRecord;
    const agents = store.agents.filter((a) => a.owner_id === user.id);
    const now = new Date().toISOString();
    const received = store.grants.filter((g) => g.grantee_id === user.id && !g.revoked_at && (!g.expires_at || g.expires_at > now));
    const given = store.grants.filter((g) => g.owner_id === user.id && !g.revoked_at);
    return c.json({ user, agents, grants: { received, given } });
  });

  // GET /api/auth/users (admin only — uses production checkRole)
  app.get("/api/auth/users", (c: any) => {
    const user = c.get("user") as UserRecord;
    const result = checkRole(user.role, "admin");
    if (!result.allowed) return c.json({ error: result.error, required: result.required, current: result.current }, 403);
    return c.json({ users: store.users });
  });

  // PUT /api/auth/users/:id/role (admin only)
  app.put("/api/auth/users/:id/role", async (c: any) => {
    const caller = c.get("user") as UserRecord;
    const result = checkRole(caller.role, "admin");
    if (!result.allowed) return c.json({ error: result.error, required: result.required, current: result.current }, 403);
    const targetId = c.req.param("id");
    const body = await c.req.json().catch(() => null);
    if (!body?.role || !["viewer", "operator", "admin"].includes(body.role)) return c.json({ error: "invalid role" }, 400);
    const target = store.users.find((u) => u.id === targetId);
    if (!target) return c.json({ error: "user_not_found" }, 404);
    const prev = target.role;
    target.role = body.role;
    return c.json({ ok: true, id: targetId, previous_role: prev, new_role: body.role });
  });

  // GET /api/auth/agents (context-filtered)
  app.get("/api/auth/agents", (c: any) => {
    const user = c.get("user") as UserRecord;
    if (user.role === "admin") return c.json({ agents: store.agents });
    const now = new Date().toISOString();
    const owned = store.agents.filter((a) => a.owner_id === user.id);
    const delegated = store.agents.filter((a) => store.grants.some((g) => g.agent_id === a.id && g.grantee_id === user.id && !g.revoked_at && (!g.expires_at || g.expires_at > now)));
    const cattle = store.agents.filter((a) => a.class === "cattle");
    return c.json({ owned, delegated, cattle });
  });

  // GET /api/auth/agents/:agentId
  app.get("/api/auth/agents/:agentId", (c: any) => {
    const agentId = c.req.param("agentId");
    const agent = store.agents.find((a) => a.id === agentId);
    if (!agent) return c.json({ error: "agent_not_found", agentId }, 404);
    const owner = store.users.find((u) => u.id === agent.owner_id);
    const grants = store.grants.filter((g) => g.agent_id === agentId && !g.revoked_at);
    return c.json({ agent, owner, grants });
  });

  // POST /api/auth/agents/:agentId/grants
  app.post("/api/auth/agents/:agentId/grants", async (c: any) => {
    const caller = c.get("user") as UserRecord;
    const agentId = c.req.param("agentId");
    const agent = store.agents.find((a) => a.id === agentId);
    if (!agent) return c.json({ error: "agent_not_found" }, 404);
    if (agent.owner_id !== caller.id && caller.role !== "admin") return c.json({ error: "only owner or admin can create grants" }, 403);
    const body = await c.req.json().catch(() => null);
    if (!body?.grantee_id || !body?.scope) return c.json({ error: "grantee_id and scope are required" }, 400);
    if (!["read", "review", "control"].includes(body.scope)) return c.json({ error: "invalid scope" }, 400);
    const grantee = store.users.find((u) => u.id === body.grantee_id);
    if (!grantee) return c.json({ error: "grantee_not_found" }, 404);
    const grantId = `grant-${Date.now()}`;
    store.grants.push({ id: grantId, agent_id: agentId, owner_id: agent.owner_id, grantee_id: body.grantee_id, scope: body.scope, requires_stepup: 1, expires_at: body.expires_at ?? null, created_at: new Date().toISOString(), revoked_at: null });
    return c.json({ ok: true, grant_id: grantId }, 201);
  });

  // DELETE /api/auth/grants/:grantId
  app.delete("/api/auth/grants/:grantId", (c: any) => {
    const caller = c.get("user") as UserRecord;
    const grantId = c.req.param("grantId");
    const grant = store.grants.find((g) => g.id === grantId);
    if (!grant) return c.json({ error: "grant_not_found" }, 404);
    if (grant.revoked_at) return c.json({ error: "grant_already_revoked" }, 409);
    if (grant.owner_id !== caller.id && caller.role !== "admin") return c.json({ error: "only owner or admin can revoke grants" }, 403);
    grant.revoked_at = new Date().toISOString();
    return c.json({ ok: true, grantId, revoked: true });
  });

  return app;
}

// =============================================================================
// Tests
// =============================================================================

describe("/api/auth/me", () => {
  test("returns user profile with agents and grants", async () => {
    const app = buildTestApp(defaultStore());
    const res = await app.request("/api/auth/me", { headers: { "X-Test-Email": "andreas@meta-factory.ai" } });
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.user.id).toBe("andreas");
    expect(body.agents.length).toBe(2); // luna + review-worker
    expect(body.grants.given.length).toBe(1); // grant to jc
  });

  test("unauthenticated → 401", async () => {
    const app = buildTestApp(defaultStore());
    expect((await app.request("/api/auth/me")).status).toBe(401);
  });
});

describe("/api/auth/users", () => {
  test("admin sees all users", async () => {
    const app = buildTestApp(defaultStore());
    const res = await app.request("/api/auth/users", { headers: { "X-Test-Email": "andreas@meta-factory.ai" } });
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.users.length).toBe(3);
  });

  test("operator → 403", async () => {
    const app = buildTestApp(defaultStore());
    const res = await app.request("/api/auth/users", { headers: { "X-Test-Email": "jc@meta-factory.ai" } });
    expect(res.status).toBe(403);
  });

  test("viewer → 403", async () => {
    const app = buildTestApp(defaultStore());
    const res = await app.request("/api/auth/users", { headers: { "X-Test-Email": "viewer@meta-factory.ai" } });
    expect(res.status).toBe(403);
  });
});

describe("PUT /api/auth/users/:id/role", () => {
  test("admin changes role", async () => {
    const app = buildTestApp(defaultStore());
    const res = await app.request("/api/auth/users/jc/role", {
      method: "PUT",
      headers: { "X-Test-Email": "andreas@meta-factory.ai", "Content-Type": "application/json" },
      body: JSON.stringify({ role: "admin" }),
    });
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.previous_role).toBe("operator");
    expect(body.new_role).toBe("admin");
  });

  test("operator cannot change roles", async () => {
    const app = buildTestApp(defaultStore());
    const res = await app.request("/api/auth/users/viewer1/role", {
      method: "PUT",
      headers: { "X-Test-Email": "jc@meta-factory.ai", "Content-Type": "application/json" },
      body: JSON.stringify({ role: "operator" }),
    });
    expect(res.status).toBe(403);
  });

  test("invalid role → 400", async () => {
    const app = buildTestApp(defaultStore());
    const res = await app.request("/api/auth/users/jc/role", {
      method: "PUT",
      headers: { "X-Test-Email": "andreas@meta-factory.ai", "Content-Type": "application/json" },
      body: JSON.stringify({ role: "superadmin" }),
    });
    expect(res.status).toBe(400);
  });
});

describe("/api/auth/agents", () => {
  test("admin sees all agents", async () => {
    const app = buildTestApp(defaultStore());
    const res = await app.request("/api/auth/agents", { headers: { "X-Test-Email": "andreas@meta-factory.ai" } });
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.agents.length).toBe(3);
  });

  test("operator sees own + delegated + cattle", async () => {
    const app = buildTestApp(defaultStore());
    const res = await app.request("/api/auth/agents", { headers: { "X-Test-Email": "jc@meta-factory.ai" } });
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.owned.length).toBe(1); // ivy
    expect(body.delegated.length).toBe(1); // luna (via grant)
    expect(body.cattle.length).toBe(1); // review-worker
  });
});

describe("/api/auth/agents/:agentId", () => {
  test("returns agent detail with owner and grants", async () => {
    const app = buildTestApp(defaultStore());
    const res = await app.request("/api/auth/agents/luna", { headers: { "X-Test-Email": "andreas@meta-factory.ai" } });
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.agent.id).toBe("luna");
    expect(body.owner.id).toBe("andreas");
    expect(body.grants.length).toBe(1);
  });

  test("unknown agent → 404", async () => {
    const app = buildTestApp(defaultStore());
    const res = await app.request("/api/auth/agents/nonexistent", { headers: { "X-Test-Email": "andreas@meta-factory.ai" } });
    expect(res.status).toBe(404);
  });
});

describe("POST /api/auth/agents/:agentId/grants", () => {
  test("owner creates grant", async () => {
    const app = buildTestApp(defaultStore());
    const res = await app.request("/api/auth/agents/luna/grants", {
      method: "POST",
      headers: { "X-Test-Email": "andreas@meta-factory.ai", "Content-Type": "application/json" },
      body: JSON.stringify({ grantee_id: "viewer1", scope: "read" }),
    });
    expect(res.status).toBe(201);
    const body = await res.json() as any;
    expect(body.ok).toBe(true);
  });

  test("non-owner non-admin → 403", async () => {
    const app = buildTestApp(defaultStore());
    const res = await app.request("/api/auth/agents/luna/grants", {
      method: "POST",
      headers: { "X-Test-Email": "jc@meta-factory.ai", "Content-Type": "application/json" },
      body: JSON.stringify({ grantee_id: "viewer1", scope: "read" }),
    });
    expect(res.status).toBe(403);
  });

  test("admin can create grant on any agent", async () => {
    const app = buildTestApp(defaultStore());
    const res = await app.request("/api/auth/agents/ivy/grants", {
      method: "POST",
      headers: { "X-Test-Email": "andreas@meta-factory.ai", "Content-Type": "application/json" },
      body: JSON.stringify({ grantee_id: "viewer1", scope: "read" }),
    });
    expect(res.status).toBe(201);
  });

  test("missing fields → 400", async () => {
    const app = buildTestApp(defaultStore());
    const res = await app.request("/api/auth/agents/luna/grants", {
      method: "POST",
      headers: { "X-Test-Email": "andreas@meta-factory.ai", "Content-Type": "application/json" },
      body: JSON.stringify({ grantee_id: "viewer1" }),
    });
    expect(res.status).toBe(400);
  });
});

describe("DELETE /api/auth/grants/:grantId", () => {
  test("owner revokes grant", async () => {
    const app = buildTestApp(defaultStore());
    const res = await app.request("/api/auth/grants/grant-1", {
      method: "DELETE",
      headers: { "X-Test-Email": "andreas@meta-factory.ai" },
    });
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.revoked).toBe(true);
  });

  test("non-owner non-admin → 403", async () => {
    const app = buildTestApp(defaultStore());
    const res = await app.request("/api/auth/grants/grant-1", {
      method: "DELETE",
      headers: { "X-Test-Email": "jc@meta-factory.ai" },
    });
    expect(res.status).toBe(403);
  });

  test("unknown grant → 404", async () => {
    const app = buildTestApp(defaultStore());
    const res = await app.request("/api/auth/grants/nonexistent", {
      method: "DELETE",
      headers: { "X-Test-Email": "andreas@meta-factory.ai" },
    });
    expect(res.status).toBe(404);
  });

  test("already revoked → 409", async () => {
    const store = defaultStore();
    store.grants[0]!.revoked_at = "2026-01-02";
    const app = buildTestApp(store);
    const res = await app.request("/api/auth/grants/grant-1", {
      method: "DELETE",
      headers: { "X-Test-Email": "andreas@meta-factory.ai" },
    });
    expect(res.status).toBe(409);
  });
});
