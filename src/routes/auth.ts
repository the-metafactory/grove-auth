/**
 * GA-1 (1.5): Auth API route group.
 * Exported as a Hono app for mounting by the consuming Worker.
 *
 * Endpoints:
 *   GET  /api/auth/me                    — current user profile + agents + grants
 *   GET  /api/auth/users                 — list all users (admin)
 *   PUT  /api/auth/users/:id/role        — change user role (admin)
 *   GET  /api/auth/agents                — list agents (context-filtered)
 *   GET  /api/auth/agents/:agentId       — agent detail
 *   POST /api/auth/agents/:agentId/grants — create grant (owner/admin)
 *   GET  /api/auth/agents/:agentId/grants — list grants for agent
 *   DELETE /api/auth/grants/:grantId     — revoke grant
 *
 * Design: grove-auth/docs/design-auth-aaa.md v2
 */

import { Hono } from "hono";
import type { AuthBindings, GrantScope, Role, UserRecord } from "../types";
import { ROLE_HIERARCHY } from "../types";
import { checkRole } from "../authorize";
import { logAuditEvent, getClientIp } from "../middleware/audit";
import { getCfAccessEmail } from "../middleware/cf-access";
import { getUserByEmail } from "../middleware/require-role";

type AuthEnv = { Bindings: AuthBindings; Variables: { user: UserRecord } };

export const authRoutes = new Hono<AuthEnv>();

// ---------------------------------------------------------------------------
// Inline auth middleware for this route group
// Extracts user from CF Access JWT → D1 lookup → sets c.var.user
// ---------------------------------------------------------------------------

authRoutes.use("/api/auth/*", async (c, next) => {
  const ip = getClientIp(c);
  const endpoint = new URL(c.req.url).pathname;
  const method = c.req.method;

  const email = await getCfAccessEmail(c.env, c.req);
  if (!email) {
    logAuditEvent(c.env.GROVE_DB, {
      eventType: "auth_api", result: "failure", ip, endpoint, method,
      detail: "no CF Access identity",
    });
    return c.json({ error: "authentication required" }, 401);
  }

  const user = await getUserByEmail(c.env.GROVE_DB, email);
  if (!user) {
    logAuditEvent(c.env.GROVE_DB, {
      eventType: "auth_api", result: "failure", ip, endpoint, method,
      identity: email, detail: "user not provisioned",
    });
    return c.json({ error: "user not provisioned", email }, 401);
  }

  c.set("user", user);
  await next();
});

// ---------------------------------------------------------------------------
// GET /api/auth/me — current user profile
// ---------------------------------------------------------------------------

authRoutes.get("/api/auth/me", async (c) => {
  const user = c.get("user");
  const db = c.env.GROVE_DB;

  const [ownedAgents, receivedGrants, givenGrants] = await Promise.all([
    db.prepare("SELECT * FROM agents WHERE owner_id = ?").bind(user.id).all(),
    db.prepare(`
      SELECT g.*, a.display_name AS agent_name
      FROM agent_grants g JOIN agents a ON g.agent_id = a.id
      WHERE g.grantee_id = ? AND g.revoked_at IS NULL
      AND (g.expires_at IS NULL OR g.expires_at > datetime('now'))
    `).bind(user.id).all(),
    db.prepare(`
      SELECT g.*, a.display_name AS agent_name
      FROM agent_grants g JOIN agents a ON g.agent_id = a.id
      WHERE g.owner_id = ? AND g.revoked_at IS NULL
    `).bind(user.id).all(),
  ]);

  return c.json({
    user,
    agents: ownedAgents.results,
    grants: {
      received: receivedGrants.results,
      given: givenGrants.results,
    },
  });
});

// ---------------------------------------------------------------------------
// GET /api/auth/users — list all users (admin only)
// ---------------------------------------------------------------------------

authRoutes.get("/api/auth/users", async (c) => {
  const user = c.get("user");
  const result = checkRole(user.role, "admin");
  if (!result.allowed) {
    return c.json({ error: result.error, required: result.required, current: result.current }, 403);
  }

  const users = await c.env.GROVE_DB.prepare("SELECT * FROM users ORDER BY created_at").all();
  return c.json({ users: users.results });
});

// ---------------------------------------------------------------------------
// PUT /api/auth/users/:id/role — change user role (admin only)
// ---------------------------------------------------------------------------

authRoutes.put("/api/auth/users/:id/role", async (c) => {
  const caller = c.get("user");
  const result = checkRole(caller.role, "admin");
  if (!result.allowed) {
    return c.json({ error: result.error, required: result.required, current: result.current }, 403);
  }

  const targetId = c.req.param("id");
  const body = await c.req.json<{ role: Role }>().catch(() => null);
  if (!body?.role || !["viewer", "operator", "admin"].includes(body.role)) {
    return c.json({ error: "invalid role", valid: ["viewer", "operator", "admin"] }, 400);
  }

  const target = await c.env.GROVE_DB.prepare("SELECT * FROM users WHERE id = ?").bind(targetId).first<UserRecord>();
  if (!target) {
    return c.json({ error: "user_not_found", id: targetId }, 404);
  }

  await c.env.GROVE_DB.prepare(
    "UPDATE users SET role = ?, updated_at = datetime('now') WHERE id = ?",
  ).bind(body.role, targetId).run();

  logAuditEvent(c.env.GROVE_DB, {
    eventType: "role_change", result: "success",
    ip: getClientIp(c), endpoint: new URL(c.req.url).pathname, method: "PUT",
    identity: caller.email,
    detail: `${targetId}: ${target.role} → ${body.role}`,
  });

  return c.json({ ok: true, id: targetId, previous_role: target.role, new_role: body.role });
});

// ---------------------------------------------------------------------------
// GET /api/auth/agents — list agents (context-filtered by caller)
// ---------------------------------------------------------------------------

authRoutes.get("/api/auth/agents", async (c) => {
  const user = c.get("user");
  const db = c.env.GROVE_DB;

  if (user.role === "admin") {
    // Admin sees all agents
    const agents = await db.prepare("SELECT * FROM agents ORDER BY created_at").all();
    return c.json({ agents: agents.results });
  }

  // Operators/viewers: own agents + delegated + cattle
  const [owned, delegated, cattle] = await Promise.all([
    db.prepare("SELECT * FROM agents WHERE owner_id = ?").bind(user.id).all(),
    db.prepare(`
      SELECT a.*, g.scope AS grant_scope
      FROM agents a JOIN agent_grants g ON g.agent_id = a.id
      WHERE g.grantee_id = ? AND g.revoked_at IS NULL
      AND (g.expires_at IS NULL OR g.expires_at > datetime('now'))
    `).bind(user.id).all(),
    db.prepare("SELECT * FROM agents WHERE class = 'cattle'").all(),
  ]);

  return c.json({
    owned: owned.results,
    delegated: delegated.results,
    cattle: cattle.results,
  });
});

// ---------------------------------------------------------------------------
// GET /api/auth/agents/:agentId — agent detail
// ---------------------------------------------------------------------------

authRoutes.get("/api/auth/agents/:agentId", async (c) => {
  const agentId = c.req.param("agentId");
  const db = c.env.GROVE_DB;

  const agent = await db.prepare("SELECT * FROM agents WHERE id = ?").bind(agentId).first();
  if (!agent) {
    return c.json({ error: "agent_not_found", agentId }, 404);
  }

  const grants = await db.prepare(`
    SELECT g.*, u.display_name AS grantee_name, u.email AS grantee_email
    FROM agent_grants g JOIN users u ON g.grantee_id = u.id
    WHERE g.agent_id = ? AND g.revoked_at IS NULL
  `).bind(agentId).all();

  const owner = await db.prepare(
    "SELECT id, display_name, email FROM users WHERE id = ?",
  ).bind(agent.owner_id as string).first();

  return c.json({ agent, owner, grants: grants.results });
});

// ---------------------------------------------------------------------------
// POST /api/auth/agents/:agentId/grants — create grant (owner or admin)
// ---------------------------------------------------------------------------

authRoutes.post("/api/auth/agents/:agentId/grants", async (c) => {
  const caller = c.get("user");
  const agentId = c.req.param("agentId");
  const db = c.env.GROVE_DB;

  const agent = await db.prepare("SELECT * FROM agents WHERE id = ?").bind(agentId).first();
  if (!agent) {
    return c.json({ error: "agent_not_found", agentId }, 404);
  }

  // Only owner or admin can create grants
  if (agent.owner_id !== caller.id && caller.role !== "admin") {
    return c.json({ error: "only owner or admin can create grants" }, 403);
  }

  const body = await c.req.json<{
    grantee_id: string;
    scope: GrantScope;
    requires_stepup?: boolean;
    expires_at?: string;
  }>().catch(() => null);

  if (!body?.grantee_id || !body?.scope) {
    return c.json({ error: "grantee_id and scope are required" }, 400);
  }
  if (!["read", "review", "control"].includes(body.scope)) {
    return c.json({ error: "invalid scope", valid: ["read", "review", "control"] }, 400);
  }

  // Verify grantee exists
  const grantee = await db.prepare("SELECT id FROM users WHERE id = ?").bind(body.grantee_id).first();
  if (!grantee) {
    return c.json({ error: "grantee_not_found", grantee_id: body.grantee_id }, 404);
  }

  const grantId = crypto.randomUUID();
  await db.prepare(`
    INSERT INTO agent_grants (id, agent_id, owner_id, grantee_id, scope, requires_stepup, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(
    grantId,
    agentId,
    agent.owner_id as string,
    body.grantee_id,
    body.scope,
    body.requires_stepup === false ? 0 : 1,
    body.expires_at ?? null,
  ).run();

  logAuditEvent(db, {
    eventType: "grant_create", result: "success",
    ip: getClientIp(c), endpoint: new URL(c.req.url).pathname, method: "POST",
    identity: caller.email,
    detail: `grant=${grantId}, agent=${agentId}, grantee=${body.grantee_id}, scope=${body.scope}`,
  });

  return c.json({ ok: true, grant_id: grantId }, 201);
});

// ---------------------------------------------------------------------------
// GET /api/auth/agents/:agentId/grants — list grants for an agent
// ---------------------------------------------------------------------------

authRoutes.get("/api/auth/agents/:agentId/grants", async (c) => {
  const agentId = c.req.param("agentId");
  const db = c.env.GROVE_DB;

  const agent = await db.prepare("SELECT id FROM agents WHERE id = ?").bind(agentId).first();
  if (!agent) {
    return c.json({ error: "agent_not_found", agentId }, 404);
  }

  const grants = await db.prepare(`
    SELECT g.*, u.display_name AS grantee_name, u.email AS grantee_email
    FROM agent_grants g JOIN users u ON g.grantee_id = u.id
    WHERE g.agent_id = ?
    ORDER BY g.created_at DESC
  `).bind(agentId).all();

  return c.json({ grants: grants.results });
});

// ---------------------------------------------------------------------------
// DELETE /api/auth/grants/:grantId — revoke grant (soft delete)
// ---------------------------------------------------------------------------

authRoutes.delete("/api/auth/grants/:grantId", async (c) => {
  const caller = c.get("user");
  const grantId = c.req.param("grantId");
  const db = c.env.GROVE_DB;

  const grant = await db.prepare(
    "SELECT * FROM agent_grants WHERE id = ?",
  ).bind(grantId).first<{ id: string; owner_id: string; revoked_at: string | null }>();

  if (!grant) {
    return c.json({ error: "grant_not_found", grantId }, 404);
  }
  if (grant.revoked_at) {
    return c.json({ error: "grant_already_revoked", grantId }, 409);
  }

  // Only grant owner or admin can revoke
  if (grant.owner_id !== caller.id && caller.role !== "admin") {
    return c.json({ error: "only owner or admin can revoke grants" }, 403);
  }

  await db.prepare(
    "UPDATE agent_grants SET revoked_at = datetime('now') WHERE id = ?",
  ).bind(grantId).run();

  logAuditEvent(db, {
    eventType: "grant_revoke", result: "success",
    ip: getClientIp(c), endpoint: new URL(c.req.url).pathname, method: "DELETE",
    identity: caller.email,
    detail: `grant=${grantId}`,
  });

  return c.json({ ok: true, grantId, revoked: true });
});
