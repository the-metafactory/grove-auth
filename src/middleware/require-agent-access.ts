/**
 * GA-1: requireAgentAccess() — agent-level access control middleware.
 * Resolution order: owner → active grant → admin bypass → cattle open access.
 * Single JOIN query for performance.
 * Design: docs/design-auth-aaa.md v2
 */

import type { Context, Next } from "hono";
import type { AgentClass, AuthBindings, GrantScope, Role, UserRecord } from "../types";
import { ROLE_HIERARCHY, SCOPE_HIERARCHY } from "../types";
import { logAuditEvent, getClientIp } from "./audit";

/**
 * Middleware factory that checks agent-level access.
 * Reads agentId from route params. Resolution order:
 * 1. Caller is agent owner → full access
 * 2. Caller has active grant with sufficient scope → granted access
 * 3. Caller is admin → bypass
 * 4. Agent is cattle class → any operator can access
 * Otherwise → 403.
 *
 * Requires requireRole() to have run first (needs c.get("user")).
 */
export function requireAgentAccess(requiredScope: GrantScope) {
  return async function (c: Context<{ Bindings: AuthBindings; Variables: { user: UserRecord } }>, next: Next) {
    const ip = getClientIp(c);
    const endpoint = new URL(c.req.url).pathname;
    const method = c.req.method;
    const user = c.get("user");
    const agentId = c.req.param("agentId");

    if (!agentId) {
      return c.json({ error: "missing agentId parameter" }, 400);
    }

    // Single query: fetch agent + best matching grant in one round-trip
    const row = await c.env.GROVE_DB.prepare(`
      SELECT
        a.id AS agent_id,
        a.owner_id,
        a.class AS agent_class,
        g.scope AS grant_scope
      FROM agents a
      LEFT JOIN agent_grants g
        ON g.agent_id = a.id
        AND g.grantee_id = ?
        AND g.revoked_at IS NULL
        AND (g.expires_at IS NULL OR g.expires_at > datetime('now'))
      WHERE a.id = ?
      ORDER BY
        CASE g.scope WHEN 'control' THEN 2 WHEN 'review' THEN 1 WHEN 'read' THEN 0 ELSE -1 END DESC
      LIMIT 1
    `).bind(user.id, agentId).first<{
      agent_id: string;
      owner_id: string;
      agent_class: AgentClass;
      grant_scope: GrantScope | null;
    }>();

    if (!row) {
      logAuditEvent(c.env.GROVE_DB, {
        eventType: "agent_access", result: "failure", ip, endpoint, method,
        identity: user.email, detail: `agent ${agentId} not found`,
      });
      return c.json({ error: "agent_not_found", agentId }, 404);
    }

    // Resolution order: owner → grant → admin → cattle
    let resolution: string | null = null;
    let availableScope: GrantScope = "control"; // owners and admins get full scope

    // 1. Owner check
    if (row.owner_id === user.id) {
      resolution = "owner";
    }
    // 2. Active grant check
    else if (row.grant_scope && SCOPE_HIERARCHY[row.grant_scope] >= SCOPE_HIERARCHY[requiredScope]) {
      resolution = "grant";
      availableScope = row.grant_scope;
    }
    // 3. Admin bypass
    else if (user.role === "admin") {
      resolution = "admin";
    }
    // 4. Cattle open access (any operator)
    else if (row.agent_class === "cattle" && ROLE_HIERARCHY[user.role] >= ROLE_HIERARCHY["operator"]) {
      resolution = "cattle";
    }

    if (!resolution) {
      const grantInfo = row.grant_scope ? `available_scope=${row.grant_scope}` : "no_grant";
      logAuditEvent(c.env.GROVE_DB, {
        eventType: "agent_access", result: "failure", ip, endpoint, method,
        identity: user.email,
        detail: `no_agent_access: agent=${agentId}, required=${requiredScope}, ${grantInfo}`,
      });
      return c.json({
        error: "no_agent_access",
        agentId,
        required_scope: requiredScope,
        available_scope: row.grant_scope ?? null,
      }, 403);
    }

    logAuditEvent(c.env.GROVE_DB, {
      eventType: "agent_access", result: "success", ip, endpoint, method,
      identity: user.email,
      detail: `agent=${agentId}, scope=${requiredScope}, resolution=${resolution}, available=${availableScope}`,
    });
    await next();
  };
}
