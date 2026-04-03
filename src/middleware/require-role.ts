/**
 * GA-1: requireRole() — role-based authorization middleware.
 * Looks up user by CF Access email in D1, enforces role hierarchy.
 * Design: docs/design-auth-aaa.md v2
 */

import type { Context, Next } from "hono";
import type { AuthBindings, Role, UserRecord } from "../types";
import { ROLE_HIERARCHY } from "../types";
import { getCfAccessEmail } from "./cf-access";
import { logAuditEvent, getClientIp } from "./audit";

/** Look up a user in D1 by email. */
export async function getUserByEmail(db: D1Database, email: string): Promise<UserRecord | null> {
  return db.prepare("SELECT * FROM users WHERE email = ?").bind(email).first<UserRecord>();
}

/**
 * Middleware factory that requires a minimum role level.
 * Extracts email from CF Access JWT, looks up user in D1, checks role hierarchy.
 * Sets c.set("user", userRecord) on success for downstream use.
 *
 * Returns 401 if no CF Access identity or user not provisioned.
 * Returns 403 if user role is below the required minimum.
 */
export function requireRole(minRole: Role) {
  return async function (c: Context<{ Bindings: AuthBindings; Variables: { user: UserRecord } }>, next: Next) {
    const ip = getClientIp(c);
    const endpoint = new URL(c.req.url).pathname;
    const method = c.req.method;

    const email = await getCfAccessEmail(c.env, c.req);
    if (!email) {
      logAuditEvent(c.env.GROVE_DB, {
        eventType: "role_check", result: "failure", ip, endpoint, method,
        detail: "no CF Access identity",
      });
      return c.json({ error: "authentication required" }, 401);
    }

    const user = await getUserByEmail(c.env.GROVE_DB, email);
    if (!user) {
      logAuditEvent(c.env.GROVE_DB, {
        eventType: "role_check", result: "failure", ip, endpoint, method,
        identity: email, detail: "user not provisioned",
      });
      return c.json({ error: "user not provisioned", email }, 401);
    }

    if (ROLE_HIERARCHY[user.role] < ROLE_HIERARCHY[minRole]) {
      logAuditEvent(c.env.GROVE_DB, {
        eventType: "role_check", result: "failure", ip, endpoint, method,
        identity: email, detail: `insufficient_role: has ${user.role}, needs ${minRole}`,
      });
      return c.json({ error: "insufficient_role", required: minRole, current: user.role }, 403);
    }

    logAuditEvent(c.env.GROVE_DB, {
      eventType: "role_check", result: "success", ip, endpoint, method,
      identity: email, detail: `role=${user.role} meets ${minRole}`,
    });
    c.set("user", user);
    await next();
  };
}
