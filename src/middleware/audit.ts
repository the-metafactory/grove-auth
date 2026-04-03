/**
 * GA-1: Audit logging helper for auth middleware.
 * Fire-and-forget writes to D1 audit_log table.
 */

import type { Context } from "hono";

/** Log an auth event to D1 audit_log table. Fire-and-forget (non-blocking). */
export function logAuditEvent(
  db: D1Database,
  event: {
    eventType: string;
    result: "success" | "failure";
    ip: string;
    endpoint: string;
    method: string;
    identity?: string;
    detail?: string;
  },
): void {
  db.prepare(`
    INSERT INTO audit_log (event_type, result, ip, endpoint, method, identity, detail)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(
    event.eventType,
    event.result,
    event.ip,
    event.endpoint,
    event.method,
    event.identity ?? null,
    event.detail ?? null,
  ).run().catch((_err: unknown) => {
    // Audit log write failures should not break the request — best-effort logging
  });
}

export function getClientIp(c: Context): string {
  return c.req.header("CF-Connecting-IP")
    ?? c.req.header("X-Forwarded-For")?.split(",")[0]?.trim()
    ?? "unknown";
}
