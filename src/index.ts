/**
 * grove-auth — Authentication, authorization, and device trust
 * for the metafactory ecosystem.
 *
 * Public API: middleware + types.
 */

export {
  requireAuth,
  authenticateUser,
  requireRole,
  requireAgentAccess,
  getUserByEmail,
  validateCfAccessJwt,
  getCfAccessEmail,
  logAuditEvent,
  getClientIp,
} from "./middleware";

export type {
  Role,
  AgentClass,
  GrantScope,
  UserRecord,
  AgentRecord,
  GrantRecord,
  AuthBindings,
} from "./types";

export { ROLE_HIERARCHY, SCOPE_HIERARCHY } from "./types";

export { checkRole, checkAgentAccess } from "./authorize";
export type { RoleCheckResult, AgentAccessInput, AgentAccessResult } from "./authorize";

export { authRoutes } from "./routes/auth";
