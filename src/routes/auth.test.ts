/**
 * GA-1 (1.5): Tests for auth API route group.
 * Mounts the REAL authRoutes with a Bun SQLite-backed D1 mock.
 * CF Access is mocked to use X-Test-Email header for identity injection.
 */

import { describe, test, expect, beforeEach, mock } from "bun:test";
import { Database } from "bun:sqlite";
import { Hono } from "hono";

// ---------------------------------------------------------------------------
// Mock CF Access — use X-Test-Email header instead of JWT validation
// Must be called before importing authRoutes
// ---------------------------------------------------------------------------

mock.module("../middleware/cf-access", () => ({
  getCfAccessEmail: async (_env: unknown, req: { header(name: string): string | undefined }) => {
    return req.header("X-Test-Email") ?? null;
  },
  validateCfAccessJwt: async () => null,
}));

// Import real authRoutes AFTER mock is in place
const { authRoutes } = await import("./auth");

// ---------------------------------------------------------------------------
// D1 mock backed by Bun's built-in SQLite
// ---------------------------------------------------------------------------

function createMockD1(sqlite: InstanceType<typeof Database>) {
  return {
    prepare(query: string) {
      let boundValues: unknown[] = [];
      return {
        bind(...values: unknown[]) {
          boundValues = values;
          return this;
        },
        async first<T = Record<string, unknown>>(): Promise<T | null> {
          try {
            const stmt = sqlite.prepare(query);
            const row = stmt.get(...boundValues);
            return (row as T) ?? null;
          } catch (_err) {
            return null;
          }
        },
        async all<T = Record<string, unknown>>(): Promise<{ results: T[] }> {
          try {
            const stmt = sqlite.prepare(query);
            const rows = stmt.all(...boundValues);
            return { results: rows as T[] };
          } catch (_err) {
            return { results: [] };
          }
        },
        async run() {
          try {
            const stmt = sqlite.prepare(query);
            stmt.run(...boundValues);
          } catch (_err) {
            // Audit log writes may fail in test — acceptable
          }
          return { results: [], success: true, meta: {} };
        },
      };
    },
  } as unknown as D1Database;
}

function createTestDb(): { db: D1Database; sqlite: InstanceType<typeof Database> } {
  const sqlite = new Database(":memory:");

  sqlite.run(`
    CREATE TABLE users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      display_name TEXT,
      role TEXT NOT NULL DEFAULT 'viewer' CHECK(role IN ('viewer', 'operator', 'admin')),
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  sqlite.run(`
    CREATE TABLE agents (
      id TEXT PRIMARY KEY,
      display_name TEXT NOT NULL,
      owner_id TEXT NOT NULL,
      class TEXT NOT NULL DEFAULT 'pet' CHECK(class IN ('pet', 'cattle')),
      backend TEXT,
      spawn_profile TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (owner_id) REFERENCES users(id)
    )
  `);
  sqlite.run(`
    CREATE TABLE agent_grants (
      id TEXT PRIMARY KEY,
      agent_id TEXT NOT NULL,
      owner_id TEXT NOT NULL,
      grantee_id TEXT NOT NULL,
      scope TEXT NOT NULL DEFAULT 'read' CHECK(scope IN ('read', 'review', 'control')),
      requires_stepup INTEGER DEFAULT 1,
      expires_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      revoked_at TEXT,
      FOREIGN KEY (agent_id) REFERENCES agents(id),
      FOREIGN KEY (owner_id) REFERENCES users(id),
      FOREIGN KEY (grantee_id) REFERENCES users(id)
    )
  `);
  sqlite.run(`
    CREATE TABLE audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type TEXT NOT NULL,
      result TEXT NOT NULL,
      ip TEXT,
      endpoint TEXT,
      method TEXT,
      identity TEXT,
      detail TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  return { db: createMockD1(sqlite), sqlite };
}

function seedTestData(sqlite: InstanceType<typeof Database>) {
  sqlite.run(`
    INSERT INTO users (id, email, display_name, role) VALUES
      ('andreas', 'andreas@meta-factory.ai', 'Andreas', 'admin'),
      ('jc', 'jc@meta-factory.ai', 'JC', 'operator'),
      ('viewer1', 'viewer@meta-factory.ai', 'Viewer', 'viewer')
  `);
  sqlite.run(`
    INSERT INTO agents (id, display_name, owner_id, class, backend) VALUES
      ('luna', 'Luna', 'andreas', 'pet', 'local'),
      ('ivy', 'Ivy', 'jc', 'pet', 'ec2'),
      ('review-worker', 'Review Worker', 'andreas', 'cattle', 'ec2')
  `);
  sqlite.run(`
    INSERT INTO agent_grants (id, agent_id, owner_id, grantee_id, scope, requires_stepup)
    VALUES ('grant-1', 'luna', 'andreas', 'jc', 'review', 1)
  `);
}

// ---------------------------------------------------------------------------
// Test app builder — mounts REAL authRoutes with mock D1 bindings
// ---------------------------------------------------------------------------

function buildTestApp(mockD1: D1Database) {
  const app = new Hono();
  // Mount the real production routes
  app.route("/", authRoutes);

  const env = { GROVE_DB: mockD1, CF_ACCESS_AUD: "test-audience" };

  // Return a wrapper that injects env into every request
  return {
    async request(path: string, init?: RequestInit) {
      return app.request(path, init, env);
    },
  };
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function req(path: string, opts?: { email?: string; method?: string; body?: unknown }) {
  const headers: Record<string, string> = {};
  if (opts?.email) headers["X-Test-Email"] = opts.email;
  if (opts?.body) headers["Content-Type"] = "application/json";
  return {
    path,
    init: {
      method: opts?.method ?? "GET",
      headers,
      ...(opts?.body ? { body: JSON.stringify(opts.body) } : {}),
    } as RequestInit,
  };
}

const ADMIN = "andreas@meta-factory.ai";
const OPERATOR = "jc@meta-factory.ai";
const VIEWER = "viewer@meta-factory.ai";

// =============================================================================
// Tests
// =============================================================================

describe("/api/auth/me", () => {
  let app: ReturnType<typeof buildTestApp>;
  beforeEach(() => {
    const { db, sqlite } = createTestDb();
    seedTestData(sqlite);
    app = buildTestApp(db);
  });

  test("returns user profile with agents and grants", async () => {
    const r = req("/api/auth/me", { email: ADMIN });
    const res = await app.request(r.path, r.init);
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect((body.user as Record<string, unknown>).id).toBe("andreas");
    expect((body.agents as unknown[]).length).toBe(2); // luna + review-worker
    const grants = body.grants as Record<string, unknown[]>;
    expect(grants.given.length).toBe(1); // grant to jc
  });

  test("unauthenticated → 401", async () => {
    const res = await app.request("/api/auth/me");
    expect(res.status).toBe(401);
  });

  test("unknown user → 401", async () => {
    const r = req("/api/auth/me", { email: "nobody@example.com" });
    const res = await app.request(r.path, r.init);
    expect(res.status).toBe(401);
  });
});

describe("/api/auth/users", () => {
  let app: ReturnType<typeof buildTestApp>;
  beforeEach(() => {
    const { db, sqlite } = createTestDb();
    seedTestData(sqlite);
    app = buildTestApp(db);
  });

  test("admin sees all users", async () => {
    const r = req("/api/auth/users", { email: ADMIN });
    const res = await app.request(r.path, r.init);
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown[]>;
    expect(body.users.length).toBe(3);
  });

  test("operator → 403", async () => {
    const r = req("/api/auth/users", { email: OPERATOR });
    expect((await app.request(r.path, r.init)).status).toBe(403);
  });

  test("viewer → 403", async () => {
    const r = req("/api/auth/users", { email: VIEWER });
    expect((await app.request(r.path, r.init)).status).toBe(403);
  });
});

describe("PUT /api/auth/users/:id/role", () => {
  let app: ReturnType<typeof buildTestApp>;
  let sqlite: InstanceType<typeof Database>;
  beforeEach(() => {
    const ctx = createTestDb();
    sqlite = ctx.sqlite;
    seedTestData(sqlite);
    app = buildTestApp(ctx.db);
  });

  test("admin changes role", async () => {
    const r = req("/api/auth/users/jc/role", {
      email: ADMIN, method: "PUT", body: { role: "admin" },
    });
    const res = await app.request(r.path, r.init);
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body.previous_role).toBe("operator");
    expect(body.new_role).toBe("admin");
    // Verify in DB
    const row = sqlite.prepare("SELECT role FROM users WHERE id = 'jc'").get() as { role: string };
    expect(row.role).toBe("admin");
  });

  test("operator cannot change roles", async () => {
    const r = req("/api/auth/users/viewer1/role", {
      email: OPERATOR, method: "PUT", body: { role: "operator" },
    });
    expect((await app.request(r.path, r.init)).status).toBe(403);
  });

  test("invalid role → 400", async () => {
    const r = req("/api/auth/users/jc/role", {
      email: ADMIN, method: "PUT", body: { role: "superadmin" },
    });
    expect((await app.request(r.path, r.init)).status).toBe(400);
  });

  test("user not found → 404", async () => {
    const r = req("/api/auth/users/nonexistent/role", {
      email: ADMIN, method: "PUT", body: { role: "operator" },
    });
    expect((await app.request(r.path, r.init)).status).toBe(404);
  });

  test("cannot demote last admin → 409", async () => {
    const r = req("/api/auth/users/andreas/role", {
      email: ADMIN, method: "PUT", body: { role: "viewer" },
    });
    const res = await app.request(r.path, r.init);
    expect(res.status).toBe(409);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe("cannot_demote_last_admin");
  });

  test("can demote admin when another admin exists", async () => {
    sqlite.run("UPDATE users SET role = 'admin' WHERE id = 'jc'");
    const r = req("/api/auth/users/andreas/role", {
      email: ADMIN, method: "PUT", body: { role: "operator" },
    });
    const res = await app.request(r.path, r.init);
    expect(res.status).toBe(200);
  });
});

describe("/api/auth/agents", () => {
  let app: ReturnType<typeof buildTestApp>;
  beforeEach(() => {
    const { db, sqlite } = createTestDb();
    seedTestData(sqlite);
    app = buildTestApp(db);
  });

  test("admin sees all agents", async () => {
    const r = req("/api/auth/agents", { email: ADMIN });
    const res = await app.request(r.path, r.init);
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown[]>;
    expect(body.agents.length).toBe(3);
  });

  test("operator sees own + delegated + cattle", async () => {
    const r = req("/api/auth/agents", { email: OPERATOR });
    const res = await app.request(r.path, r.init);
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown[]>;
    expect(body.owned.length).toBe(1); // ivy
    expect(body.delegated.length).toBe(1); // luna (via grant)
    expect(body.cattle.length).toBe(1); // review-worker
  });
});

describe("/api/auth/agents/:agentId", () => {
  let app: ReturnType<typeof buildTestApp>;
  beforeEach(() => {
    const { db, sqlite } = createTestDb();
    seedTestData(sqlite);
    app = buildTestApp(db);
  });

  test("owner sees agent detail with grants", async () => {
    const r = req("/api/auth/agents/luna", { email: ADMIN });
    const res = await app.request(r.path, r.init);
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect((body.agent as Record<string, unknown>).id).toBe("luna");
    expect((body.owner as Record<string, unknown>).id).toBe("andreas");
    expect((body.grants as unknown[]).length).toBe(1);
  });

  test("grantee can see delegated agent", async () => {
    const r = req("/api/auth/agents/luna", { email: OPERATOR });
    const res = await app.request(r.path, r.init);
    expect(res.status).toBe(200);
  });

  test("viewer without grant → 403", async () => {
    const r = req("/api/auth/agents/luna", { email: VIEWER });
    const res = await app.request(r.path, r.init);
    expect(res.status).toBe(403);
  });

  test("any operator can see cattle agent", async () => {
    const r = req("/api/auth/agents/review-worker", { email: OPERATOR });
    const res = await app.request(r.path, r.init);
    expect(res.status).toBe(200);
  });

  test("unknown agent → 404", async () => {
    const r = req("/api/auth/agents/nonexistent", { email: ADMIN });
    expect((await app.request(r.path, r.init)).status).toBe(404);
  });
});

describe("POST /api/auth/agents/:agentId/grants", () => {
  let app: ReturnType<typeof buildTestApp>;
  beforeEach(() => {
    const { db, sqlite } = createTestDb();
    seedTestData(sqlite);
    app = buildTestApp(db);
  });

  test("owner creates grant", async () => {
    const r = req("/api/auth/agents/luna/grants", {
      email: ADMIN, method: "POST",
      body: { grantee_id: "viewer1", scope: "read" },
    });
    const res = await app.request(r.path, r.init);
    expect(res.status).toBe(201);
    const body = await res.json() as Record<string, unknown>;
    expect(body.ok).toBe(true);
  });

  test("non-owner non-admin → 403", async () => {
    const r = req("/api/auth/agents/luna/grants", {
      email: OPERATOR, method: "POST",
      body: { grantee_id: "viewer1", scope: "read" },
    });
    expect((await app.request(r.path, r.init)).status).toBe(403);
  });

  test("admin can create grant on any agent", async () => {
    const r = req("/api/auth/agents/ivy/grants", {
      email: ADMIN, method: "POST",
      body: { grantee_id: "viewer1", scope: "read" },
    });
    expect((await app.request(r.path, r.init)).status).toBe(201);
  });

  test("missing fields → 400", async () => {
    const r = req("/api/auth/agents/luna/grants", {
      email: ADMIN, method: "POST",
      body: { grantee_id: "viewer1" },
    });
    expect((await app.request(r.path, r.init)).status).toBe(400);
  });

  test("invalid scope → 400", async () => {
    const r = req("/api/auth/agents/luna/grants", {
      email: ADMIN, method: "POST",
      body: { grantee_id: "viewer1", scope: "supercontrol" },
    });
    expect((await app.request(r.path, r.init)).status).toBe(400);
  });

  test("grantee_id too long → 400", async () => {
    const r = req("/api/auth/agents/luna/grants", {
      email: ADMIN, method: "POST",
      body: { grantee_id: "x".repeat(200), scope: "read" },
    });
    expect((await app.request(r.path, r.init)).status).toBe(400);
  });

  test("invalid expires_at → 400", async () => {
    const r = req("/api/auth/agents/luna/grants", {
      email: ADMIN, method: "POST",
      body: { grantee_id: "viewer1", scope: "read", expires_at: "not-a-date" },
    });
    expect((await app.request(r.path, r.init)).status).toBe(400);
  });

  test("valid expires_at accepted", async () => {
    const r = req("/api/auth/agents/luna/grants", {
      email: ADMIN, method: "POST",
      body: { grantee_id: "viewer1", scope: "read", expires_at: "2027-01-01T00:00:00Z" },
    });
    expect((await app.request(r.path, r.init)).status).toBe(201);
  });
});

describe("GET /api/auth/agents/:agentId/grants", () => {
  let app: ReturnType<typeof buildTestApp>;
  beforeEach(() => {
    const { db, sqlite } = createTestDb();
    seedTestData(sqlite);
    app = buildTestApp(db);
  });

  test("owner can list grants", async () => {
    const r = req("/api/auth/agents/luna/grants", { email: ADMIN });
    const res = await app.request(r.path, r.init);
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown[]>;
    expect(body.grants.length).toBe(1);
  });

  test("viewer without access → 403", async () => {
    const r = req("/api/auth/agents/luna/grants", { email: VIEWER });
    expect((await app.request(r.path, r.init)).status).toBe(403);
  });

  test("unknown agent → 404", async () => {
    const r = req("/api/auth/agents/nonexistent/grants", { email: ADMIN });
    expect((await app.request(r.path, r.init)).status).toBe(404);
  });
});

describe("DELETE /api/auth/grants/:grantId", () => {
  let app: ReturnType<typeof buildTestApp>;
  let sqlite: InstanceType<typeof Database>;
  beforeEach(() => {
    const ctx = createTestDb();
    sqlite = ctx.sqlite;
    seedTestData(sqlite);
    app = buildTestApp(ctx.db);
  });

  test("owner revokes grant", async () => {
    const r = req("/api/auth/grants/grant-1", { email: ADMIN, method: "DELETE" });
    const res = await app.request(r.path, r.init);
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body.revoked).toBe(true);
    // Verify in DB
    const row = sqlite.prepare("SELECT revoked_at FROM agent_grants WHERE id = 'grant-1'").get() as { revoked_at: string | null };
    expect(row.revoked_at).not.toBeNull();
  });

  test("non-owner non-admin → 403", async () => {
    const r = req("/api/auth/grants/grant-1", { email: OPERATOR, method: "DELETE" });
    expect((await app.request(r.path, r.init)).status).toBe(403);
  });

  test("unknown grant → 404", async () => {
    const r = req("/api/auth/grants/nonexistent", { email: ADMIN, method: "DELETE" });
    expect((await app.request(r.path, r.init)).status).toBe(404);
  });

  test("already revoked → 409", async () => {
    sqlite.run("UPDATE agent_grants SET revoked_at = datetime('now') WHERE id = 'grant-1'");
    const r = req("/api/auth/grants/grant-1", { email: ADMIN, method: "DELETE" });
    expect((await app.request(r.path, r.init)).status).toBe(409);
  });
});

// =============================================================================
// Audit logging verification
// =============================================================================

describe("audit logging", () => {
  let app: ReturnType<typeof buildTestApp>;
  let sqlite: InstanceType<typeof Database>;
  beforeEach(() => {
    const ctx = createTestDb();
    sqlite = ctx.sqlite;
    seedTestData(sqlite);
    app = buildTestApp(ctx.db);
  });

  test("successful auth is audited", async () => {
    const r = req("/api/auth/me", { email: ADMIN });
    await app.request(r.path, r.init);
    const row = sqlite.prepare(
      "SELECT * FROM audit_log WHERE event_type = 'auth' AND result = 'success'",
    ).get() as Record<string, unknown> | null;
    expect(row).not.toBeNull();
    expect(row!.identity).toBe("andreas@meta-factory.ai");
  });

  test("failed auth is audited", async () => {
    await app.request("/api/auth/me");
    const row = sqlite.prepare(
      "SELECT * FROM audit_log WHERE event_type = 'auth' AND result = 'failure'",
    ).get() as Record<string, unknown> | null;
    expect(row).not.toBeNull();
  });

  test("grant 403 is audited", async () => {
    const r = req("/api/auth/agents/luna/grants", {
      email: OPERATOR, method: "POST",
      body: { grantee_id: "viewer1", scope: "read" },
    });
    await app.request(r.path, r.init);
    const row = sqlite.prepare(
      "SELECT * FROM audit_log WHERE event_type = 'grant_create' AND result = 'failure'",
    ).get() as Record<string, unknown> | null;
    expect(row).not.toBeNull();
  });
});
