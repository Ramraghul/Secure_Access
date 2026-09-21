import { flushAuditLogs } from "../../src/middleware/audit.middleware";
import {
  api, bearer, closeAll, createUserSession, enableMfa, login, loginAdmin, loginDemo, prisma, registerUser,
  uniqueEmail, TestSession,
} from "./helpers";

let admin: TestSession;

beforeAll(async () => {
  admin = await loginAdmin();
});
afterAll(closeAll);

describe("audit trail recording", () => {
  it("records successful logins with the user, event and masked secrets", async () => {
    const { email, password, userId } = await registerUser();
    const res = await login(email, password);
    await flushAuditLogs();

    const row = await prisma.auditLog.findFirstOrThrow({
      where: { userId, event: "LOGIN_SUCCESS" }, orderBy: { timestamp: "desc" },
    });
    expect(row).toMatchObject({ action: "POST", resource: "/api/v1/auth/login", statusCode: 200 });

    const stored = JSON.stringify(row);
    expect(stored).not.toContain(password);
    expect(stored).not.toContain(res.body.accessToken);
    expect(stored).not.toContain(res.body.refreshToken.split(".")[1]);
    expect((row.metadata as { requestBody: { password: string } }).requestBody.password).toBe("••••••");
  });

  it("records failed logins against the targeted account", async () => {
    const { email, userId } = await registerUser();
    await login(email, "Wrong!Password123");
    await flushAuditLogs();

    const row = await prisma.auditLog.findFirst({ where: { userId, event: "LOGIN_FAILED" } });
    expect(row?.statusCode).toBe(401);
  });

  it("records logins for unknown emails anonymously", async () => {
    const ghost = uniqueEmail("ghost");
    await login(ghost, "Wrong!Password123");
    await flushAuditLogs();

    const row = await prisma.auditLog.findFirst({
      where: { event: "LOGIN_FAILED", userId: null }, orderBy: { timestamp: "desc" },
    });
    expect(JSON.stringify(row?.metadata)).toContain(ghost);
  });

  it("records rejected unauthenticated requests", async () => {
    const res = await api().get("/api/v1/users").set("X-Request-Id", "audit-test-unauthenticated-1");
    expect(res.status).toBe(401);
    await flushAuditLogs();

    const rows = await prisma.auditLog.findMany({ where: { statusCode: 401, resource: "/api/v1/users" } });
    expect(rows.some(r => (r.metadata as { requestId?: string }).requestId === "audit-test-unauthenticated-1")).toBe(true);
  });

  it("never stores MFA secrets or backup codes", async () => {
    const session = await createUserSession();
    const { secret, backupCodes } = await enableMfa(session);
    await flushAuditLogs();

    const rows = JSON.stringify(await prisma.auditLog.findMany({ where: { userId: session.userId } }));
    expect(rows).toContain("MFA_ENABLED");
    expect(rows).not.toContain(secret);
    backupCodes.forEach(code => expect(rows).not.toContain(code));
  });
});

describe("audit endpoints", () => {
  it("lists logs with pagination and filters", async () => {
    const { email, password, userId } = await registerUser();
    await login(email, password);
    await flushAuditLogs();

    const res = await api().get("/api/v1/audit").query({ userId, event: "LOGIN_SUCCESS", limit: 10 }).set(bearer(admin.accessToken));
    expect(res.status).toBe(200);
    expect(res.body.pagination).toMatchObject({ page: 1, limit: 10, total: 1 });
    expect(res.body.data[0]).toMatchObject({ userId, event: "LOGIN_SUCCESS", user: { email } });
  });

  it("searches events by email and flags nothing for local traffic", async () => {
    const { email, password } = await registerUser();
    await login(email, password);
    await flushAuditLogs();

    const found = await api().get("/api/v1/audit/events").query({ email }).set(bearer(admin.accessToken));
    expect(found.status).toBe(200);
    expect(found.body.total).toBeGreaterThanOrEqual(2); // register + login
    expect(found.body.events.every((e: { suspicious: string | null }) => e.suspicious === null)).toBe(true);

    const none = await api().get("/api/v1/audit/events").query({ email: uniqueEmail("nobody") }).set(bearer(admin.accessToken));
    expect(none.body).toEqual({ total: 0, events: [] });
  });

  it("filters sensitive operations", async () => {
    const res = await api().get("/api/v1/audit/events").query({ sensitive: "true", limit: 200 }).set(bearer(admin.accessToken));
    expect(res.status).toBe(200);
    for (const e of res.body.events) {
      expect(
        /\/login|\/mfa|password|\/roles/.test(e.resource) ||
        ["ACCOUNT_LOCKED", "REFRESH_TOKEN_REUSED", "USER_DEACTIVATED", "USER_DELETED"].includes(e.event)
      ).toBe(true);
    }
  });

  it("reports statistics", async () => {
    const res = await api().get("/api/v1/audit/retention").set(bearer(admin.accessToken));
    expect(res.status).toBe(200);
    expect(res.body.totalRecords).toBeGreaterThan(0);
    expect(res.body.configuredRetentionDays).toBe(90);
    expect(res.body.eventCounts.LOGIN_SUCCESS).toBeGreaterThan(0);
  });

  it("exports CSV", async () => {
    const res = await api().post("/api/v1/audit/export").query({ event: "LOGIN_SUCCESS" }).set(bearer(admin.accessToken));
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toContain("text/csv");
    expect(res.headers["content-disposition"]).toMatch(/attachment; filename="audit-\d{4}-\d{2}-\d{2}\.csv"/);
    const [header, firstRow] = res.text.split("\n");
    expect(header).toBe("Timestamp,User,Email,Event,Action,Resource,Status,IP,Device,Duration(ms),RequestId");
    expect(firstRow).toContain('"LOGIN_SUCCESS"');
  });

  it("purges rows older than the given age", async () => {
    const old = await prisma.auditLog.create({
      data: { action: "GET", resource: "/old", ipAddress: "127.0.0.1", userAgent: "test", timestamp: new Date(Date.now() - 400 * 86400000) },
    });

    const res = await api().post("/api/v1/audit/purge").set(bearer(admin.accessToken)).send({ olderThanDays: 365 });
    expect(res.status).toBe(200);
    expect(res.body.deleted).toBeGreaterThanOrEqual(1);
    expect(await prisma.auditLog.findUnique({ where: { id: old.id } })).toBeNull();

    const invalid = await api().post("/api/v1/audit/purge").set(bearer(admin.accessToken)).send({ olderThanDays: 0 });
    expect(invalid.status).toBe(400);
  });

  it("gives the auditor read and export but not purge; regular users nothing", async () => {
    const auditor = await loginDemo("auditor");
    expect((await api().get("/api/v1/audit").set(bearer(auditor.accessToken))).status).toBe(200);
    expect((await api().post("/api/v1/audit/export").set(bearer(auditor.accessToken))).status).toBe(200);
    expect((await api().post("/api/v1/audit/purge").set(bearer(auditor.accessToken)).send({ olderThanDays: 30 })).status).toBe(403);

    const user = await createUserSession();
    expect((await api().get("/api/v1/audit").set(bearer(user.accessToken))).status).toBe(403);
  });
});
