import {
  api, bearer, closeAll, createUserSession, DEMO_ACCOUNTS, login, loginAdmin, loginDemo, prisma, registerUser,
  STRONG_PASSWORD, TestSession,
} from "./helpers";

let admin: TestSession;

beforeAll(async () => {
  admin = await loginAdmin();
});
afterAll(closeAll);

describe("access control on /api/v1/users", () => {
  it("rejects anonymous requests", async () => {
    expect((await api().get("/api/v1/users")).status).toBe(401);
  });

  it("forbids regular users", async () => {
    const user = await createUserSession();
    const res = await api().get("/api/v1/users").set(bearer(user.accessToken));
    expect(res.status).toBe(403);
    expect(res.body).toMatchObject({ error: "FORBIDDEN", message: "Missing permission: read:user" });
  });

  it("lets the auditor read but not modify", async () => {
    const auditor = await loginDemo("auditor");
    const { userId } = await registerUser();
    expect((await api().get("/api/v1/users").set(bearer(auditor.accessToken))).status).toBe(200);
    expect((await api().post(`/api/v1/users/${userId}/deactivate`).set(bearer(auditor.accessToken))).status).toBe(403);
  });
});

describe("user administration", () => {
  it("lists users with pagination, search and status filter", async () => {
    const marker = `Marker${Date.now()}`;
    const { userId } = await registerUser({ lastName: marker });

    const search = await api().get("/api/v1/users").query({ search: marker.toLowerCase(), limit: 5 }).set(bearer(admin.accessToken));
    expect(search.status).toBe(200);
    expect(search.body.pagination).toMatchObject({ page: 1, limit: 5, total: 1, totalPages: 1 });
    expect(search.body.data[0]).toMatchObject({ id: userId, lastName: marker, isActive: true });
    expect(search.body.data[0].roles[0].role.name).toBe("user");

    await prisma.user.update({ where: { id: userId }, data: { isActive: false } });
    const inactive = await api().get("/api/v1/users").query({ search: marker, status: "inactive" }).set(bearer(admin.accessToken));
    expect(inactive.body.pagination.total).toBe(1);
    const active = await api().get("/api/v1/users").query({ search: marker, status: "active" }).set(bearer(admin.accessToken));
    expect(active.body.pagination.total).toBe(0);
  });

  it("validates list query parameters", async () => {
    const res = await api().get("/api/v1/users").query({ limit: 1000 }).set(bearer(admin.accessToken));
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("VALIDATION_ERROR");
  });

  it("returns a user without secrets", async () => {
    const user = await createUserSession();
    const res = await api().get(`/api/v1/users/${user.userId}`).set(bearer(admin.accessToken));
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ id: user.userId, email: user.email, activeSessions: 1 });
    expect(res.body.devices).toHaveLength(1);
    expect(res.body).not.toHaveProperty("passwordHash");
    expect(res.body).not.toHaveProperty("mfaSecret");
    expect(res.body).not.toHaveProperty("backupCodesHashed");
  });

  it("returns 404 for unknown users and 400 for malformed ids", async () => {
    const unknown = await api().get("/api/v1/users/00000000-0000-4000-8000-000000000000").set(bearer(admin.accessToken));
    expect(unknown.status).toBe(404);
    expect(unknown.body.error).toBe("USER_NOT_FOUND");
    expect((await api().get("/api/v1/users/not-a-uuid").set(bearer(admin.accessToken))).status).toBe(400);
  });

  it("deactivation revokes sessions and blocks login until reactivated", async () => {
    const user = await createUserSession();

    const res = await api().post(`/api/v1/users/${user.userId}/deactivate`).set(bearer(admin.accessToken));
    expect(res.status).toBe(200);
    expect(res.body.revokedSessions).toBe(1);
    expect((await api().get("/api/v1/auth/me").set(bearer(user.accessToken))).status).toBe(401);
    expect((await login(user.email, user.password)).status).toBe(403);

    expect((await api().post(`/api/v1/users/${user.userId}/activate`).set(bearer(admin.accessToken))).status).toBe(200);
    expect((await login(user.email, user.password)).status).toBe(200);
  });

  it("activation clears a lockout", async () => {
    const { email, password, userId } = await registerUser();
    await prisma.user.update({ where: { id: userId }, data: { lockedUntil: new Date(Date.now() + 60 * 60 * 1000) } });
    expect((await login(email, password)).status).toBe(423);

    await api().post(`/api/v1/users/${userId}/activate`).set(bearer(admin.accessToken));
    expect((await login(email, password)).status).toBe(200);
  });

  it("prevents administrators from deactivating or deleting themselves", async () => {
    for (const req of [
      api().post(`/api/v1/users/${admin.userId}/deactivate`),
      api().delete(`/api/v1/users/${admin.userId}`),
    ]) {
      const res = await req.set(bearer(admin.accessToken));
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("CANNOT_MODIFY_SELF");
    }
  });

  it("protects demo accounts from modification", async () => {
    const demo = await prisma.user.findUniqueOrThrow({ where: { email: DEMO_ACCOUNTS[0].email } });
    for (const req of [
      api().post(`/api/v1/users/${demo.id}/deactivate`),
      api().post(`/api/v1/users/${demo.id}/reset-password`),
      api().delete(`/api/v1/users/${demo.id}`),
    ]) {
      const res = await req.set(bearer(admin.accessToken));
      expect(res.status).toBe(403);
      expect(res.body.error).toBe("PROTECTED_ACCOUNT");
    }
  });

  it("resets a password: temporary password works, sessions are revoked, change is required", async () => {
    const user = await createUserSession();

    const res = await api().post(`/api/v1/users/${user.userId}/reset-password`).set(bearer(admin.accessToken));
    expect(res.status).toBe(200);
    expect(res.body.temporaryPassword).toHaveLength(16);

    expect((await api().get("/api/v1/auth/me").set(bearer(user.accessToken))).status).toBe(401);
    expect((await login(user.email, STRONG_PASSWORD)).status).toBe(401);

    const relogin = await login(user.email, res.body.temporaryPassword);
    expect(relogin.status).toBe(200);
    expect(relogin.body.user.mustChangePassword).toBe(true);
  });

  it("deletes a user", async () => {
    const { email, password, userId } = await registerUser();
    expect((await api().delete(`/api/v1/users/${userId}`).set(bearer(admin.accessToken))).status).toBe(200);
    expect((await api().get(`/api/v1/users/${userId}`).set(bearer(admin.accessToken))).status).toBe(404);
    expect((await login(email, password)).status).toBe(401);
  });
});
