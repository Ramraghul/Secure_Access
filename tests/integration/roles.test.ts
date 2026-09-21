import { api, bearer, closeAll, createUserSession, loginAdmin, prisma, TestSession } from "./helpers";

let admin: TestSession;

beforeAll(async () => {
  admin = await loginAdmin();
});
afterAll(closeAll);

const roleName = (prefix: string) => `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;

async function createRole(body: Record<string, unknown>) {
  const res = await api().post("/api/v1/roles").set(bearer(admin.accessToken)).send(body);
  expect(res.status).toBe(201);
  return res.body;
}

describe("roles CRUD", () => {
  it("lists the seeded system roles", async () => {
    const res = await api().get("/api/v1/roles").set(bearer(admin.accessToken));
    expect(res.status).toBe(200);
    const byName = Object.fromEntries(res.body.map((r: { name: string }) => [r.name, r]));
    expect(byName.admin).toMatchObject({ isSystem: true, permissions: [expect.objectContaining({ action: "manage", resource: "*" })] });
    expect(byName.auditor.isSystem).toBe(true);
    expect(byName.user.permissions).toEqual([]);
  });

  it("creates a role, de-duplicating permissions", async () => {
    const name = roleName("support");
    const role = await createRole({
      name, description: "Support desk",
      permissions: [{ action: "read", resource: "user" }, { action: "read", resource: "user" }, { action: "read", resource: "audit" }],
    });
    expect(role).toMatchObject({ name, description: "Support desk", isSystem: false });
    expect(role.permissions).toHaveLength(2);

    const duplicate = await api().post("/api/v1/roles").set(bearer(admin.accessToken)).send({ name });
    expect(duplicate.status).toBe(409);
    expect(duplicate.body.error).toBe("ROLE_EXISTS");
  });

  it("validates role input", async () => {
    const res = await api().post("/api/v1/roles").set(bearer(admin.accessToken))
      .send({ name: "Bad Name", permissions: [{ action: "fly", resource: "user" }] });
    expect(res.status).toBe(400);
    expect(res.body.details).toHaveProperty("name");
  });

  it("gets, renames and replaces permissions of a custom role", async () => {
    const role = await createRole({ name: roleName("editor"), permissions: [{ action: "read", resource: "role" }] });

    expect((await api().get(`/api/v1/roles/${role.id}`).set(bearer(admin.accessToken))).body.name).toBe(role.name);

    const newName = roleName("renamed");
    const updated = await api().put(`/api/v1/roles/${role.id}`).set(bearer(admin.accessToken))
      .send({ name: newName, permissions: [{ action: "update", resource: "user" }] });
    expect(updated.status).toBe(200);
    expect(updated.body.name).toBe(newName);
    expect(updated.body.permissions).toEqual([expect.objectContaining({ action: "update", resource: "user" })]);
  });

  it("only lets system roles change their description", async () => {
    const adminRole = await prisma.role.findUniqueOrThrow({ where: { name: "admin" } });

    const perms = await api().put(`/api/v1/roles/${adminRole.id}`).set(bearer(admin.accessToken)).send({ permissions: [] });
    expect(perms.status).toBe(403);
    expect(perms.body.error).toBe("SYSTEM_ROLE");

    const rename = await api().put(`/api/v1/roles/${adminRole.id}`).set(bearer(admin.accessToken)).send({ name: "superuser" });
    expect(rename.status).toBe(403);

    const describe = await api().put(`/api/v1/roles/${adminRole.id}`).set(bearer(admin.accessToken)).send({ description: "Full system access" });
    expect(describe.status).toBe(200);

    const del = await api().delete(`/api/v1/roles/${adminRole.id}`).set(bearer(admin.accessToken));
    expect(del.status).toBe(403);
  });

  it("deletes a custom role and returns 404 afterwards", async () => {
    const role = await createRole({ name: roleName("temp") });
    expect((await api().delete(`/api/v1/roles/${role.id}`).set(bearer(admin.accessToken))).status).toBe(200);
    expect((await api().get(`/api/v1/roles/${role.id}`).set(bearer(admin.accessToken))).status).toBe(404);
  });

  it("forbids role management for regular users", async () => {
    const user = await createUserSession();
    const res = await api().post("/api/v1/roles").set(bearer(user.accessToken)).send({ name: roleName("nope") });
    expect(res.status).toBe(403);
  });
});

describe("assigning roles changes access immediately", () => {
  it("grants and removes a permission", async () => {
    const user = await createUserSession();
    const role = await createRole({ name: roleName("reader"), permissions: [{ action: "read", resource: "user" }] });
    const listUsers = () => api().get("/api/v1/users").set(bearer(user.accessToken));

    expect((await listUsers()).status).toBe(403);

    const assign = await api().post(`/api/v1/roles/${role.id}/assign`).set(bearer(admin.accessToken)).send({ userId: user.userId });
    expect(assign.status).toBe(200);
    expect((await listUsers()).status).toBe(200);

    const me = await api().get("/api/v1/auth/me").set(bearer(user.accessToken));
    expect(me.body.user.permissions).toContain("read:user");

    const revoke = await api().post(`/api/v1/roles/${role.id}/revoke`).set(bearer(admin.accessToken)).send({ userId: user.userId });
    expect(revoke.status).toBe(200);
    expect((await listUsers()).status).toBe(403);

    const again = await api().post(`/api/v1/roles/${role.id}/revoke`).set(bearer(admin.accessToken)).send({ userId: user.userId });
    expect(again.status).toBe(404);
    expect(again.body.error).toBe("ROLE_NOT_ASSIGNED");
  });

  it("honours the * resource wildcard", async () => {
    const user = await createUserSession();
    const role = await createRole({ name: roleName("read-all"), permissions: [{ action: "read", resource: "*" }] });
    await api().post(`/api/v1/roles/${role.id}/assign`).set(bearer(admin.accessToken)).send({ userId: user.userId });

    expect((await api().get("/api/v1/audit").set(bearer(user.accessToken))).status).toBe(200);
    expect((await api().get("/api/v1/roles").set(bearer(user.accessToken))).status).toBe(200);
    expect((await api().post("/api/v1/roles").set(bearer(user.accessToken)).send({ name: roleName("x") })).status).toBe(403);
  });

  it("never removes the admin role from the last administrator", async () => {
    const adminRole = await prisma.role.findUniqueOrThrow({ where: { name: "admin" } });
    const res = await api().post(`/api/v1/roles/${adminRole.id}/revoke`).set(bearer(admin.accessToken)).send({ userId: admin.userId });
    expect(res.status).toBe(409);
    expect(res.body.error).toBe("LAST_ADMIN");
  });

  it("returns 404 for unknown roles or users", async () => {
    const role = await createRole({ name: roleName("lonely") });
    const unknownUser = await api().post(`/api/v1/roles/${role.id}/assign`).set(bearer(admin.accessToken))
      .send({ userId: "00000000-0000-4000-8000-000000000000" });
    expect(unknownUser.body.error).toBe("USER_NOT_FOUND");

    const unknownRole = await api().post("/api/v1/roles/00000000-0000-4000-8000-000000000000/assign").set(bearer(admin.accessToken))
      .send({ userId: admin.userId });
    expect(unknownRole.body.error).toBe("ROLE_NOT_FOUND");
  });
});
