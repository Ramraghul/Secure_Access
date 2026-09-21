import {
  api, bearer, closeAll, createUserSession, loginDemo, login, loginOk, prisma, registerUser,
  STRONG_PASSWORD, uniqueEmail, BROWSER_UA,
} from "./helpers";

afterAll(closeAll);

const OTHER_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";

describe("POST /api/v1/auth/register", () => {
  it("creates a user with a hashed password and the default role", async () => {
    const email = uniqueEmail();
    const res = await api().post("/api/v1/auth/register")
      .send({ email: `  ${email.toUpperCase()} `, password: STRONG_PASSWORD, firstName: "Jane", lastName: "Doe" });

    expect(res.status).toBe(201);
    expect(res.body).toEqual({ message: "User registered successfully", userId: expect.any(String) });

    const user = await prisma.user.findUnique({ where: { email }, include: { roles: { include: { role: true } } } });
    expect(user).not.toBeNull();
    expect(user!.passwordHash).not.toContain(STRONG_PASSWORD);
    expect(user!.roles.map(r => r.role.name)).toEqual(["user"]);
  });

  it("rejects weak passwords with the failed rules", async () => {
    const res = await api().post("/api/v1/auth/register")
      .send({ email: uniqueEmail(), password: "alllowercase123", firstName: "A", lastName: "B" });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("WEAK_PASSWORD");
    expect(res.body.details.password).toEqual(expect.arrayContaining(["At least one uppercase letter", "At least one special character"]));
  });

  it("rejects invalid bodies with field errors", async () => {
    const res = await api().post("/api/v1/auth/register").send({ email: "nope" });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("VALIDATION_ERROR");
    expect(Object.keys(res.body.details)).toEqual(expect.arrayContaining(["email", "password", "firstName", "lastName"]));
    expect(res.body.requestId).toEqual(expect.any(String));
  });

  it("rejects duplicate emails", async () => {
    const { email } = await registerUser();
    const res = await api().post("/api/v1/auth/register")
      .send({ email, password: STRONG_PASSWORD, firstName: "Again", lastName: "User" });
    expect(res.status).toBe(409);
    expect(res.body.error).toBe("EMAIL_EXISTS");
  });

  it("returns 400 for malformed JSON", async () => {
    const res = await api().post("/api/v1/auth/register").set("Content-Type", "application/json").send("{not json");
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("INVALID_JSON");
  });
});

describe("POST /api/v1/auth/login", () => {
  it("returns an access token, a rotating refresh token, the user and the device", async () => {
    const { email, password, userId } = await registerUser();
    const res = await login(email, password);

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      tokenType: "Bearer",
      expiresIn: 900,
      user: { id: userId, email, mfaEnabled: false, mustChangePassword: false },
      mfa: "not_enabled",
      device: { isTrusted: false, trustedUntil: null },
    });
    expect(res.body.accessToken.split(".")).toHaveLength(3);
    expect(res.body.refreshToken).toMatch(/^[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/);
    expect(JSON.stringify(res.body)).not.toContain("passwordHash");
  });

  it("gives the same answer for an unknown email and a wrong password", async () => {
    const { email } = await registerUser();
    const wrongPassword = await login(email, "Wrong!Password123");
    const unknownEmail  = await login(uniqueEmail("ghost"), "Wrong!Password123");

    expect(wrongPassword.status).toBe(401);
    expect(unknownEmail.status).toBe(401);
    expect(wrongPassword.body.error).toBe("INVALID_CREDENTIALS");
    expect(unknownEmail.body.message).toBe(wrongPassword.body.message);
  });

  it("locks the account for 15 minutes after 5 failed attempts", async () => {
    const { email, password } = await registerUser();
    for (let i = 0; i < 5; i++) {
      expect((await login(email, "Wrong!Password123")).status).toBe(401);
    }

    const locked = await login(email, password);
    expect(locked.status).toBe(423);
    expect(locked.body.error).toBe("ACCOUNT_LOCKED");
    const lockedUntil = new Date(locked.body.details.lockedUntil).getTime();
    expect(lockedUntil).toBeGreaterThan(Date.now() + 14 * 60 * 1000);
  });

  it("resets the failure counter after a successful login", async () => {
    const { email, password, userId } = await registerUser();
    for (let i = 0; i < 3; i++) await login(email, "Wrong!Password123");
    expect((await prisma.user.findUnique({ where: { id: userId } }))!.failedLoginAttempts).toBe(3);

    await loginOk(email, password);
    const user = await prisma.user.findUnique({ where: { id: userId } });
    expect(user!.failedLoginAttempts).toBe(0);
    expect(user!.lastLoginAt).not.toBeNull();
  });

  it("refuses deactivated accounts only after the password is proven", async () => {
    const { email, password, userId } = await registerUser();
    await prisma.user.update({ where: { id: userId }, data: { isActive: false } });

    expect((await login(email, "Wrong!Password123")).status).toBe(401);
    const res = await login(email, password);
    expect(res.status).toBe(403);
    expect(res.body.error).toBe("ACCOUNT_DISABLED");
  });
});

describe("GET/PATCH /api/v1/auth/me", () => {
  it("requires a bearer token", async () => {
    const res = await api().get("/api/v1/auth/me");
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("ACCESS_TOKEN_REQUIRED");
  });

  it("rejects invalid tokens", async () => {
    const res = await api().get("/api/v1/auth/me").set(bearer("not.a.jwt"));
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("INVALID_TOKEN");
  });

  it("returns the profile with roles, permissions and devices", async () => {
    const session = await createUserSession();
    const res = await api().get("/api/v1/auth/me").set(bearer(session.accessToken));

    expect(res.status).toBe(200);
    expect(res.headers["x-request-id"]).toEqual(expect.any(String));
    expect(res.body.user).toMatchObject({ id: session.userId, email: session.email, roles: ["user"], permissions: [] });
    expect(res.body.devices).toHaveLength(1);
    expect(res.body.devices[0].current).toBe(true);
    expect(JSON.stringify(res.body)).not.toMatch(/passwordHash|mfaSecret|backupCodes/);
  });

  it("updates the first and last name", async () => {
    const session = await createUserSession();
    const res = await api().patch("/api/v1/auth/me").set(bearer(session.accessToken)).send({ firstName: "Renamed" });
    expect(res.status).toBe(200);
    expect(res.body.user).toMatchObject({ firstName: "Renamed", lastName: "User" });
  });
});

describe("refresh tokens", () => {
  it("rotates the refresh token and issues a working access token", async () => {
    const session = await createUserSession();
    const res = await api().post("/api/v1/auth/refresh").send({ refreshToken: session.refreshToken });

    expect(res.status).toBe(200);
    expect(res.body.refreshToken).not.toBe(session.refreshToken);
    expect(res.body.refreshToken.split(".")[0]).toBe(session.refreshToken.split(".")[0]); // same session
    expect((await api().get("/api/v1/auth/me").set(bearer(res.body.accessToken))).status).toBe(200);
  });

  it("revokes the whole session when a used refresh token is replayed", async () => {
    const session = await createUserSession();
    const first = await api().post("/api/v1/auth/refresh").send({ refreshToken: session.refreshToken });
    expect(first.status).toBe(200);

    const replay = await api().post("/api/v1/auth/refresh").send({ refreshToken: session.refreshToken });
    expect(replay.status).toBe(401);
    expect(replay.body.error).toBe("REFRESH_TOKEN_REUSED");

    // Neither the attacker's nor the legitimate newest token keeps working
    const newest = await api().post("/api/v1/auth/refresh").send({ refreshToken: first.body.refreshToken });
    expect(newest.status).toBe(401);
    const me = await api().get("/api/v1/auth/me").set(bearer(first.body.accessToken));
    expect(me.status).toBe(401);
    expect(me.body.error).toBe("SESSION_REVOKED");
  });

  it("rejects malformed and unknown refresh tokens", async () => {
    for (const refreshToken of ["no-dot-in-this-token", "00000000-0000-0000-0000-000000000000.secret"]) {
      const res = await api().post("/api/v1/auth/refresh").send({ refreshToken });
      expect(res.status).toBe(401);
      expect(res.body.error).toBe("INVALID_REFRESH_TOKEN");
    }
  });
});

describe("logout and sessions", () => {
  it("logout revokes only the current session", async () => {
    const { email, password } = await registerUser();
    const a = await loginOk(email, password);
    const b = await loginOk(email, password, OTHER_UA);

    expect((await api().post("/api/v1/auth/logout").set(bearer(a.accessToken))).status).toBe(200);
    expect((await api().get("/api/v1/auth/me").set(bearer(a.accessToken))).status).toBe(401);
    expect((await api().post("/api/v1/auth/refresh").send({ refreshToken: a.refreshToken })).status).toBe(401);
    expect((await api().get("/api/v1/auth/me").set(bearer(b.accessToken))).status).toBe(200);
  });

  it("logout-all revokes every session", async () => {
    const { email, password } = await registerUser();
    const a = await loginOk(email, password);
    const b = await loginOk(email, password, OTHER_UA);

    const res = await api().post("/api/v1/auth/logout-all").set(bearer(a.accessToken));
    expect(res.status).toBe(200);
    expect(res.body.revokedSessions).toBe(2);
    expect((await api().get("/api/v1/auth/me").set(bearer(b.accessToken))).status).toBe(401);
  });

  it("lists active sessions and revokes a chosen one", async () => {
    const { email, password } = await registerUser();
    const a = await loginOk(email, password);
    const b = await loginOk(email, password, OTHER_UA);

    const list = await api().get("/api/v1/auth/sessions").set(bearer(a.accessToken));
    expect(list.status).toBe(200);
    expect(list.body.sessions).toHaveLength(2);
    const other = list.body.sessions.find((s: { current: boolean }) => !s.current);
    expect(other.type).toBe("first-party");

    expect((await api().delete(`/api/v1/auth/sessions/${other.id}`).set(bearer(a.accessToken))).status).toBe(200);
    expect((await api().get("/api/v1/auth/me").set(bearer(b.accessToken))).status).toBe(401);
    expect((await api().delete(`/api/v1/auth/sessions/${other.id}`).set(bearer(a.accessToken))).status).toBe(404);
  });

  it("cannot revoke another user's session", async () => {
    const mine = await createUserSession();
    const theirs = await createUserSession();
    const theirSessionId = theirs.refreshToken.split(".")[0];

    const res = await api().delete(`/api/v1/auth/sessions/${theirSessionId}`).set(bearer(mine.accessToken));
    expect(res.status).toBe(404);
    expect((await api().get("/api/v1/auth/me").set(bearer(theirs.accessToken))).status).toBe(200);
  });
});

describe("POST /api/v1/auth/change-password", () => {
  it("changes the password, keeps this session and signs out the others", async () => {
    const { email, password } = await registerUser();
    const current = await loginOk(email, password);
    const other   = await loginOk(email, password, OTHER_UA);
    const newPassword = "Brand!NewPass2026";

    const res = await api().post("/api/v1/auth/change-password").set(bearer(current.accessToken))
      .send({ currentPassword: password, newPassword });
    expect(res.status).toBe(200);
    expect(res.body.revokedSessions).toBe(1);

    expect((await api().get("/api/v1/auth/me").set(bearer(current.accessToken))).status).toBe(200);
    expect((await api().get("/api/v1/auth/me").set(bearer(other.accessToken))).status).toBe(401);
    expect((await login(email, password)).status).toBe(401);
    expect((await login(email, newPassword)).status).toBe(200);
  });

  it("rejects a wrong current password, reuse and weak passwords", async () => {
    const session = await createUserSession();
    const send = (body: object) => api().post("/api/v1/auth/change-password").set(bearer(session.accessToken)).send(body);

    const wrong = await send({ currentPassword: "Wrong!Password123", newPassword: "Brand!NewPass2026" });
    expect(wrong.status).toBe(401);

    const reuse = await send({ currentPassword: session.password, newPassword: session.password });
    expect(reuse.status).toBe(400);
    expect(reuse.body.error).toBe("PASSWORD_REUSE");

    const weak = await send({ currentPassword: session.password, newPassword: "weakpassword1" });
    expect(weak.status).toBe(400);
    expect(weak.body.error).toBe("WEAK_PASSWORD");
  });
});

describe("protected demo accounts", () => {
  it("cannot change credentials, profile or MFA", async () => {
    const demo = await loginDemo("user");
    const auth = bearer(demo.accessToken);

    const changePassword = await api().post("/api/v1/auth/change-password").set(auth)
      .send({ currentPassword: demo.password, newPassword: "Brand!NewPass2026" });
    expect(changePassword.status).toBe(403);
    expect(changePassword.body.error).toBe("PROTECTED_ACCOUNT");
    expect((await api().patch("/api/v1/auth/me").set(auth).send({ firstName: "Hacked" })).status).toBe(403);
    expect((await api().post("/api/v1/auth/mfa/setup").set(auth)).status).toBe(403);
  });

  it("are exempt from lockout so nobody can lock the public demo", async () => {
    const demo = await loginDemo("user");
    for (let i = 0; i < 6; i++) await login(demo.email, "Wrong!Password123");
    expect((await login(demo.email, demo.password, {}, BROWSER_UA)).status).toBe(200);
  });
});
