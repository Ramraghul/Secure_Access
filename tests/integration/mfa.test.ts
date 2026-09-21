import {
  api, bearer, closeAll, createUserSession, enableMfa, freshTotp, login, prisma, totpCode,
  BROWSER_UA, TestSession,
} from "./helpers";

afterAll(closeAll);

const OTHER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0";

describe("MFA enrolment", () => {
  it("returns a QR code and backup codes, stores only hashes, and activates after verification", async () => {
    const session = await createUserSession();
    const auth = bearer(session.accessToken);

    const setup = await api().post("/api/v1/auth/mfa/setup").set(auth);
    expect(setup.status).toBe(200);
    expect(setup.body.qrCode).toMatch(/^data:image\/png;base64,/);
    expect(setup.body.backupCodes).toHaveLength(10);

    const pending = await prisma.user.findUniqueOrThrow({ where: { id: session.userId } });
    expect(pending.mfaEnabled).toBe(false);
    for (const code of setup.body.backupCodes) expect(pending.backupCodesHashed).not.toContain(code);

    const wrong = await api().post("/api/v1/auth/mfa/verify").set(auth).send({ token: "000000" });
    expect(wrong.status).toBe(400);
    expect(wrong.body.error).toBe("INVALID_MFA_CODE");

    const verify = await api().post("/api/v1/auth/mfa/verify").set(auth).send({ token: totpCode(setup.body.secret) });
    expect(verify.status).toBe(200);
    expect((await prisma.user.findUniqueOrThrow({ where: { id: session.userId } })).mfaEnabled).toBe(true);

    const again = await api().post("/api/v1/auth/mfa/setup").set(auth);
    expect(again.status).toBe(409);
    expect(again.body.error).toBe("MFA_ALREADY_ENABLED");
  });

  it("requires setup before verification", async () => {
    const session = await createUserSession();
    const res = await api().post("/api/v1/auth/mfa/verify").set(bearer(session.accessToken)).send({ token: "123456" });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("MFA_NOT_INITIALIZED");
  });
});

describe("login with MFA enabled", () => {
  let session: TestSession;
  let secret: string;
  let backupCodes: string[];

  beforeEach(async () => {
    session = await createUserSession();
    ({ secret, backupCodes } = await enableMfa(session));
  });

  const startLogin = async (userAgent = BROWSER_UA) => {
    const res = await login(session.email, session.password, {}, userAgent);
    expect(res.status).toBe(202);
    return res.body.mfaToken as string;
  };

  it("answers 202 with an MFA token instead of access tokens", async () => {
    const res = await login(session.email, session.password);
    expect(res.status).toBe(202);
    expect(res.body).toMatchObject({ mfaRequired: true, mfaToken: expect.any(String) });
    expect(res.body.expiresIn).toBeGreaterThan(290);
    expect(res.body.accessToken).toBeUndefined();
  });

  it("completes the two-step flow with a TOTP code", async () => {
    const mfaToken = await startLogin();
    const res = await api().post("/api/v1/auth/login/mfa").set("User-Agent", BROWSER_UA)
      .send({ mfaToken, code: await freshTotp(session.userId, secret) });
    expect(res.status).toBe(200);
    expect(res.body.accessToken).toEqual(expect.any(String));
    expect(res.body.user.mfaEnabled).toBe(true);
  });

  it("accepts the code in a single login request", async () => {
    const res = await login(session.email, session.password, { totp_code: await freshTotp(session.userId, secret) });
    expect(res.status).toBe(200);
  });

  it("rejects a wrong code and counts it toward lockout", async () => {
    const mfaToken = await startLogin();
    const res = await api().post("/api/v1/auth/login/mfa").set("User-Agent", BROWSER_UA).send({ mfaToken, code: "000000" });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("INVALID_MFA");
    expect((await prisma.user.findUniqueOrThrow({ where: { id: session.userId } })).failedLoginAttempts).toBe(1);
  });

  it("rejects a replayed TOTP code", async () => {
    const code = await freshTotp(session.userId, secret);
    const first = await api().post("/api/v1/auth/login/mfa").set("User-Agent", BROWSER_UA).send({ mfaToken: await startLogin(), code });
    expect(first.status).toBe(200);

    const replay = await api().post("/api/v1/auth/login/mfa").set("User-Agent", BROWSER_UA).send({ mfaToken: await startLogin(), code });
    expect(replay.status).toBe(401);
    expect(replay.body.error).toBe("INVALID_MFA");
  });

  it("accepts each backup code exactly once", async () => {
    const [code] = backupCodes;
    const first = await api().post("/api/v1/auth/login/mfa").set("User-Agent", BROWSER_UA).send({ mfaToken: await startLogin(), backupCode: code });
    expect(first.status).toBe(200);

    const again = await api().post("/api/v1/auth/login/mfa").set("User-Agent", BROWSER_UA).send({ mfaToken: await startLogin(), backupCode: code });
    expect(again.status).toBe(401);

    const stored = await prisma.user.findUniqueOrThrow({ where: { id: session.userId } });
    expect(JSON.parse(stored.backupCodesHashed!)).toHaveLength(9);
  });

  it("binds the MFA token to the device that passed the password step", async () => {
    const mfaToken = await startLogin(BROWSER_UA);
    const res = await api().post("/api/v1/auth/login/mfa").set("User-Agent", OTHER_UA)
      .send({ mfaToken, code: await freshTotp(session.userId, secret) });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("INVALID_MFA_TOKEN");
  });

  it("does not accept an access token as an MFA token", async () => {
    const res = await api().post("/api/v1/auth/login/mfa").set("User-Agent", BROWSER_UA)
      .send({ mfaToken: session.accessToken, code: await freshTotp(session.userId, secret) });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("INVALID_MFA_TOKEN");
  });

  it("skips MFA on a remembered device until trust is revoked", async () => {
    const remembered = await api().post("/api/v1/auth/login/mfa").set("User-Agent", BROWSER_UA)
      .send({ mfaToken: await startLogin(), code: await freshTotp(session.userId, secret), rememberDevice: true });
    expect(remembered.status).toBe(200);
    expect(remembered.body.device.isTrusted).toBe(true);
    expect(remembered.body.mfa).toBe("verified");

    // Same device: straight in, and the response says why. A different browser still needs MFA.
    const skipped = await login(session.email, session.password);
    expect(skipped.status).toBe(200);
    expect(skipped.body.mfa).toBe("trusted_device");
    expect(new Date(skipped.body.device.trustedUntil).getTime()).toBeGreaterThan(Date.now() + 29 * 86_400_000);
    expect((await login(session.email, session.password, {}, OTHER_UA)).status).toBe(202);

    const revoke = await api().post(`/api/v1/devices/${remembered.body.device.id}/revoke`).set(bearer(remembered.body.accessToken));
    expect(revoke.status).toBe(200);
    expect((await login(session.email, session.password)).status).toBe(202);
  });

  it("asks for the code on every login unless the device is remembered", async () => {
    for (let i = 0; i < 2; i++) {
      const res = await api().post("/api/v1/auth/login/mfa").set("User-Agent", BROWSER_UA)
        .send({ mfaToken: await startLogin(), code: await freshTotp(session.userId, secret) });
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ mfa: "verified", device: { isTrusted: false, trustedUntil: null } });
    }
    expect((await login(session.email, session.password)).status).toBe(202);
  });

  it("regression: a signed-in session cannot switch MFA off by trusting a device without a code", async () => {
    const [device] = (await api().get("/api/v1/devices").set(bearer(session.accessToken))).body.devices;
    const res = await api().post(`/api/v1/devices/${device.id}/trust`).set(bearer(session.accessToken));
    expect(res.status).toBe(400);
    expect((await login(session.email, session.password)).status).toBe(202);
  });

  it("asks for the code again when the remembered period ends", async () => {
    const remembered = await api().post("/api/v1/auth/login/mfa").set("User-Agent", BROWSER_UA)
      .send({ mfaToken: await startLogin(), code: await freshTotp(session.userId, secret), rememberDevice: true });
    expect(remembered.body.device.isTrusted).toBe(true);

    await prisma.device.update({ where: { id: remembered.body.device.id }, data: { trustedUntil: new Date(Date.now() - 1000) } });
    expect((await login(session.email, session.password)).status).toBe(202);
  });

  it("forgets every remembered device when the password changes", async () => {
    const remembered = await api().post("/api/v1/auth/login/mfa").set("User-Agent", BROWSER_UA)
      .send({ mfaToken: await startLogin(), code: await freshTotp(session.userId, secret), rememberDevice: true });
    const newPassword = "Another!Passphrase9";
    const change = await api().post("/api/v1/auth/change-password").set(bearer(remembered.body.accessToken))
      .send({ currentPassword: session.password, newPassword });
    expect(change.status).toBe(200);
    expect((await login(session.email, newPassword)).status).toBe(202);
  });
});

describe("POST /api/v1/auth/mfa/disable", () => {
  it("requires the password and a valid second factor", async () => {
    const session = await createUserSession();
    const { secret } = await enableMfa(session);
    const auth = bearer(session.accessToken);

    const wrongPassword = await api().post("/api/v1/auth/mfa/disable").set(auth)
      .send({ password: "Wrong!Password123", code: await freshTotp(session.userId, secret) });
    expect(wrongPassword.status).toBe(401);
    expect(wrongPassword.body.error).toBe("INVALID_CREDENTIALS");

    const wrongCode = await api().post("/api/v1/auth/mfa/disable").set(auth).send({ password: session.password, code: "000000" });
    expect(wrongCode.status).toBe(401);
    expect(wrongCode.body.error).toBe("INVALID_MFA");

    const ok = await api().post("/api/v1/auth/mfa/disable").set(auth)
      .send({ password: session.password, code: await freshTotp(session.userId, secret) });
    expect(ok.status).toBe(200);

    const user = await prisma.user.findUniqueOrThrow({ where: { id: session.userId } });
    expect(user).toMatchObject({ mfaEnabled: false, mfaSecret: null, backupCodesHashed: null });
    expect((await login(session.email, session.password)).status).toBe(200);
  });

  it("returns 400 when MFA is not enabled", async () => {
    const session = await createUserSession();
    const res = await api().post("/api/v1/auth/mfa/disable").set(bearer(session.accessToken))
      .send({ password: session.password, code: "123456" });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("MFA_NOT_ENABLED");
  });
});
