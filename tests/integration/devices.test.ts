import { api, bearer, closeAll, createUserSession, enableMfa, freshTotp, loginOk, registerUser, BROWSER_UA } from "./helpers";

afterAll(closeAll);

const PHONE_UA = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Mobile Safari/537.36";

describe("devices", () => {
  it("records one device per browser and marks the current one", async () => {
    const { email, password } = await registerUser();
    const desktop = await loginOk(email, password, BROWSER_UA);
    await loginOk(email, password, BROWSER_UA); // same browser → same device
    await loginOk(email, password, PHONE_UA);

    const res = await api().get("/api/v1/devices").set(bearer(desktop.accessToken)).set("User-Agent", BROWSER_UA);
    expect(res.status).toBe(200);
    expect(res.body.devices).toHaveLength(2);

    const current = res.body.devices.find((d: { current: boolean }) => d.current);
    expect(current.deviceName).toContain("Chrome");
    expect(current.activeSessions).toBe(2);
  });

  it("describes the calling device", async () => {
    const session = await createUserSession();
    const res = await api().get("/api/v1/devices/current").set(bearer(session.accessToken)).set("User-Agent", BROWSER_UA);
    expect(res.status).toBe(200);
    expect(res.body.currentDevice).toMatchObject({ isKnown: true, isTrusted: false, userAgent: BROWSER_UA });
    expect(res.body.currentDevice.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it("refuses to trust a device while MFA is off (trust only skips MFA)", async () => {
    const session = await createUserSession();
    const auth = bearer(session.accessToken);
    const [device] = (await api().get("/api/v1/devices").set(auth)).body.devices;

    const res = await api().post(`/api/v1/devices/${device.id}/trust`).set(auth).send({ code: "123456" });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("MFA_NOT_ENABLED");
  });

  it("needs a current MFA code to trust a device, trusts it for 30 days, and can un-trust it", async () => {
    const session = await createUserSession();
    const { secret } = await enableMfa(session);
    const auth = bearer(session.accessToken);
    const [device] = (await api().get("/api/v1/devices").set(auth)).body.devices;
    const trust = (body: object) => api().post(`/api/v1/devices/${device.id}/trust`).set(auth).send(body);

    expect((await trust({})).body.error).toBe("VALIDATION_ERROR");
    expect((await trust({ code: "000000" })).body.error).toBe("INVALID_MFA");

    const ok = await trust({ code: await freshTotp(session.userId, secret) });
    expect(ok.status).toBe(200);
    const days = (new Date(ok.body.trustedUntil).getTime() - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(29.9);
    expect(days).toBeLessThanOrEqual(30);
    expect((await api().get("/api/v1/devices").set(auth)).body.devices[0]).toMatchObject({ isTrusted: true, trustedUntil: ok.body.trustedUntil });

    expect((await api().post(`/api/v1/devices/${device.id}/revoke`).set(auth)).status).toBe(200);
    expect((await api().get("/api/v1/devices").set(auth)).body.devices[0]).toMatchObject({ isTrusted: false, trustedUntil: null });
  });

  it("removing a device signs out its sessions", async () => {
    const { email, password } = await registerUser();
    const desktop = await loginOk(email, password, BROWSER_UA);
    const phone   = await loginOk(email, password, PHONE_UA);

    const devices = (await api().get("/api/v1/devices").set(bearer(desktop.accessToken)).set("User-Agent", BROWSER_UA)).body.devices;
    const phoneDevice = devices.find((d: { current: boolean }) => !d.current);

    const res = await api().delete(`/api/v1/devices/${phoneDevice.id}`).set(bearer(desktop.accessToken));
    expect(res.status).toBe(200);
    expect(res.body.revokedSessions).toBe(1);
    expect((await api().get("/api/v1/auth/me").set(bearer(phone.accessToken))).status).toBe(401);
    expect((await api().get("/api/v1/auth/me").set(bearer(desktop.accessToken))).status).toBe(200);
  });

  it("hides other users' devices behind 404", async () => {
    const owner = await createUserSession();
    const intruder = await createUserSession();
    const [device] = (await api().get("/api/v1/devices").set(bearer(owner.accessToken))).body.devices;

    for (const req of [
      api().post(`/api/v1/devices/${device.id}/trust`),
      api().post(`/api/v1/devices/${device.id}/revoke`),
      api().delete(`/api/v1/devices/${device.id}`),
    ]) {
      const res = await req.set(bearer(intruder.accessToken));
      expect(res.status).toBe(404);
      expect(res.body.error).toBe("DEVICE_NOT_FOUND");
    }
  });

  it("validates device ids", async () => {
    const session = await createUserSession();
    expect((await api().post("/api/v1/devices/abc/trust").set(bearer(session.accessToken))).status).toBe(400);
  });
});
