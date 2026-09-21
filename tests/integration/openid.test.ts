import { createHash, createPublicKey, randomBytes } from "crypto";
import jwt from "jsonwebtoken";
import {
  api, bearer, closeAll, createUserSession, loginAdmin, loginDemo, prisma, DEMO_CLIENT, TestSession,
} from "./helpers";

afterAll(closeAll);

// supertest listens on a random port per request, so pin the Host header to get a stable issuer
const HOST         = "auth.test";
const ISSUER       = `http://${HOST}`;
const REDIRECT_URI = `${ISSUER}/oauth/callback.html`;
const CLIENT_ID    = DEMO_CLIENT.clientId;

const pkce = () => {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
};

const authParams = (challenge: string, extra: Record<string, string> = {}) => ({
  response_type: "code",
  client_id: CLIENT_ID,
  redirect_uri: REDIRECT_URI,
  scope: "openid profile email offline_access",
  state: "state-123",
  nonce: "nonce-456",
  code_challenge: challenge,
  code_challenge_method: "S256",
  ...extra,
});

async function authorizeCode(user: TestSession, extra: Record<string, string> = {}) {
  const { verifier, challenge } = pkce();
  const res = await api().post("/api/v1/openid/consent").set("Host", HOST).set(bearer(user.accessToken))
    .send({ ...authParams(challenge, extra), decision: "allow" });
  expect(res.status).toBe(200);
  const url = new URL(res.body.redirectTo);
  return { code: url.searchParams.get("code")!, verifier, url };
}

const tokenRequest = (form: Record<string, string>) =>
  api().post("/api/v1/openid/token").set("Host", HOST).type("form").send(form);

async function exchange(user: TestSession, extra: Record<string, string> = {}) {
  const { code, verifier } = await authorizeCode(user, extra);
  const res = await tokenRequest({
    grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, client_id: CLIENT_ID, code_verifier: verifier,
  });
  expect(res.status).toBe(200);
  return res.body;
}

describe("discovery and keys", () => {
  it("serves discovery at the issuer root and the API alias", async () => {
    for (const path of ["/.well-known/openid-configuration", "/api/v1/openid/.well-known/openid-configuration"]) {
      const res = await api().get(path).set("Host", HOST);
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({
        issuer: ISSUER,
        token_endpoint: `${ISSUER}/api/v1/openid/token`,
        jwks_uri: `${ISSUER}/api/v1/openid/jwks`,
        code_challenge_methods_supported: ["S256"],
        id_token_signing_alg_values_supported: ["RS256"],
      });
    }
  });

  it("publishes a usable RSA JWK", async () => {
    const res = await api().get("/api/v1/openid/jwks");
    expect(res.status).toBe(200);
    const [key] = res.body.keys;
    expect(key).toMatchObject({ kty: "RSA", use: "sig", alg: "RS256", e: "AQAB", kid: expect.any(String) });
    expect(() => createPublicKey({ key, format: "jwk" })).not.toThrow();
  });
});

describe("authorization endpoint", () => {
  it("redirects a valid request to the consent page", async () => {
    const res = await api().get("/api/v1/openid/authorize").set("Host", HOST).query(authParams(pkce().challenge));
    expect(res.status).toBe(302);
    expect(res.headers.location).toMatch(/^\/oauth\/consent\.html\?/);
    expect(res.headers.location).toContain(`client_id=${CLIENT_ID}`);
  });

  it("never redirects for unknown clients or unregistered redirect URIs", async () => {
    const unknownClient = await api().get("/api/v1/openid/authorize").set("Host", HOST)
      .query(authParams(pkce().challenge, { client_id: "nope" }));
    expect(unknownClient.status).toBe(400);
    expect(unknownClient.body.error).toBe("invalid_client");

    const evilRedirect = await api().get("/api/v1/openid/authorize").set("Host", HOST)
      .query(authParams(pkce().challenge, { redirect_uri: "https://evil.example.com/cb" }));
    expect(evilRedirect.status).toBe(400);
    expect(evilRedirect.body.error).toBe("invalid_request");
  });

  it("reports other errors back to the client's redirect URI", async () => {
    const noPkce = await api().get("/api/v1/openid/authorize").set("Host", HOST)
      .query({ response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, scope: "openid", state: "s1" });
    expect(noPkce.status).toBe(302);
    const location = new URL(noPkce.headers.location);
    expect(`${location.origin}${location.pathname}`).toBe(REDIRECT_URI);
    expect(location.searchParams.get("error")).toBe("invalid_request");
    expect(location.searchParams.get("state")).toBe("s1");

    const noOpenid = await api().get("/api/v1/openid/authorize").set("Host", HOST)
      .query(authParams(pkce().challenge, { scope: "profile" }));
    expect(new URL(noOpenid.headers.location).searchParams.get("error")).toBe("invalid_scope");
  });

  it("describes the client and scopes for the consent screen", async () => {
    const res = await api().get("/api/v1/openid/consent").set("Host", HOST).query(authParams(pkce().challenge));
    expect(res.status).toBe(200);
    expect(res.body.client).toMatchObject({ clientId: CLIENT_ID, name: DEMO_CLIENT.name });
    expect(res.body.scopes.map((s: { name: string }) => s.name)).toEqual(["openid", "profile", "email", "offline_access"]);
  });

  it("requires a signed-in user to consent, and supports denial", async () => {
    const anonymous = await api().post("/api/v1/openid/consent").set("Host", HOST)
      .send({ ...authParams(pkce().challenge), decision: "allow" });
    expect(anonymous.status).toBe(401);

    const user = await createUserSession();
    const denied = await api().post("/api/v1/openid/consent").set("Host", HOST).set(bearer(user.accessToken))
      .send({ ...authParams(pkce().challenge), decision: "deny" });
    const url = new URL(denied.body.redirectTo);
    expect(url.searchParams.get("error")).toBe("access_denied");
    expect(url.searchParams.get("code")).toBeNull();
  });
});

describe("authorization code flow with PKCE", () => {
  it("issues verifiable tokens and user info", async () => {
    const user = await createUserSession();
    const { code, verifier, url } = await authorizeCode(user);
    expect(url.searchParams.get("state")).toBe("state-123");
    expect(url.searchParams.get("iss")).toBe(ISSUER);

    const res = await tokenRequest({
      grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, client_id: CLIENT_ID, code_verifier: verifier,
    });
    expect(res.status).toBe(200);
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.body).toMatchObject({ token_type: "Bearer", expires_in: 900, scope: "openid profile email offline_access" });

    // The id_token verifies against the published JWKS
    const jwks = (await api().get("/api/v1/openid/jwks")).body;
    const publicKey = createPublicKey({ key: jwks.keys[0], format: "jwk" });
    const idToken = jwt.verify(res.body.id_token, publicKey, { algorithms: ["RS256"], issuer: ISSUER, audience: CLIENT_ID }) as jwt.JwtPayload;
    expect(idToken).toMatchObject({ sub: user.userId, nonce: "nonce-456", email: user.email, given_name: "Test" });

    const info = await api().get("/api/v1/openid/userinfo").set("Host", HOST).set(bearer(res.body.access_token));
    expect(info.status).toBe(200);
    expect(info.body).toEqual({
      sub: user.userId, email: user.email, email_verified: false, name: "Test User", given_name: "Test", family_name: "User",
    });
  });

  it("keeps first-party and OIDC access tokens separate", async () => {
    const user = await createUserSession();
    const tokens = await exchange(user);

    expect((await api().get("/api/v1/auth/me").set(bearer(tokens.access_token))).status).toBe(401);
    const info = await api().get("/api/v1/openid/userinfo").set("Host", HOST).set(bearer(user.accessToken));
    expect(info.status).toBe(401);
    expect(info.body.error).toBe("invalid_token");
  });

  it("releases only the claims for granted scopes and omits refresh tokens without offline_access", async () => {
    const user = await createUserSession();
    const tokens = await exchange(user, { scope: "openid email" });
    expect(tokens.refresh_token).toBeUndefined();

    const info = await api().get("/api/v1/openid/userinfo").set("Host", HOST).set(bearer(tokens.access_token));
    expect(info.body).toEqual({ sub: user.userId, email: user.email, email_verified: false });
  });

  it("rejects a wrong PKCE verifier or redirect URI", async () => {
    const user = await createUserSession();

    const wrongVerifier = await authorizeCode(user);
    const res1 = await tokenRequest({
      grant_type: "authorization_code", code: wrongVerifier.code, redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID, code_verifier: pkce().verifier,
    });
    expect(res1.status).toBe(400);
    expect(res1.body).toEqual({ error: "invalid_grant", error_description: "PKCE verification failed" });

    const wrongRedirect = await authorizeCode(user);
    const res2 = await tokenRequest({
      grant_type: "authorization_code", code: wrongRedirect.code, redirect_uri: `${ISSUER}/other`,
      client_id: CLIENT_ID, code_verifier: wrongRedirect.verifier,
    });
    expect(res2.body.error).toBe("invalid_grant");
  });

  it("rejects expired codes", async () => {
    const user = await createUserSession();
    const { code, verifier } = await authorizeCode(user);
    await prisma.authorizationCode.updateMany({ where: { userId: user.userId }, data: { expiresAt: new Date(Date.now() - 1000) } });

    const res = await tokenRequest({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, client_id: CLIENT_ID, code_verifier: verifier });
    expect(res.body).toEqual({ error: "invalid_grant", error_description: "Authorization code has expired" });
  });

  it("treats code replay as an attack and revokes the tokens it produced", async () => {
    const user = await createUserSession();
    const { code, verifier } = await authorizeCode(user);
    const form = { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, client_id: CLIENT_ID, code_verifier: verifier };

    const first = await tokenRequest(form);
    expect(first.status).toBe(200);

    const replay = await tokenRequest(form);
    expect(replay.body.error).toBe("invalid_grant");

    const info = await api().get("/api/v1/openid/userinfo").set("Host", HOST).set(bearer(first.body.access_token));
    expect(info.status).toBe(401);
  });

  it("rotates refresh tokens and rejects reuse", async () => {
    const user = await createUserSession();
    const tokens = await exchange(user);

    const refreshed = await tokenRequest({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: CLIENT_ID });
    expect(refreshed.status).toBe(200);
    expect(refreshed.body.refresh_token).not.toBe(tokens.refresh_token);
    expect(refreshed.body.id_token).toEqual(expect.any(String));

    const reuse = await tokenRequest({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: CLIENT_ID });
    expect(reuse.status).toBe(400);
    expect(reuse.body.error).toBe("invalid_grant");
  });

  it("revokes tokens via the revocation endpoint and always answers 200", async () => {
    const user = await createUserSession();
    const tokens = await exchange(user);

    const revoke = await api().post("/api/v1/openid/revoke").set("Host", HOST).type("form")
      .send({ token: tokens.refresh_token, client_id: CLIENT_ID });
    expect(revoke.status).toBe(200);

    const refresh = await tokenRequest({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: CLIENT_ID });
    expect(refresh.body.error).toBe("invalid_grant");

    const garbage = await api().post("/api/v1/openid/revoke").set("Host", HOST).type("form").send({ token: "garbage", client_id: CLIENT_ID });
    expect(garbage.status).toBe(200);
  });

  it("shows OIDC sessions in the user's session list", async () => {
    const user = await createUserSession();
    await exchange(user);
    const res = await api().get("/api/v1/auth/sessions").set(bearer(user.accessToken));
    expect(res.body.sessions).toEqual(expect.arrayContaining([
      expect.objectContaining({ type: "oidc", clientId: CLIENT_ID, clientName: DEMO_CLIENT.name }),
    ]));
  });

  it("validates the grant type", async () => {
    const missing = await tokenRequest({ client_id: CLIENT_ID });
    expect(missing.body.error).toBe("invalid_request");
    const unsupported = await tokenRequest({ grant_type: "password", client_id: CLIENT_ID });
    expect(unsupported.body.error).toBe("unsupported_grant_type");
  });
});

describe("confidential clients and client management", () => {
  it("creates a confidential client whose secret is required and shown once", async () => {
    const admin = await loginAdmin();
    const created = await api().post("/api/v1/openid/clients").set(bearer(admin.accessToken))
      .send({ name: "Backend App", redirectUris: [`${ISSUER}/cb`], isConfidential: true });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ isConfidential: true, hasSecret: true, clientSecret: expect.any(String) });
    const { clientId, clientSecret, id } = created.body;

    const list = await api().get("/api/v1/openid/clients").set(bearer(admin.accessToken));
    expect(JSON.stringify(list.body)).not.toContain(clientSecret);
    expect(JSON.stringify(list.body)).not.toContain("clientSecretHash");

    // Confidential client without PKCE, authenticating with HTTP Basic
    const user = await createUserSession();
    const consent = await api().post("/api/v1/openid/consent").set("Host", HOST).set(bearer(user.accessToken))
      .send({ response_type: "code", client_id: clientId, redirect_uri: `${ISSUER}/cb`, scope: "openid", decision: "allow" });
    const code = new URL(consent.body.redirectTo).searchParams.get("code")!;
    const form = { grant_type: "authorization_code", code, redirect_uri: `${ISSUER}/cb` };

    const noSecret = await tokenRequest({ ...form, client_id: clientId });
    expect(noSecret.status).toBe(401);
    expect(noSecret.body.error).toBe("invalid_client");

    const withSecret = await api().post("/api/v1/openid/token").set("Host", HOST).auth(clientId, clientSecret).type("form").send(form);
    expect(withSecret.status).toBe(200);
    expect(withSecret.body.access_token).toEqual(expect.any(String));

    expect((await api().delete(`/api/v1/openid/clients/${id}`).set(bearer(admin.accessToken))).status).toBe(200);
  });

  it("requires client permissions", async () => {
    const auditor = await loginDemo("auditor");
    expect((await api().get("/api/v1/openid/clients").set(bearer(auditor.accessToken))).status).toBe(200);
    expect((await api().post("/api/v1/openid/clients").set(bearer(auditor.accessToken))
      .send({ name: "Nope", redirectUris: ["/cb"] })).status).toBe(403);

    const user = await createUserSession();
    expect((await api().get("/api/v1/openid/clients").set(bearer(user.accessToken))).status).toBe(403);
  });
});
