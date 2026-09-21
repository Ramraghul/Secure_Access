// src/controllers/openid.controller.ts — OpenID Connect provider (Authorization Code + PKCE)
import { Request, Response } from "express";
import { prisma } from "../lib/prisma";
import { config } from "../config";
import { getSigningKey } from "../lib/keys";
import { randomToken, safeEqual, sha256Hex, verifyPkce } from "../utils/crypto";
import { AppError, notFound } from "../utils/errors";
import { clientIp, clientUserAgent } from "../utils/request";
import { validate, AuthorizeRequestSchema, ConsentSchema, CreateClientSchema, IdParamSchema } from "../utils/validation";
import { createSession, revokeSession, rotateRefreshToken } from "../services/session.service";
import {
  OAuthError, authenticateClient, buildRedirect, validateAuthorizationRequest, AuthorizationParams,
} from "../openid/clients";
import {
  SCOPE_DESCRIPTIONS, SUPPORTED_SCOPES, expiresInSeconds, issuerFor, signIdToken,
  signOidcAccessToken, userClaims, verifyOidcAccessToken,
} from "../openid/tokens";

const CONSENT_PAGE = "/oauth/consent.html";

function parseAuthorizationParams(input: unknown): AuthorizationParams {
  const parsed = AuthorizeRequestSchema.safeParse(input);
  if (!parsed.success) {
    const field = Object.keys(parsed.error.flatten().fieldErrors)[0] ?? "request";
    throw new OAuthError(400, "invalid_request", `Missing or invalid parameter: ${field}`);
  }
  return parsed.data;
}

// ── Discovery ───────────────────────────────────────────────────
export const discovery = (req: Request, res: Response): void => {
  const issuer = issuerFor(req);
  const base   = `${issuer}/api/v1/openid`;
  res.set("Cache-Control", "public, max-age=300").json({
    issuer,
    authorization_endpoint:                `${base}/authorize`,
    token_endpoint:                        `${base}/token`,
    userinfo_endpoint:                     `${base}/userinfo`,
    jwks_uri:                              `${base}/jwks`,
    revocation_endpoint:                   `${base}/revoke`,
    response_types_supported:              ["code"],
    response_modes_supported:              ["query"],
    grant_types_supported:                 ["authorization_code", "refresh_token"],
    subject_types_supported:               ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    scopes_supported:                      SUPPORTED_SCOPES,
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
    code_challenge_methods_supported:      ["S256"],
    authorization_response_iss_parameter_supported: true,
    claims_supported: [
      "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid",
      "name", "given_name", "family_name", "email", "email_verified",
    ],
  });
};

export const jwks = (_req: Request, res: Response): void => {
  res.set("Cache-Control", "public, max-age=300").json({ keys: [getSigningKey().publicJwk] });
};

// ── Authorization ───────────────────────────────────────────────

// Browser entry point: validates, then hands over to the consent page (login + approve)
export const authorize = async (req: Request, res: Response): Promise<void> => {
  const params = parseAuthorizationParams(req.query);
  const { errorRedirect } = await validateAuthorizationRequest(params, issuerFor(req));
  if (errorRedirect) return res.redirect(302, errorRedirect);

  const query = new URLSearchParams(
    Object.entries(params).filter((e): e is [string, string] => typeof e[1] === "string")
  );
  res.redirect(302, `${CONSENT_PAGE}?${query}`);
};

// Public details the consent page shows ("<client> wants to access …")
export const consentDetails = async (req: Request, res: Response): Promise<void> => {
  const params = parseAuthorizationParams(req.query);
  const { client, scopes, errorRedirect } = await validateAuthorizationRequest(params, issuerFor(req));
  if (errorRedirect) {
    res.status(400).json({ error: "invalid_request", error_description: "Invalid authorization request", redirectTo: errorRedirect });
    return;
  }

  res.json({
    client: { clientId: client.clientId, name: client.name, isConfidential: client.isConfidential },
    scopes: scopes.map(name => ({ name, description: SCOPE_DESCRIPTIONS[name] ?? name })),
    redirectUri: params.redirect_uri,
  });
};

// Signed-in user approves or denies. Returns where the browser should go next.
export const consent = async (req: Request, res: Response): Promise<void> => {
  const body   = validate(ConsentSchema, req.body);
  const issuer = issuerFor(req);
  const { client, scopes, errorRedirect } = await validateAuthorizationRequest(body, issuer);
  if (errorRedirect) { res.json({ redirectTo: errorRedirect }); return; }

  if (body.decision === "deny") {
    res.locals.auditEvent   = "OIDC_CONSENT_DENIED";
    res.locals.auditDetails = { clientId: client.clientId };
    res.json({ redirectTo: buildRedirect(body.redirect_uri, { error: "access_denied", state: body.state, iss: issuer }) });
    return;
  }

  const session = await prisma.session.findUniqueOrThrow({ where: { id: req.user!.sessionId } });
  const code    = randomToken(32);

  await prisma.authorizationCode.create({
    data: {
      codeHash:            sha256Hex(code),
      clientId:            client.clientId,
      userId:              req.user!.id,
      redirectUri:         body.redirect_uri,
      scope:               scopes.join(" "),
      nonce:               body.nonce ?? null,
      codeChallenge:       body.code_challenge ?? null,
      codeChallengeMethod: body.code_challenge ? "S256" : null,
      authTime:            session.createdAt,
      expiresAt:           new Date(Date.now() + config.oidc.codeTtlSeconds * 1000),
    },
  });

  res.locals.auditEvent   = "OIDC_CONSENT_GRANTED";
  res.locals.auditDetails = { clientId: client.clientId, scope: scopes.join(" ") };
  res.json({ redirectTo: buildRedirect(body.redirect_uri, { code, state: body.state, iss: issuer }) });
};

// ── Token endpoint ──────────────────────────────────────────────
const str = (value: unknown): string | undefined => (typeof value === "string" && value.length > 0 ? value : undefined);

async function issueTokens(req: Request, res: Response, p: {
  user: { id: string; email: string; firstName: string; lastName: string };
  clientId: string; scope: string; sessionId: string; authTime: Date;
  refreshToken: string; nonce?: string | null;
}): Promise<void> {
  const issuer      = issuerFor(req);
  const accessToken = signOidcAccessToken({ issuer, userId: p.user.id, clientId: p.clientId, scope: p.scope, sessionId: p.sessionId });
  const idToken     = signIdToken({ issuer, user: p.user, clientId: p.clientId, scope: p.scope, sessionId: p.sessionId, authTime: p.authTime, nonce: p.nonce });
  const offline     = p.scope.split(" ").includes("offline_access");

  res.locals.auditUserId = p.user.id;
  res.json({
    access_token: accessToken,
    token_type:   "Bearer",
    expires_in:   expiresInSeconds(accessToken),
    id_token:     idToken,
    scope:        p.scope,
    ...(offline ? { refresh_token: p.refreshToken } : {}),
  });
}

export const token = async (req: Request, res: Response): Promise<void> => {
  res.set({ "Cache-Control": "no-store", Pragma: "no-cache" });
  const body      = (req.body ?? {}) as Record<string, unknown>;
  const grantType = str(body.grant_type);

  if (grantType !== "authorization_code" && grantType !== "refresh_token") {
    throw new OAuthError(400, grantType ? "unsupported_grant_type" : "invalid_request",
      grantType ? `Unsupported grant_type: ${grantType}` : "grant_type is required");
  }

  const client = await authenticateClient(req);

  if (grantType === "authorization_code") {
    res.locals.auditEvent = "OIDC_CODE_EXCHANGE_FAILED";
    const code        = str(body.code);
    const redirectUri = str(body.redirect_uri);
    if (!code || !redirectUri) throw new OAuthError(400, "invalid_request", "code and redirect_uri are required");

    const invalidGrant = (why: string) => new OAuthError(400, "invalid_grant", why);
    const record = await prisma.authorizationCode.findUnique({
      where:   { codeHash: sha256Hex(code) },
      include: { user: true },
    });

    if (!record || record.clientId !== client.clientId) throw invalidGrant("Authorization code is invalid");

    if (record.consumedAt) {
      // Code replay: revoke everything issued from this grant (RFC 6749 §4.1.2)
      await prisma.session.updateMany({
        where: { userId: record.userId, clientId: record.clientId, createdAt: { gte: record.createdAt }, revokedAt: null },
        data:  { revokedAt: new Date(), revokedReason: "AUTH_CODE_REPLAY" },
      });
      res.locals.auditEvent = "OIDC_CODE_REPLAY";
      throw invalidGrant("Authorization code has already been used");
    }
    if (record.expiresAt <= new Date()) throw invalidGrant("Authorization code has expired");
    if (record.redirectUri !== redirectUri) throw invalidGrant("redirect_uri does not match the authorization request");

    if (record.codeChallenge) {
      const verifier = str(body.code_verifier);
      if (!verifier || !verifyPkce(verifier, record.codeChallenge, record.codeChallengeMethod ?? "")) {
        throw invalidGrant("PKCE verification failed");
      }
    } else if (!client.isConfidential) {
      throw invalidGrant("PKCE is required for public clients");
    }

    // Atomic single use
    const { count } = await prisma.authorizationCode.updateMany({
      where: { id: record.id, consumedAt: null },
      data:  { consumedAt: new Date() },
    });
    if (count === 0) throw invalidGrant("Authorization code has already been used");
    if (!record.user.isActive) throw invalidGrant("User account is deactivated");

    const { session, refreshToken } = await createSession({
      userId:    record.userId,
      clientId:  client.clientId,
      scope:     record.scope,
      ipAddress: clientIp(req),
      userAgent: clientUserAgent(req),
    });

    res.locals.auditEvent = "OIDC_TOKENS_ISSUED";
    return issueTokens(req, res, {
      user: record.user, clientId: client.clientId, scope: record.scope, sessionId: session.id,
      authTime: record.authTime, refreshToken, nonce: record.nonce,
    });
  }

  // refresh_token grant
  res.locals.auditEvent = "OIDC_REFRESH_FAILED";
  const presented = str(body.refresh_token);
  if (!presented) throw new OAuthError(400, "invalid_request", "refresh_token is required");

  let rotated;
  try {
    rotated = await rotateRefreshToken(presented, { clientId: client.clientId, ipAddress: clientIp(req), userAgent: clientUserAgent(req) });
  } catch (err) {
    if (err instanceof AppError) throw new OAuthError(400, "invalid_grant", err.message);
    throw err;
  }

  res.locals.auditEvent = "OIDC_TOKENS_REFRESHED";
  return issueTokens(req, res, {
    user: rotated.user, clientId: client.clientId, scope: rotated.session.scope ?? "openid",
    sessionId: rotated.session.id, authTime: rotated.session.createdAt, refreshToken: rotated.refreshToken,
  });
};

// ── UserInfo ────────────────────────────────────────────────────
export const userinfo = async (req: Request, res: Response): Promise<void> => {
  res.set("Cache-Control", "no-store");
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) throw new OAuthError(401, "invalid_token", "Bearer access token required");

  let payload;
  try {
    payload = verifyOidcAccessToken(header.slice(7).trim(), issuerFor(req));
  } catch {
    throw new OAuthError(401, "invalid_token", "Access token invalid or expired");
  }

  const session = await prisma.session.findUnique({ where: { id: payload.sid }, include: { user: true } });
  if (!session || session.revokedAt || session.expiresAt <= new Date() || session.clientId !== payload.client_id ||
      session.userId !== payload.sub || !session.user.isActive) {
    throw new OAuthError(401, "invalid_token", "Session revoked or expired");
  }

  const scopes = new Set(payload.scope.split(" "));
  if (!scopes.has("openid")) throw new OAuthError(403, "insufficient_scope", "The openid scope is required");

  res.locals.auditUserId = session.userId;
  res.json({ sub: session.userId, ...userClaims(session.user, scopes) });
};

// ── Revocation (RFC 7009) ───────────────────────────────────────
export const revoke = async (req: Request, res: Response): Promise<void> => {
  const client    = await authenticateClient(req);
  const presented = str((req.body ?? {}).token);
  if (!presented) throw new OAuthError(400, "invalid_request", "token is required");

  const dot = presented.indexOf(".");
  if (dot > 0 && presented.split(".").length === 2) {
    // Refresh token "<sessionId>.<secret>"
    const session = await prisma.session.findUnique({ where: { id: presented.slice(0, dot) } });
    if (session && session.clientId === client.clientId && safeEqual(session.refreshTokenHash, sha256Hex(presented.slice(dot + 1)))) {
      await revokeSession(session.id, "CLIENT_REVOKED");
    }
  } else {
    try {
      const payload = verifyOidcAccessToken(presented, issuerFor(req));
      if (payload.client_id === client.clientId) await revokeSession(payload.sid, "CLIENT_REVOKED");
    } catch { /* invalid tokens are ignored per RFC 7009 */ }
  }

  res.locals.auditEvent = "OIDC_TOKEN_REVOKED";
  // Always 200, so the endpoint cannot be used to probe token validity
  res.status(200).json({ success: true });
};

// ── Client management (admin) ──────────────────────────────────
const clientView = (c: { id: string; clientId: string; name: string; redirectUris: string[]; isConfidential: boolean; clientSecretHash: string | null; createdAt: Date }) => ({
  id: c.id, clientId: c.clientId, name: c.name, redirectUris: c.redirectUris,
  isConfidential: c.isConfidential, hasSecret: Boolean(c.clientSecretHash), createdAt: c.createdAt,
});

export const listClients = async (_req: Request, res: Response): Promise<void> => {
  const clients = await prisma.oAuthClient.findMany({ orderBy: { createdAt: "asc" } });
  res.json({ clients: clients.map(clientView) });
};

export const createClient = async (req: Request, res: Response): Promise<void> => {
  const body         = validate(CreateClientSchema, req.body);
  const clientSecret = body.isConfidential ? randomToken(32) : null;

  const client = await prisma.oAuthClient.create({
    data: {
      clientId:         `client_${randomToken(12)}`,
      clientSecretHash: clientSecret ? sha256Hex(clientSecret) : null,
      name:             body.name,
      redirectUris:     body.redirectUris,
      isConfidential:   body.isConfidential,
    },
  });

  res.locals.auditEvent   = "OIDC_CLIENT_CREATED";
  res.locals.auditDetails = { clientId: client.clientId };
  res.status(201).json({
    ...clientView(client),
    ...(clientSecret ? { clientSecret, warning: "Store the client secret now — it is shown only once" } : {}),
  });
};

export const deleteClient = async (req: Request, res: Response): Promise<void> => {
  const { id } = validate(IdParamSchema, req.params);
  const client = await prisma.oAuthClient.findUnique({ where: { id } });
  if (!client) throw notFound("CLIENT_NOT_FOUND", "Client not found");

  // Codes and sessions issued to the client cascade
  await prisma.oAuthClient.delete({ where: { id } });
  res.locals.auditEvent   = "OIDC_CLIENT_DELETED";
  res.locals.auditDetails = { clientId: client.clientId };
  res.json({ success: true, message: "Client deleted" });
};
