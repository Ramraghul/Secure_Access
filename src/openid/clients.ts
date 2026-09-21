// src/openid/clients.ts — Client authentication, redirect URI and request validation
import { Request, Response, NextFunction } from "express";
import { OAuthClient } from "@prisma/client";
import { prisma } from "../lib/prisma";
import { safeEqual, sha256Hex } from "../utils/crypto";
import { SUPPORTED_SCOPES } from "./tokens";

// RFC 6749 §5.2 error: { error, error_description }
export class OAuthError extends Error {
  constructor(
    public readonly status: number,
    public readonly error: string,
    public readonly description: string,
  ) {
    super(description);
    this.name = "OAuthError";
  }
}

// Wraps an OAuth endpoint so OAuthErrors use the RFC response shape
export const oauthHandler =
  (fn: (req: Request, res: Response) => Promise<void>) =>
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      await fn(req, res);
    } catch (err) {
      if (!(err instanceof OAuthError)) return next(err);
      res.locals.auditEvent ??= "OIDC_ERROR";
      res.locals.auditDetails = { ...res.locals.auditDetails, oauthError: err.error };
      if (err.status === 401) res.set("WWW-Authenticate", `Bearer error="${err.error}"`);
      res.set("Cache-Control", "no-store")
        .status(err.status)
        .json({ error: err.error, error_description: err.description });
    }
  };

// Stored URIs starting with "/" are relative to this server's origin, so the
// seeded demo client works on localhost, Render and Vercel without changes.
export const resolveRedirectUri = (stored: string, issuer: string): string =>
  stored.startsWith("/") ? `${issuer}${stored}` : stored;

const isRegisteredRedirectUri =(client: OAuthClient, redirectUri: string, issuer: string): boolean =>
  client.redirectUris.some(uri => resolveRedirectUri(uri, issuer) === redirectUri);

export interface AuthorizationParams {
  response_type: string;
  client_id: string;
  redirect_uri: string;
  scope: string;
  state?: string;
  nonce?: string;
  code_challenge?: string;
  code_challenge_method?: string;
}

export function buildRedirect(redirectUri: string, params: Record<string, string | undefined>): string {
  const url = new URL(redirectUri);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) url.searchParams.set(key, value);
  }
  return url.toString();
}

/**
 * Validates an authorization request.
 * Unknown clients and unregistered redirect URIs throw (never redirect to an
 * unverified URI). Other problems are reported back to the client's redirect_uri.
 */
export async function validateAuthorizationRequest(q: AuthorizationParams, issuer: string): Promise<{
  client: OAuthClient;
  scopes: string[];
  errorRedirect: string | null;
}> {
  const client = await prisma.oAuthClient.findUnique({ where: { clientId: q.client_id } });
  if (!client) throw new OAuthError(400, "invalid_client", "Unknown client_id");
  if (!isRegisteredRedirectUri(client, q.redirect_uri, issuer)) {
    throw new OAuthError(400, "invalid_request", "redirect_uri is not registered for this client");
  }

  const scopes = [...new Set(q.scope.split(/\s+/).filter(Boolean))];
  const fail = (error: string, description: string) => ({
    client,
    scopes,
    errorRedirect: buildRedirect(q.redirect_uri, { error, error_description: description, state: q.state, iss: issuer }),
  });

  if (q.response_type !== "code") {
    return fail("unsupported_response_type", "Only response_type=code is supported");
  }
  if (!scopes.includes("openid")) {
    return fail("invalid_scope", "The openid scope is required");
  }
  const unknown = scopes.filter(s => !(SUPPORTED_SCOPES as readonly string[]).includes(s));
  if (unknown.length > 0) {
    return fail("invalid_scope", `Unsupported scope: ${unknown.join(" ")}`);
  }
  if (q.code_challenge && q.code_challenge_method !== "S256") {
    return fail("invalid_request", "code_challenge_method must be S256");
  }
  if (!client.isConfidential && !q.code_challenge) {
    return fail("invalid_request", "PKCE (code_challenge with S256) is required for public clients");
  }

  return { client, scopes, errorRedirect: null };
}

/**
 * Authenticates the client at the token/revocation endpoints.
 * Confidential clients: client_secret_basic or client_secret_post.
 * Public clients: client_id only (they must use PKCE).
 */
export async function authenticateClient(req: Request): Promise<OAuthClient> {
  let clientId: string | undefined;
  let clientSecret: string | undefined;

  const header = req.headers.authorization;
  if (header?.startsWith("Basic ")) {
    const decoded = Buffer.from(header.slice(6), "base64").toString("utf8");
    const sep = decoded.indexOf(":");
    if (sep < 0) throw new OAuthError(401, "invalid_client", "Malformed Basic authorization header");
    clientId     = decodeURIComponent(decoded.slice(0, sep));
    clientSecret = decodeURIComponent(decoded.slice(sep + 1));
  } else {
    const body = req.body as Record<string, unknown>;
    clientId     = typeof body.client_id === "string" ? body.client_id : undefined;
    clientSecret = typeof body.client_secret === "string" ? body.client_secret : undefined;
  }

  if (!clientId) throw new OAuthError(401, "invalid_client", "Client authentication required");

  const client = await prisma.oAuthClient.findUnique({ where: { clientId } });
  if (!client) throw new OAuthError(401, "invalid_client", "Client authentication failed");

  if (client.isConfidential) {
    if (!clientSecret || !client.clientSecretHash || !safeEqual(sha256Hex(clientSecret), client.clientSecretHash)) {
      throw new OAuthError(401, "invalid_client", "Client authentication failed");
    }
  } else if (clientSecret) {
    throw new OAuthError(401, "invalid_client", "Public clients must not send a client_secret");
  }

  return client;
}
