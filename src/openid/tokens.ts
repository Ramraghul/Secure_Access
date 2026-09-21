// src/openid/tokens.ts — RS256 tokens issued to OpenID Connect clients
import jwt, { JwtPayload, SignOptions } from "jsonwebtoken";
import { Request } from "express";
import { config } from "../config";
import { getSigningKey } from "../lib/keys";

export const SUPPORTED_SCOPES = ["openid", "profile", "email", "offline_access"] as const;

export const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid:         "Sign you in and share your account ID",
  profile:        "See your first and last name",
  email:          "See your email address",
  offline_access: "Stay signed in when you are not using the app (refresh tokens)",
};

const ID_TOKEN_TTL = "1h";

// Issuer = PUBLIC_URL when configured, otherwise this request's origin
export function issuerFor(req: Request): string {
  return config.publicUrl || `${req.protocol}://${req.get("host")}`;
}

export interface OidcAccessTokenPayload extends JwtPayload {
  sub:       string;
  scope:     string;
  sid:       string;
  client_id: string;
  token_use: "access";
}

interface ClaimsUser {
  id:        string;
  email:     string;
  firstName: string;
  lastName:  string;
}

// Standard claims released per scope
export function userClaims(user: ClaimsUser, scopes: Set<string>): Record<string, unknown> {
  const claims: Record<string, unknown> = {};
  if (scopes.has("profile")) {
    claims.name        = `${user.firstName} ${user.lastName}`.trim();
    claims.given_name  = user.firstName;
    claims.family_name = user.lastName;
  }
  if (scopes.has("email")) {
    claims.email          = user.email;
    claims.email_verified = false; // no email verification flow in this project
  }
  return claims;
}

const signOptions = (issuer: string, subject: string, audience: string, expiresIn: string): SignOptions => ({
  algorithm: "RS256",
  keyid:     getSigningKey().kid,
  issuer,
  subject,
  audience,
  expiresIn: expiresIn as SignOptions["expiresIn"],
});

export function signOidcAccessToken(p: {
  issuer: string; userId: string; clientId: string; scope: string; sessionId: string;
}): string {
  return jwt.sign(
    { scope: p.scope, sid: p.sessionId, client_id: p.clientId, token_use: "access" },
    getSigningKey().privateKey,
    signOptions(p.issuer, p.userId, p.clientId, config.oidc.accessTokenTtl),
  );
}

export function signIdToken(p: {
  issuer: string; user: ClaimsUser; clientId: string; scope: string;
  sessionId: string; authTime: Date; nonce?: string | null;
}): string {
  const claims: Record<string, unknown> = {
    auth_time: Math.floor(p.authTime.getTime() / 1000),
    sid:       p.sessionId,
    ...(p.nonce ? { nonce: p.nonce } : {}),
    ...userClaims(p.user, new Set(p.scope.split(" "))),
  };
  return jwt.sign(claims, getSigningKey().privateKey, signOptions(p.issuer, p.user.id, p.clientId, ID_TOKEN_TTL));
}

export function verifyOidcAccessToken(token: string, issuer: string): OidcAccessTokenPayload {
  const payload = jwt.verify(token, getSigningKey().publicKey, {
    algorithms: ["RS256"],
    issuer,
  }) as JwtPayload;

  if (payload.token_use !== "access" || typeof payload.sub !== "string" || typeof payload.sid !== "string") {
    throw new Error("WRONG_TOKEN_TYPE");
  }
  return payload as OidcAccessTokenPayload;
}

export function expiresInSeconds(token: string): number {
  const decoded = jwt.decode(token) as JwtPayload | null;
  return decoded?.exp && decoded.iat ? decoded.exp - decoded.iat : 0;
}
