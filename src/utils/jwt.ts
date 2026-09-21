// src/utils/jwt.ts — First-party JWTs (HS512, signed with JWT_SECRET)
// OpenID Connect tokens for third-party clients are RS256 — see src/openid/tokens.ts
import jwt, { SignOptions } from "jsonwebtoken";
import { config } from "../config";

const ISSUER = "secureaccess";

export interface AccessTokenPayload {
  sub:   string; // user id
  email: string;
  sid:   string; // session id
  type:  "access";
  iat:   number;
  exp:   number;
}

// Short-lived token proving the password step passed; exchanged at /auth/login/mfa
export interface MfaTokenPayload {
  sub:  string;
  fp:   string; // device fingerprint the password step came from
  type: "mfa";
  iat:  number;
  exp:  number;
}

type TokenPayloads = { access: AccessTokenPayload; mfa: MfaTokenPayload };

const sign = (payload: object, expiresIn: string): string =>
  jwt.sign(payload, config.jwt.secret, {
    algorithm: "HS512",
    issuer:    ISSUER,
    expiresIn: expiresIn as SignOptions["expiresIn"],
  });

export const signAccessToken = (userId: string, email: string, sessionId: string): string =>
  sign({ sub: userId, email, sid: sessionId, type: "access" }, config.jwt.accessTokenTtl);

export const signMfaToken = (userId: string, fingerprint: string): string =>
  sign({ sub: userId, fp: fingerprint, type: "mfa" }, config.jwt.mfaTokenTtl);

// Verifies signature, algorithm, issuer, expiry AND token type, so an MFA
// token can never be used where an access token is expected.
export function verifyToken<T extends keyof TokenPayloads>(token: string, type: T): TokenPayloads[T] {
  const payload = jwt.verify(token, config.jwt.secret, {
    algorithms: ["HS512"],
    issuer:     ISSUER,
  }) as jwt.JwtPayload;

  if (payload.type !== type || typeof payload.sub !== "string") {
    throw new Error("WRONG_TOKEN_TYPE");
  }
  return payload as unknown as TokenPayloads[T];
}

export function secondsUntilExpiry(token: string): number {
  const decoded = jwt.decode(token) as jwt.JwtPayload | null;
  return decoded?.exp ? Math.max(0, decoded.exp - Math.floor(Date.now() / 1000)) : 0;
}
