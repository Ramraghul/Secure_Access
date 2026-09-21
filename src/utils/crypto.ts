// src/utils/crypto.ts — Random tokens, hashing and constant-time comparison
import { createHash, randomBytes, timingSafeEqual } from "crypto";

export const randomToken = (bytes = 32): string => randomBytes(bytes).toString("base64url");

export const sha256Hex = (value: string): string =>
  createHash("sha256").update(value).digest("hex");

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

// PKCE (RFC 7636). Only S256 is accepted — "plain" offers no protection.
export function verifyPkce(verifier: string, challenge: string, method: string): boolean {
  if (method !== "S256") return false;
  const computed = createHash("sha256").update(verifier).digest("base64url");
  return safeEqual(computed, challenge);
}

// Refresh tokens are opaque: "<sessionId>.<secret>". Only SHA-256(secret) is stored.
export function splitRefreshToken(token: string): { sessionId: string; secret: string } | null {
  const dot = token.indexOf(".");
  if (dot <= 0 || dot === token.length - 1) return null;
  return { sessionId: token.slice(0, dot), secret: token.slice(dot + 1) };
}
