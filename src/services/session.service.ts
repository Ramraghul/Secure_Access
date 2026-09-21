// src/services/session.service.ts — Login sessions and rotating refresh tokens
import { prisma } from "../lib/prisma";
import { config } from "../config";
import { randomToken, safeEqual, sha256Hex, splitRefreshToken } from "../utils/crypto";
import { unauthorized } from "../utils/errors";

interface CreateSessionInput {
  userId:    string;
  deviceId?: string | null;
  clientId?: string | null;
  scope?:    string | null;
  ipAddress: string;
  userAgent: string;
}

const sessionExpiry = (): Date =>
  new Date(Date.now() + config.jwt.refreshTokenTtlDays * 24 * 60 * 60 * 1000);

export async function createSession(input: CreateSessionInput) {
  const secret  = randomToken(32);
  const session = await prisma.session.create({
    data: {
      userId:           input.userId,
      deviceId:         input.deviceId ?? null,
      clientId:         input.clientId ?? null,
      scope:            input.scope ?? null,
      ipAddress:        input.ipAddress,
      userAgent:        input.userAgent,
      refreshTokenHash: sha256Hex(secret),
      expiresAt:        sessionExpiry(),
    },
  });
  return { session, refreshToken: `${session.id}.${secret}` };
}

/**
 * Exchanges a refresh token for a new one (rotation).
 * Presenting a token that was already rotated means it was copied — the whole
 * session is revoked so neither the attacker nor the victim can keep using it.
 */
export async function rotateRefreshToken(
  token: string,
  ctx: { clientId: string | null; ipAddress: string; userAgent: string },
) {
  const invalid = unauthorized("INVALID_REFRESH_TOKEN", "Refresh token invalid, expired or revoked");
  const parts   = splitRefreshToken(token);
  if (!parts) throw invalid;

  const session = await prisma.session.findUnique({
    where:   { id: parts.sessionId },
    include: { user: { select: { id: true, email: true, firstName: true, lastName: true, isActive: true } } },
  });

  if (!session || session.clientId !== ctx.clientId) throw invalid;
  if (session.revokedAt || session.expiresAt <= new Date() || !session.user.isActive) throw invalid;

  const reuseDetected = unauthorized("REFRESH_TOKEN_REUSED", "Refresh token reuse detected — session revoked");

  if (!safeEqual(sha256Hex(parts.secret), session.refreshTokenHash)) {
    await revokeSession(session.id, "REFRESH_TOKEN_REUSE");
    throw reuseDetected;
  }

  const secret = randomToken(32);
  // Conditional update: if two requests race with the same token, only one wins
  const { count } = await prisma.session.updateMany({
    where: { id: session.id, refreshTokenHash: session.refreshTokenHash, revokedAt: null },
    data:  {
      refreshTokenHash: sha256Hex(secret),
      lastUsedAt:       new Date(),
      ipAddress:        ctx.ipAddress,
      userAgent:        ctx.userAgent,
    },
  });

  if (count === 0) {
    await revokeSession(session.id, "REFRESH_TOKEN_REUSE");
    throw reuseDetected;
  }

  return { session, user: session.user, refreshToken: `${session.id}.${secret}` };
}

export async function revokeSession(sessionId: string, reason: string): Promise<void> {
  await prisma.session.updateMany({
    where: { id: sessionId, revokedAt: null },
    data:  { revokedAt: new Date(), revokedReason: reason },
  });
}

export async function revokeAllSessions(
  userId: string,
  reason: string,
  opts: { exceptSessionId?: string; deviceId?: string } = {},
): Promise<number> {
  const { count } = await prisma.session.updateMany({
    where: {
      userId,
      revokedAt: null,
      ...(opts.exceptSessionId ? { id: { not: opts.exceptSessionId } } : {}),
      ...(opts.deviceId ? { deviceId: opts.deviceId } : {}),
    },
    data: { revokedAt: new Date(), revokedReason: reason },
  });
  return count;
}
