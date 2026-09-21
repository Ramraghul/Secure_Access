// src/middleware/auth.middleware.ts
import { Request, Response, NextFunction } from "express";
import { verifyToken } from "../utils/jwt";
import { unauthorized } from "../utils/errors";
import { prisma } from "../lib/prisma";

/**
 * Requires a valid first-party access token AND a live session.
 * Checking the session on every request is what makes logout, "sign out
 * everywhere", password changes and account deactivation take effect immediately
 * instead of waiting for the JWT to expire.
 */
export const authenticate = async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) {
    return next(unauthorized("ACCESS_TOKEN_REQUIRED", "Bearer token required"));
  }

  let payload;
  try {
    payload = verifyToken(header.slice(7).trim(), "access");
  } catch {
    return next(unauthorized("INVALID_TOKEN", "Token invalid or expired"));
  }

  try {
    const session = await prisma.session.findUnique({
      where:  { id: payload.sid },
      select: {
        userId: true, deviceId: true, clientId: true, revokedAt: true, expiresAt: true,
        user: { select: { id: true, email: true, isActive: true, mfaEnabled: true, isProtected: true } },
      },
    });

    if (!session || session.userId !== payload.sub || session.clientId !== null ||
        session.revokedAt || session.expiresAt <= new Date()) {
      return next(unauthorized("SESSION_REVOKED", "Session expired or revoked"));
    }

    if (!session.user.isActive) {
      return next(unauthorized("INVALID_ACCOUNT", "Account not found or deactivated"));
    }

    req.user = {
      id:          session.user.id,
      email:       session.user.email,
      mfaEnabled:  session.user.mfaEnabled,
      isProtected: session.user.isProtected,
      sessionId:   payload.sid,
      deviceId:    session.deviceId,
    };
    next();
  } catch (err) {
    next(err);
  }
};
