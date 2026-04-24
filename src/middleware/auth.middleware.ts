// src/middleware/auth.middleware.ts
import { Request, Response, NextFunction } from "express";
import { verifyJwt } from "../utils/jwt";
import { prisma } from "../lib/prisma";

export const authenticate = async (
  req: Request, res: Response, next: NextFunction
): Promise<void> => {
  try {
    const header = req.headers.authorization;
    if (!header?.startsWith("Bearer ")) {
      res.status(401).json({ error: "ACCESS_TOKEN_REQUIRED", message: "Bearer token required" });
      return;
    }

    const payload = verifyJwt(header.split(" ")[1]);

    const user = await prisma.user.findUnique({
      where:  { id: payload.id },
      select: { id: true, email: true, isActive: true, mfaEnabled: true },
    });

    if (!user || !user.isActive) {
      res.status(401).json({ error: "INVALID_ACCOUNT", message: "Account not found or deactivated" });
      return;
    }

    req.user = {
      id:         user.id,
      email:      user.email,
      mfaEnabled: user.mfaEnabled,
      deviceId:   payload.deviceId ?? null,
    };

    next();
  } catch {
    res.status(401).json({ error: "INVALID_TOKEN", message: "Token invalid or expired" });
  }
};

// For public endpoints that optionally benefit from user context
export const authenticateOptional = async (
  req: Request, _res: Response, next: NextFunction
): Promise<void> => {
  try {
    const header = req.headers.authorization;
    if (header?.startsWith("Bearer ")) {
      const payload = verifyJwt(header.split(" ")[1]);
      const user = await prisma.user.findUnique({
        where:  { id: payload.id },
        select: { id: true, email: true, isActive: true, mfaEnabled: true },
      });
      if (user?.isActive) {
        req.user = { id: user.id, email: user.email, mfaEnabled: user.mfaEnabled, deviceId: payload.deviceId ?? null };
      }
    }
  } catch { /* ignore */ }
  next();
};
