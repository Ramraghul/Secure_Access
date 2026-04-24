// src/middleware/device.middleware.ts — Stronger fingerprinting + trust logic
import { Request, Response, NextFunction } from "express";
import { createHash } from "crypto";
import { prisma } from "../lib/prisma";
import DeviceDetector from "node-device-detector";

const detector = new DeviceDetector();

function extractIp(req: Request): string {
  const fwd = req.headers["x-forwarded-for"];
  if (fwd) return (Array.isArray(fwd) ? fwd[0] : fwd.split(",")[0]).trim();
  return req.ip ?? req.socket.remoteAddress ?? "unknown";
}

// Fingerprint uses multiple signals for better accuracy
function buildFingerprint(req: Request): string {
  const ua       = req.headers["user-agent"] ?? "";
  const ip       = extractIp(req);
  const lang     = req.headers["accept-language"] ?? "";
  const encoding = req.headers["accept-encoding"] ?? "";
  return createHash("sha256")
    .update(`${ua}|${ip}|${lang}|${encoding}`)
    .digest("hex");
}

export const deviceRecognition = async (
  req: Request, res: Response, next: NextFunction
): Promise<void> => {
  const ua          = req.headers["user-agent"] ?? "";
  const ip          = extractIp(req);
  const fingerprint = buildFingerprint(req);
  const info        = detector.detect(ua);
  const name        = info
    ? [info.device?.brand, info.device?.model, info.os?.name, info.client?.name]
        .filter(Boolean).join(" ") || "Unknown Device"
    : "Unknown Device";

  req.device = { fingerprint, name, userAgent: ua, ipAddress: ip };

  // Only check trust on login
  if (req.path.endsWith("/login") && req.method === "POST") {
    const { email } = req.body as { email?: string };
    if (email) {
      const user = await prisma.user.findUnique({
        where:  { email: email.toLowerCase().trim() },
        select: { id: true, mfaEnabled: true },
      }).catch(() => null);

      if (user?.mfaEnabled) {
        const trusted = await prisma.device.findUnique({
          where: { userId_fingerprint: { userId: user.id, fingerprint } },
        }).catch(() => null);

        req.trustedDevice = trusted?.isTrusted === true;
      }
    }
  }

  next();
};

export const trustCurrentDevice = async (
  req: Request,
  userId: string
): Promise<void> => {
  const device = req.device;
  if (!device) return;

  await prisma.device.upsert({
    where:  { userId_fingerprint: { userId, fingerprint: device.fingerprint } },
    update: { isTrusted: true, lastUsedAt: new Date(), deviceName: device.name },
    create: {
      userId,
      userAgent:   device.userAgent,
      ipAddress:   device.ipAddress,
      deviceName:  device.name,
      fingerprint: device.fingerprint,
      isTrusted:   true,
    },
  });
};
