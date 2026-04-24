// src/middleware/audit.middleware.ts — Production-grade audit trail
import { Request, Response, NextFunction } from "express";
import { randomUUID } from "crypto";
import { prisma } from "../lib/prisma";
import { logger } from "../lib/logger";
import DeviceDetector from "node-device-detector";

const detector = new DeviceDetector();

const SENSITIVE_KEYS = new Set([
  "password", "confirmPassword", "currentPassword", "newPassword",
  "token", "accessToken", "refreshToken", "secret", "apiKey",
  "totp_code", "otp", "cvv", "cardNumber", "pin", "backupCode",
]);

const MASK = "••••••";

function maskSensitive(value: unknown, seen = new WeakSet()): unknown {
  if (value === null || typeof value !== "object") return value;
  if (seen.has(value as object)) return "[Circular]";
  seen.add(value as object);
  if (Array.isArray(value)) return value.map(i => maskSensitive(i, seen));
  const masked: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    masked[k] = SENSITIVE_KEYS.has(k.toLowerCase()) ? MASK : maskSensitive(v, seen);
  }
  return masked;
}

function parseResponseSnippet(data: unknown): string | null {
  if (data == null) return null;
  let str: string;
  if (Buffer.isBuffer(data))      str = data.toString("utf8");
  else if (typeof data === "object") {
    try { str = JSON.stringify(data); } catch { return "[Unserializable]"; }
  } else str = String(data);
  return str.length > 500 ? str.slice(0, 500) + "…" : str;
}

function extractIp(req: Request): string {
  const fwd = req.headers["x-forwarded-for"];
  if (fwd) return (Array.isArray(fwd) ? fwd[0] : fwd.split(",")[0]).trim();
  return req.ip ?? req.socket.remoteAddress ?? "unknown";
}

function buildDeviceName(ua: string): string {
  try {
    const r = detector.detect(ua);
    if (!r) return "Unknown Device";
    return [r.device?.brand, r.device?.model, r.os?.name, r.os?.version, r.client?.name]
      .filter(Boolean).join(" ") || "Unknown Device";
  } catch { return "Unknown Device"; }
}

export const auditLog = (req: Request, res: Response, next: NextFunction): void => {
  const start      = Date.now();
  const requestId  = req.requestId ?? randomUUID();
  req.requestId    = requestId;
  const userId     = req.user?.id ?? null;
  const ua         = req.headers["user-agent"] ?? "unknown";
  const ip         = extractIp(req);
  const device     = buildDeviceName(ua);
  const safeBody   = maskSensitive(req.body);

  res.setHeader("X-Request-Id", requestId);

  let fired = false;

  const fire = (data: unknown): void => {
    if (fired) return;
    fired = true;
    prisma.auditLog.create({
      data: {
        userId,
        action:    req.method,
        resource:  req.originalUrl,
        ipAddress: ip,
        userAgent: ua,
        metadata: {
          requestId,
          device,
          method:          req.method,
          statusCode:      res.statusCode,
          durationMs:      Date.now() - start,
          requestBody:     safeBody ?? null,
          responseSnippet: parseResponseSnippet(data),
        } as any,
        timestamp: new Date(),
      },
    }).catch(err => logger.error("Audit log write failed", { err, requestId }));
  };

  const origJson = res.json.bind(res);
  res.json = function (body: unknown): Response {
    fire(body);
    return origJson(body);
  };

  const origSend = res.send.bind(res);
  res.send = function (body: unknown): Response {
    fire(body);
    return origSend(body);
  };

  const origEnd = res.end.bind(res);
  res.end = function (chunk?: unknown, enc?: unknown, cb?: () => void): Response {
    fire(chunk ?? null);
    return origEnd(chunk, enc as BufferEncoding, cb);
  };

  next();
};
