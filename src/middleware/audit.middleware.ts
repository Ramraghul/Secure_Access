// src/middleware/audit.middleware.ts — Audit trail for every API request
import { Request, Response, NextFunction } from "express";
import { waitUntil } from "@vercel/functions";
import { prisma } from "../lib/prisma";
import { logger } from "../lib/logger";
import { config } from "../config";
import { maskSensitive, responseSnippet } from "../utils/mask";
import { clientIp, clientUserAgent, deviceNameFromUserAgent } from "../utils/request";

const pending = new Set<Promise<unknown>>();

// Resolves once every in-flight audit write has settled (graceful shutdown, tests)
export async function flushAuditLogs(): Promise<void> {
  while (pending.size > 0) {
    await Promise.allSettled([...pending]);
  }
}

/**
 * Mounted once in front of all API routers. The row is written when the response
 * finishes, so it captures the final status code and — because the user is
 * resolved at that moment — the authenticated user or the account a login
 * attempt targeted (res.locals.auditUserId). Failed authentication is audited too.
 */
export const auditLog = (req: Request, res: Response, next: NextFunction): void => {
  if (req.method === "OPTIONS" || req.method === "HEAD") return next();
  if (!config.audit.logReads && req.method === "GET") return next();

  const start = Date.now();
  let responseBody: unknown = null;
  let written = false;

  const originalJson = res.json.bind(res);
  res.json = (body: unknown): Response => {
    responseBody = body;
    return originalJson(body);
  };

  const write = (): void => {
    if (written) return;
    written = true;

    const isRead    = req.method === "GET";
    const userAgent = clientUserAgent(req);

    const task = prisma.auditLog.create({
      data: {
        userId:     req.user?.id ?? res.locals.auditUserId ?? null,
        event:      res.locals.auditEvent ?? null,
        action:     req.method,
        resource:   req.originalUrl.slice(0, 1000),
        statusCode: res.statusCode,
        ipAddress:  clientIp(req),
        userAgent:  userAgent.slice(0, 500),
        metadata: {
          requestId:       req.requestId ?? null,
          device:          deviceNameFromUserAgent(userAgent),
          durationMs:      Date.now() - start,
          aborted:         !res.writableFinished,
          requestBody:     isRead ? null : (maskSensitive(req.body) as object) ?? null,
          responseSnippet: isRead && res.statusCode < 400 ? null : responseSnippet(responseBody),
          details:         (maskSensitive(res.locals.auditDetails) as object) ?? null,
        },
      },
    })
      .catch(err => logger.error("Audit log write failed", { error: String(err), requestId: req.requestId }))
      .finally(() => pending.delete(task));

    pending.add(task);
    // On Vercel, keep the function alive until the write completes. No-op elsewhere.
    waitUntil(task);
  };

  res.on("finish", write);
  res.on("close", write);
  next();
};
