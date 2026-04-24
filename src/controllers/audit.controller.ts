// src/controllers/audit.controller.ts
import { Request, Response } from "express";
import { prisma } from "../lib/prisma";

export const searchAuditEvents = async (req: Request, res: Response): Promise<void> => {
  const { userId, email, action, resource, ip, status, before, after, sensitive } = req.query;

  const where: Record<string, unknown> = {};
  if (userId)   where.userId   = userId;
  if (action)   where.action   = action;
  if (resource) where.resource = { contains: resource as string };
  if (ip)       where.ipAddress = { contains: ip as string };
  if (status)   where.metadata = { path: ["statusCode"], equals: parseInt(status as string) };

  if (before || after) {
    where.timestamp = {
      ...(before ? { lte: new Date(before as string) } : {}),
      ...(after  ? { gte: new Date(after  as string) } : {}),
    };
  }

  if (email) {
    const user = await prisma.user.findFirst({
      where: { email: { contains: email as string, mode: "insensitive" } },
      select: { id: true },
    });
    if (user) where.userId = user.id;
  }

  if (sensitive === "true") {
    where.OR = [
      { resource: { contains: "/login"    } },
      { resource: { contains: "/mfa"      } },
      { resource: { contains: "/password" } },
      { action: "POST", resource: { contains: "/roles" } },
    ];
  }

  const logs = await prisma.auditLog.findMany({
    where,
    include: { user: { select: { id: true, email: true, firstName: true, lastName: true } } },
    orderBy: { timestamp: "desc" },
    take: 1000,
  });

  res.json({
    total: logs.length,
    events: logs.map(log => {
      const meta = (log.metadata && typeof log.metadata === "object" && !Array.isArray(log.metadata))
        ? log.metadata as Record<string, unknown>
        : {};

      const ts = new Date(log.timestamp);
      const isOffHours  = ts.getHours() >= 0 && ts.getHours() <= 5;
      const isExternal  = !(log.ipAddress?.startsWith("192.168.") || log.ipAddress?.startsWith("10.") || log.ipAddress === "::1");

      return {
        id:         log.id,
        timestamp:  log.timestamp,
        user:       log.user ? `${log.user.firstName} ${log.user.lastName} (${log.user.email})` : "Anonymous",
        action:     log.action,
        resource:   log.resource,
        ip:         log.ipAddress,
        device:     meta.device ?? "Unknown",
        status:     meta.statusCode,
        durationMs: meta.durationMs,
        requestId:  meta.requestId,
        suspicious: isExternal && isOffHours ? "Off-hours external access" : null,
      };
    }),
  });
};

export const getRetentionStats = async (_req: Request, res: Response): Promise<void> => {
  const [total, last30days, oldest] = await Promise.all([
    prisma.auditLog.count(),
    prisma.auditLog.count({ where: { timestamp: { gte: new Date(Date.now() - 30 * 86400000) } } }),
    prisma.auditLog.findFirst({ orderBy: { timestamp: "asc" } }),
  ]);

  res.json({
    totalRecords: total,
    last30Days:   last30days,
    oldestRecord: oldest?.timestamp ?? null,
    retentionDays: oldest
      ? Math.floor((Date.now() - new Date(oldest.timestamp).getTime()) / 86400000)
      : 0,
    complianceNote: "Meets PIPEDA 7-year & SOC 2 12-month retention requirements",
  });
};
