// src/controllers/audit.controller.ts
import { Request, Response } from "express";
import { Prisma } from "@prisma/client";
import { prisma } from "../lib/prisma";
import { config } from "../config";
import {
  validate, AuditListQuerySchema, AuditSearchQuerySchema, AuditPurgeSchema,
} from "../utils/validation";

const userSelect = { select: { id: true, email: true, firstName: true, lastName: true } } as const;

type AuditListQuery = ReturnType<typeof parseListQuery>;
const parseListQuery = (query: unknown) => validate(AuditListQuerySchema, query);

function listWhere(q: AuditListQuery): Prisma.AuditLogWhereInput {
  return {
    ...(q.userId     ? { userId: q.userId } : {}),
    ...(q.event      ? { event: q.event } : {}),
    ...(q.action     ? { action: q.action } : {}),
    ...(q.resource   ? { resource: { contains: q.resource } } : {}),
    ...(q.ipAddress  ? { ipAddress: { contains: q.ipAddress } } : {}),
    ...(q.statusCode ? { statusCode: q.statusCode } : {}),
    ...(q.startDate || q.endDate ? {
      timestamp: {
        ...(q.startDate ? { gte: q.startDate } : {}),
        ...(q.endDate   ? { lte: q.endDate } : {}),
      },
    } : {}),
  };
}

const metadataOf = (value: Prisma.JsonValue): Record<string, unknown> =>
  value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};

export function isPrivateIp(ip: string): boolean {
  const v4 = ip.replace(/^::ffff:/, "");
  return v4 === "::1" || v4.startsWith("127.") || v4.startsWith("10.") || v4.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(v4) || v4.startsWith("fc") || v4.startsWith("fd");
}

export const listAuditLogs = async (req: Request, res: Response): Promise<void> => {
  const q     = parseListQuery(req.query);
  const where = listWhere(q);

  const [logs, total] = await Promise.all([
    prisma.auditLog.findMany({
      where,
      include: { user: userSelect },
      orderBy: { timestamp: "desc" },
      skip: (q.page - 1) * q.limit,
      take: q.limit,
    }),
    prisma.auditLog.count({ where }),
  ]);

  res.json({ data: logs, pagination: { page: q.page, limit: q.limit, total, totalPages: Math.ceil(total / q.limit) } });
};

export const searchAuditEvents = async (req: Request, res: Response): Promise<void> => {
  const q = validate(AuditSearchQuerySchema, req.query);
  const where: Prisma.AuditLogWhereInput = {
    ...(q.userId   ? { userId: q.userId } : {}),
    ...(q.event    ? { event: q.event } : {}),
    ...(q.action   ? { action: q.action } : {}),
    ...(q.resource ? { resource: { contains: q.resource } } : {}),
    ...(q.ip       ? { ipAddress: { contains: q.ip } } : {}),
    ...(q.status   ? { statusCode: q.status } : {}),
    ...(q.before || q.after ? {
      timestamp: { ...(q.before ? { lte: q.before } : {}), ...(q.after ? { gte: q.after } : {}) },
    } : {}),
  };

  if (q.email) {
    const users = await prisma.user.findMany({
      where:  { email: { contains: q.email, mode: "insensitive" } },
      select: { id: true },
      take:   100,
    });
    // No matching user means no matching events — not "all events"
    if (users.length === 0) { res.json({ total: 0, events: [] }); return; }
    where.userId = { in: users.map(u => u.id) };
  }

  if (q.sensitive === "true") {
    where.OR = [
      { resource: { contains: "/login" } },
      { resource: { contains: "/mfa" } },
      { resource: { contains: "password" } },
      { resource: { contains: "/roles" }, action: { not: "GET" } },
      { event: { in: ["ACCOUNT_LOCKED", "REFRESH_TOKEN_REUSED", "USER_DEACTIVATED", "USER_DELETED"] } },
    ];
  }

  const logs = await prisma.auditLog.findMany({
    where,
    include: { user: userSelect },
    orderBy: { timestamp: "desc" },
    take:    q.limit,
  });

  res.json({
    total: logs.length,
    events: logs.map(log => {
      const meta    = metadataOf(log.metadata);
      const hourUtc = log.timestamp.getUTCHours();
      const offHoursExternal = hourUtc <= 5 && !isPrivateIp(log.ipAddress);
      return {
        id:         log.id,
        timestamp:  log.timestamp,
        user:       log.user ? `${log.user.firstName} ${log.user.lastName} (${log.user.email})` : "Anonymous",
        event:      log.event,
        action:     log.action,
        resource:   log.resource,
        ip:         log.ipAddress,
        device:     meta.device ?? "Unknown",
        status:     log.statusCode,
        durationMs: meta.durationMs ?? null,
        requestId:  meta.requestId ?? null,
        suspicious: offHoursExternal ? "Off-hours (00:00–05:59 UTC) external access" : null,
      };
    }),
  });
};

export const getRetentionStats = async (_req: Request, res: Response): Promise<void> => {
  const now = Date.now();
  const [total, last30Days, oldest, failedLogins24h, byEvent] = await Promise.all([
    prisma.auditLog.count(),
    prisma.auditLog.count({ where: { timestamp: { gte: new Date(now - 30 * 86400000) } } }),
    prisma.auditLog.findFirst({ orderBy: { timestamp: "asc" }, select: { timestamp: true } }),
    prisma.auditLog.count({ where: { event: { in: ["LOGIN_FAILED", "MFA_FAILED", "ACCOUNT_LOCKED"] }, timestamp: { gte: new Date(now - 86400000) } } }),
    prisma.auditLog.groupBy({ by: ["event"], where: { event: { not: null } }, _count: { _all: true } }),
  ]);

  res.json({
    totalRecords:           total,
    last30Days,
    failedLoginsLast24h:    failedLogins24h,
    oldestRecord:           oldest?.timestamp ?? null,
    oldestRecordAgeDays:    oldest ? Math.floor((now - oldest.timestamp.getTime()) / 86400000) : 0,
    configuredRetentionDays: config.audit.retentionDays,
    eventCounts: Object.fromEntries(
      byEvent.sort((a, b) => b._count._all - a._count._all).map(e => [e.event, e._count._all])
    ),
    note: `Records older than ${config.audit.retentionDays} days can be removed with POST /audit/purge.`,
  });
};

// Prevents CSV/formula injection when the file is opened in a spreadsheet
export function csvCell(value: unknown): string {
  let text = value == null ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

export const exportAuditLogs = async (req: Request, res: Response): Promise<void> => {
  const q = parseListQuery(req.query);
  const logs = await prisma.auditLog.findMany({
    where:   listWhere(q),
    include: { user: userSelect },
    orderBy: { timestamp: "desc" },
    take:    10000,
  });

  const header = "Timestamp,User,Email,Event,Action,Resource,Status,IP,Device,Duration(ms),RequestId";
  const rows = logs.map(log => {
    const meta = metadataOf(log.metadata);
    return [
      log.timestamp.toISOString(),
      log.user ? `${log.user.firstName} ${log.user.lastName}`.trim() : "Anonymous",
      log.user?.email ?? "",
      log.event ?? "",
      log.action,
      log.resource,
      log.statusCode ?? "",
      log.ipAddress,
      meta.device ?? "Unknown",
      meta.durationMs ?? "",
      meta.requestId ?? "",
    ].map(csvCell).join(",");
  });

  res.locals.auditEvent   = "AUDIT_EXPORTED";
  res.locals.auditDetails = { rows: logs.length };
  res
    .status(200)
    .type("text/csv")
    .attachment(`audit-${new Date().toISOString().split("T")[0]}.csv`)
    .send([header, ...rows].join("\n"));
};

export const purgeAuditLogs = async (req: Request, res: Response): Promise<void> => {
  const { olderThanDays } = validate(AuditPurgeSchema, {
    olderThanDays: config.audit.retentionDays,
    ...(req.body ?? {}),
  });

  const cutoff = new Date(Date.now() - olderThanDays * 86400000);
  const { count } = await prisma.auditLog.deleteMany({ where: { timestamp: { lt: cutoff } } });

  res.locals.auditEvent   = "AUDIT_PURGED";
  res.locals.auditDetails = { olderThanDays, deleted: count };
  res.json({ success: true, deleted: count, cutoff });
};
