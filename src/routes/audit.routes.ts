import { Router } from "express";
import { searchAuditEvents, getRetentionStats } from "../controllers/audit.controller";
import { authenticate } from "../middleware/auth.middleware";
import { requirePermission } from "../middleware/rbac.middleware";
import { auditLog } from "../middleware/audit.middleware";
import { asyncHandler } from "../middleware/asyncHandler.middleware";
import { prisma } from "../lib/prisma";

const router = Router();

router.get("/events",    authenticate, requirePermission("read",   "audit"), auditLog, asyncHandler(searchAuditEvents));
router.get("/retention", authenticate, requirePermission("read",   "audit"), auditLog, asyncHandler(getRetentionStats));

// Main paginated list
router.get("/", authenticate, requirePermission("read", "audit"), auditLog, asyncHandler(async (req, res) => {
  const page  = parseInt(req.query.page  as string) || 1;
  const limit = Math.min(parseInt(req.query.limit as string) || 50, 500);
  const skip  = (page - 1) * limit;
  const where: Record<string, unknown> = {};

  if (req.query.userId)    where.userId   = req.query.userId;
  if (req.query.action)    where.action   = req.query.action;
  if (req.query.resource)  where.resource = { contains: req.query.resource };
  if (req.query.ipAddress) where.ipAddress = { contains: req.query.ipAddress };
  if (req.query.startDate || req.query.endDate) {
    where.timestamp = {
      ...(req.query.startDate ? { gte: new Date(req.query.startDate as string) } : {}),
      ...(req.query.endDate   ? { lte: new Date(req.query.endDate   as string) } : {}),
    };
  }

  const [logs, total] = await Promise.all([
    prisma.auditLog.findMany({
      where,
      include: { user: { select: { id: true, email: true, firstName: true, lastName: true } } },
      orderBy: { timestamp: "desc" },
      skip, take: limit,
    }),
    prisma.auditLog.count({ where }),
  ]);

  res.json({
    data: logs.map(log => {
      const meta = (log.metadata && typeof log.metadata === "object") ? log.metadata as Record<string, unknown> : {};
      return { ...log, metadata: { ...meta, requestBody: meta.requestBody ? "[masked]" : null } };
    }),
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  });
}));

// CSV export
router.post("/export", authenticate, requirePermission("export", "audit"), auditLog, asyncHandler(async (_req, res) => {
  const logs = await prisma.auditLog.findMany({
    include: { user: { select: { email: true, firstName: true, lastName: true } } },
    orderBy: { timestamp: "desc" },
    take: 10000,
  });

  const csv = [
    "Timestamp,User,Email,Action,Resource,IP,Device,Status,Duration(ms),RequestId",
    ...logs.map(log => {
      const meta = (log.metadata && typeof log.metadata === "object") ? log.metadata as Record<string, unknown> : {};
      return [
        log.timestamp.toISOString(),
        log.user ? `${log.user.firstName} ${log.user.lastName}`.trim() : "Anonymous",
        log.user?.email ?? "",
        log.action, log.resource, log.ipAddress,
        meta.device ?? "Unknown",
        meta.statusCode ?? "",
        meta.durationMs ?? "",
        meta.requestId  ?? "",
      ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(",");
    }),
  ].join("\n");

  res
    .header("Content-Type", "text/csv")
    .header("Content-Disposition", `attachment; filename="audit-${new Date().toISOString().split("T")[0]}.csv"`)
    .send(csv);
}));

export default router;
