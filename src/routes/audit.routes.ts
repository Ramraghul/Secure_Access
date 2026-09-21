import { Router } from "express";
import {
  listAuditLogs, searchAuditEvents, getRetentionStats, exportAuditLogs, purgeAuditLogs,
} from "../controllers/audit.controller";
import { authenticate } from "../middleware/auth.middleware";
import { requirePermission } from "../middleware/rbac.middleware";
import { asyncHandler } from "../middleware/asyncHandler.middleware";

const router = Router();
router.use(authenticate);

router.get("/",          requirePermission("read",   "audit"), asyncHandler(listAuditLogs));
router.get("/events",    requirePermission("read",   "audit"), asyncHandler(searchAuditEvents));
router.get("/retention", requirePermission("read",   "audit"), asyncHandler(getRetentionStats));
router.post("/export",   requirePermission("export", "audit"), asyncHandler(exportAuditLogs));
router.post("/purge",    requirePermission("manage", "audit"), asyncHandler(purgeAuditLogs));

export default router;
