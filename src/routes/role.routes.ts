import { Router } from "express";
import { listRoles, createRole, updateRole, assignRole, revokeRole } from "../controllers/role.controller";
import { authenticate } from "../middleware/auth.middleware";
import { requirePermission } from "../middleware/rbac.middleware";
import { auditLog } from "../middleware/audit.middleware";
import { asyncHandler } from "../middleware/asyncHandler.middleware";

const router = Router();
router.get("/",           authenticate, requirePermission("read",   "role"),      auditLog, asyncHandler(listRoles));
router.post("/",          authenticate, requirePermission("create", "role"),      auditLog, asyncHandler(createRole));
router.put("/:id",        authenticate, requirePermission("update", "role"),      auditLog, asyncHandler(updateRole));
router.post("/:id/assign",authenticate, requirePermission("manage","user-role"),  auditLog, asyncHandler(assignRole));
router.post("/:id/revoke",authenticate, requirePermission("manage","user-role"),  auditLog, asyncHandler(revokeRole));
export default router;
