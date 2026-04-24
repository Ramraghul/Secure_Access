import { Router } from "express";
import { listUsers, getUser, deactivateUser, activateUser, adminResetPassword } from "../controllers/user.controller";
import { authenticate } from "../middleware/auth.middleware";
import { requirePermission } from "../middleware/rbac.middleware";
import { auditLog } from "../middleware/audit.middleware";
import { asyncHandler } from "../middleware/asyncHandler.middleware";

const router = Router();
router.get("/",                  authenticate, requirePermission("read",   "user"), auditLog, asyncHandler(listUsers));
router.get("/:id",               authenticate, requirePermission("read",   "user"), auditLog, asyncHandler(getUser));
router.post("/:id/deactivate",   authenticate, requirePermission("update", "user"), auditLog, asyncHandler(deactivateUser));
router.post("/:id/activate",     authenticate, requirePermission("update", "user"), auditLog, asyncHandler(activateUser));
router.post("/:id/reset-password", authenticate, requirePermission("manage","user"), auditLog, asyncHandler(adminResetPassword));
export default router;
