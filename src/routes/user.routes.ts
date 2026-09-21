import { Router } from "express";
import {
  listUsers, getUser, deactivateUser, activateUser, adminResetPassword, deleteUser,
} from "../controllers/user.controller";
import { authenticate } from "../middleware/auth.middleware";
import { requirePermission } from "../middleware/rbac.middleware";
import { asyncHandler } from "../middleware/asyncHandler.middleware";

const router = Router();
router.use(authenticate);

router.get("/",                    requirePermission("read",   "user"), asyncHandler(listUsers));
router.get("/:id",                 requirePermission("read",   "user"), asyncHandler(getUser));
router.post("/:id/deactivate",     requirePermission("update", "user"), asyncHandler(deactivateUser));
router.post("/:id/activate",       requirePermission("update", "user"), asyncHandler(activateUser));
router.post("/:id/reset-password", requirePermission("manage", "user"), asyncHandler(adminResetPassword));
router.delete("/:id",              requirePermission("delete", "user"), asyncHandler(deleteUser));

export default router;
