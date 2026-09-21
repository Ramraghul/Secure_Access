import { Router } from "express";
import {
  listRoles, getRole, createRole, updateRole, deleteRole, assignRole, revokeRole,
} from "../controllers/role.controller";
import { authenticate } from "../middleware/auth.middleware";
import { requirePermission } from "../middleware/rbac.middleware";
import { asyncHandler } from "../middleware/asyncHandler.middleware";

const router = Router();
router.use(authenticate);

router.get("/",            requirePermission("read",   "role"),      asyncHandler(listRoles));
router.post("/",           requirePermission("create", "role"),      asyncHandler(createRole));
router.get("/:id",         requirePermission("read",   "role"),      asyncHandler(getRole));
router.put("/:id",         requirePermission("update", "role"),      asyncHandler(updateRole));
router.delete("/:id",      requirePermission("delete", "role"),      asyncHandler(deleteRole));
router.post("/:id/assign", requirePermission("manage", "user-role"), asyncHandler(assignRole));
router.post("/:id/revoke", requirePermission("manage", "user-role"), asyncHandler(revokeRole));

export default router;
