import { Router } from "express";
import { listMyDevices, getCurrentDevice, trustDevice, revokeDevice, deleteDevice } from "../controllers/device.controller";
import { authenticate } from "../middleware/auth.middleware";
import { deviceRecognition } from "../middleware/device.middleware";
import { auditLog } from "../middleware/audit.middleware";
import { asyncHandler } from "../middleware/asyncHandler.middleware";

const router = Router();
router.get("/",         authenticate, auditLog, asyncHandler(listMyDevices));
router.get("/current",  authenticate, deviceRecognition, auditLog, asyncHandler(getCurrentDevice));
router.post("/:id/trust",  authenticate, auditLog, asyncHandler(trustDevice));
router.post("/:id/revoke", authenticate, auditLog, asyncHandler(revokeDevice));
router.delete("/:id",      authenticate, auditLog, asyncHandler(deleteDevice));
export default router;
