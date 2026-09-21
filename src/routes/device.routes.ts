import { Router } from "express";
import {
  listMyDevices, getCurrentDevice, trustDevice, revokeDevice, deleteDevice,
} from "../controllers/device.controller";
import { authenticate } from "../middleware/auth.middleware";
import { deviceRecognition } from "../middleware/device.middleware";
import { asyncHandler } from "../middleware/asyncHandler.middleware";

const router = Router();
router.use(authenticate);

router.get("/",            asyncHandler(listMyDevices));
router.get("/current",     deviceRecognition, asyncHandler(getCurrentDevice));
router.post("/:id/trust",  asyncHandler(trustDevice));
router.post("/:id/revoke", asyncHandler(revokeDevice));
router.delete("/:id",      asyncHandler(deleteDevice));

export default router;
