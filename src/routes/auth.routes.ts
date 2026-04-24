import { Router } from "express";
import { register, login, setupMFA, verifyMFA, me } from "../controllers/auth.controller";
import { authenticate } from "../middleware/auth.middleware";
import { deviceRecognition } from "../middleware/device.middleware";
import { auditLog } from "../middleware/audit.middleware";
import { asyncHandler } from "../middleware/asyncHandler.middleware";

const router = Router();
router.post("/register",    auditLog, asyncHandler(register));
router.post("/login",       deviceRecognition, auditLog, asyncHandler(login));
router.post("/mfa/setup",   authenticate, auditLog, asyncHandler(setupMFA));
router.post("/mfa/verify",  authenticate, auditLog, asyncHandler(verifyMFA));
router.get("/me",           authenticate, auditLog, asyncHandler(me));
export default router;
