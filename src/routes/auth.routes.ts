import { Router } from "express";
import {
  register, login, loginMfa, refresh, logout, logoutAll, me, updateProfile, changePassword,
  listSessions, revokeSessionById, setupMFA, verifyMFA, disableMFA,
} from "../controllers/auth.controller";
import { authenticate } from "../middleware/auth.middleware";
import { deviceRecognition } from "../middleware/device.middleware";
import { authLimiter } from "../middleware/rateLimit.middleware";
import { asyncHandler } from "../middleware/asyncHandler.middleware";

const router = Router();

// Public — credential endpoints are rate limited on failures
router.post("/register",   authLimiter, asyncHandler(register));
router.post("/login",      authLimiter, deviceRecognition, asyncHandler(login));
router.post("/login/mfa",  authLimiter, deviceRecognition, asyncHandler(loginMfa));
router.post("/refresh",    authLimiter, asyncHandler(refresh));

// Authenticated
router.post("/logout",          authenticate, asyncHandler(logout));
router.post("/logout-all",      authenticate, asyncHandler(logoutAll));
router.get("/me",               authenticate, asyncHandler(me));
router.patch("/me",             authenticate, asyncHandler(updateProfile));
router.post("/change-password", authenticate, authLimiter, asyncHandler(changePassword));
router.get("/sessions",         authenticate, asyncHandler(listSessions));
router.delete("/sessions/:id",  authenticate, asyncHandler(revokeSessionById));
router.post("/mfa/setup",       authenticate, asyncHandler(setupMFA));
router.post("/mfa/verify",      authenticate, authLimiter, asyncHandler(verifyMFA));
router.post("/mfa/disable",     authenticate, authLimiter, asyncHandler(disableMFA));

export default router;
