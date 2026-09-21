import { Router } from "express";
import {
  discovery, jwks, authorize, consentDetails, consent, token, userinfo, revoke,
  listClients, createClient, deleteClient,
} from "../controllers/openid.controller";
import { oauthHandler } from "../openid/clients";
import { authenticate } from "../middleware/auth.middleware";
import { requirePermission } from "../middleware/rbac.middleware";
import { authLimiter } from "../middleware/rateLimit.middleware";
import { asyncHandler } from "../middleware/asyncHandler.middleware";

const router = Router();

// Protocol endpoints
router.get("/.well-known/openid-configuration", discovery);
router.get("/jwks",      jwks);
router.get("/authorize", oauthHandler(authorize));
router.get("/consent",   oauthHandler(consentDetails));
router.post("/consent",  authenticate, oauthHandler(consent));
router.post("/token",    authLimiter, oauthHandler(token));
router.get("/userinfo",  oauthHandler(userinfo));
router.post("/revoke",   oauthHandler(revoke));

// Client registry (admin)
router.get("/clients",        authenticate, requirePermission("read",   "client"), asyncHandler(listClients));
router.post("/clients",       authenticate, requirePermission("create", "client"), asyncHandler(createClient));
router.delete("/clients/:id", authenticate, requirePermission("delete", "client"), asyncHandler(deleteClient));

export default router;
