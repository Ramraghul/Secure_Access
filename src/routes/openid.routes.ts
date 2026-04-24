import { Router } from "express";
import { discovery } from "../openid/well-known";
import { jwks } from "../openid/jwks";
import { authorize } from "../openid/authorize";
import { token } from "../openid/token";
import { asyncHandler } from "../middleware/asyncHandler.middleware";

const router = Router();
router.get("/.well-known/openid-configuration", asyncHandler(discovery));
router.get("/jwks",      asyncHandler(jwks));
router.get("/authorize", asyncHandler(authorize));
router.post("/token",    asyncHandler(token));
export default router;
