import { Router } from "express";
import { discovery } from "../openid/well-known";
import { jwks } from "../openid/jwks";
import { authorize } from "../openid/authorize";
import { token } from "../openid/token";

const router = Router();
router.get("/.well-known/openid-configuration", discovery);
router.get("/jwks",      jwks);
router.get("/authorize", authorize);
router.post("/token",    token);
export default router;
