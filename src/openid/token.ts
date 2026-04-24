import { Request, Response } from "express";
import { signJwt } from "../utils/jwt";
export const token = (req: Request, res: Response) => {
  const { grant_type } = req.body as { grant_type: string };
  if (grant_type !== "authorization_code") {
    res.status(400).json({ error: "unsupported_grant_type" }); return;
  }
  const payload = { id: "user-123", email: "user@secureaccess.ca" };
  res.json({ access_token: signJwt(payload, "1h"), token_type: "Bearer", expires_in: 3600 });
};
