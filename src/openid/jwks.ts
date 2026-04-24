import { Request, Response } from "express";
import fs from "fs";
import path from "path";
export const jwks = (_req: Request, res: Response) => {
  try {
    const pub = fs.readFileSync(path.resolve("./keys/public.pem"), "utf8");
    const b64 = pub.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\n/g, "");
    res.json({ keys: [{ kty: "RSA", use: "sig", kid: "secureaccess-2025", n: Buffer.from(b64, "base64").toString("base64url"), e: "AQAB", alg: "RS256" }] });
  } catch {
    res.status(500).json({ error: "JWKS_UNAVAILABLE" });
  }
};
