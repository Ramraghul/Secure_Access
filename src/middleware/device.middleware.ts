// src/middleware/device.middleware.ts — Identifies the calling device
import { Request, Response, NextFunction } from "express";
import { clientIp, clientUserAgent, deviceFingerprint, deviceNameFromUserAgent } from "../utils/request";

export const deviceRecognition = (req: Request, _res: Response, next: NextFunction): void => {
  const userAgent = clientUserAgent(req);
  req.device = {
    fingerprint: deviceFingerprint(req),
    name:        deviceNameFromUserAgent(userAgent),
    userAgent,
    ipAddress:   clientIp(req),
  };
  next();
};
