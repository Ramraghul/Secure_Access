// src/utils/request.ts — Client IP, user agent and device identification
import { Request } from "express";
import { createHash } from "crypto";
import DeviceDetector from "node-device-detector";

const detector = new DeviceDetector();

// req.ip honours the "trust proxy" setting, so a client-supplied
// X-Forwarded-For header cannot be used to spoof the address.
export function clientIp(req: Request): string {
  return req.ip ?? req.socket.remoteAddress ?? "unknown";
}

export function clientUserAgent(req: Request): string {
  return req.headers["user-agent"] ?? "unknown";
}

export function deviceNameFromUserAgent(ua: string): string {
  try {
    const r = detector.detect(ua);
    return [r.device?.brand, r.device?.model, r.os?.name, r.os?.version, r.client?.name]
      .filter(Boolean).join(" ") || "Unknown Device";
  } catch {
    return "Unknown Device";
  }
}

// Fingerprint uses multiple request signals. Changing network (IP) or browser
// produces a new device, which is intentional: trust is per device + location.
export function deviceFingerprint(req: Request): string {
  const ua   = req.headers["user-agent"] ?? "";
  const lang = req.headers["accept-language"] ?? "";
  return createHash("sha256")
    .update(`${ua}|${clientIp(req)}|${lang}`)
    .digest("hex");
}
