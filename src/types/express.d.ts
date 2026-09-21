// src/types/express.d.ts
// Augment Express Request once globally — no more casting (req as any) anywhere

export interface AuthUser {
  id:          string;
  email:       string;
  mfaEnabled:  boolean;
  isProtected: boolean;
  sessionId:   string;
  deviceId:    string | null;
}

export interface DeviceInfo {
  fingerprint: string;
  name:        string;
  userAgent:   string;
  ipAddress:   string;
}

declare global {
  namespace Express {
    interface Request {
      user?:      AuthUser;
      device?:    DeviceInfo;
      requestId?: string;
    }

    // Controllers enrich the audit record through res.locals
    interface Locals {
      auditUserId?: string;
      auditEvent?:  string;
      auditDetails?: Record<string, unknown>;
    }
  }
}
