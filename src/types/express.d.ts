// src/types/express.d.ts
// Augment Express Request once globally — no more casting (req as any) anywhere

export interface AuthUser {
  id: string;
  email: string;
  mfaEnabled: boolean;
  deviceId: string | null;
}

export interface DeviceInfo {
  fingerprint: string;
  name: string;
  userAgent: string;
  ipAddress: string;
  isTrusted?: boolean;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
      device?: DeviceInfo;
      trustedDevice?: boolean;
      requestId?: string;
    }
  }
}
