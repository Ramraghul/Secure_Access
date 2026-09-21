// src/services/device.service.ts — Trusted-device ("remember this device") rules
import { config } from "../config";

interface TrustState {
  isTrusted:    boolean;
  trustedUntil: Date | null;
}

// A device skips the MFA code only while trust is set AND has not expired
export const isTrustActive = (device: TrustState | null | undefined): boolean =>
  Boolean(device?.isTrusted && device.trustedUntil && device.trustedUntil > new Date());

export const newTrustExpiry = (): Date =>
  new Date(Date.now() + config.security.trustedDeviceDays * 24 * 60 * 60 * 1000);

export const TRUST_CLEARED = { isTrusted: false, trustedUntil: null };

// What the API reports: the effective trust state and its expiry
export function trustView(device: TrustState): TrustState {
  const active = isTrustActive(device);
  return { isTrusted: active, trustedUntil: active ? device.trustedUntil : null };
}
