// src/utils/mfa.ts — TOTP (RFC 6238) and one-time backup codes
import speakeasy from "speakeasy";
import qrcode from "qrcode";
import { randomBytes } from "crypto";
import bcrypt from "bcryptjs";
import { config } from "../config";

const STEP_SECONDS = 30;
const BACKUP_CODE_ROUNDS = Math.min(config.security.bcryptRounds, 10);

export const generateMFASecret = async (userEmail: string) => {
  // 160-bit secret, the RFC 4226 recommendation
  const secret = speakeasy.generateSecret({ length: 20 });

  // Built explicitly: generateSecret's own URL omits the issuer parameter,
  // which authenticator apps use to label the account.
  const otpauthUrl = speakeasy.otpauthURL({
    secret:   secret.base32,
    encoding: "base32",
    label:    `SecureAccess:${userEmail}`,
    issuer:   "SecureAccess",
  });

  const qrCode = await qrcode.toDataURL(otpauthUrl);
  // 10 one-time backup codes — plaintext shown once, hashed before storage
  const backupCodes = Array.from({ length: 10 }, () =>
    randomBytes(5).toString("hex").toUpperCase()
  );

  return { secret: secret.base32, qrCode, otpauthUrl, backupCodes };
};

export const currentTotpStep = (): number => Math.floor(Date.now() / 1000 / STEP_SECONDS);

/**
 * Verifies a TOTP code allowing ±1 step of clock drift.
 * Returns the matched time-step, or null when invalid. A step that is not newer
 * than `lastUsedStep` is rejected, so a code cannot be replayed.
 */
export function verifyTOTP(secret: string, token: string, lastUsedStep?: number | null): number | null {
  if (!/^\d{6}$/.test(token)) return null;
  const result = speakeasy.totp.verifyDelta({
    secret, encoding: "base32", token, window: 1, step: STEP_SECONDS,
  });
  if (!result) return null;
  const step = currentTotpStep() + result.delta;
  if (lastUsedStep != null && step <= lastUsedStep) return null;
  return step;
}

export const normalizeBackupCode = (code: string): string =>
  code.replace(/[\s-]/g, "").toUpperCase();

// Hash backup codes with bcrypt before storing (NOT base64 — that's not hashing)
export const hashBackupCodes = async (codes: string[]): Promise<string[]> =>
  Promise.all(codes.map(c => bcrypt.hash(normalizeBackupCode(c), BACKUP_CODE_ROUNDS)));

// Compare a submitted code against all stored hashes, remove the matched one
export const verifyAndConsumeBackupCode = async (
  submitted: string,
  hashedCodes: string[]
): Promise<{ valid: boolean; remaining: string[] }> => {
  const normalized = normalizeBackupCode(submitted);
  for (let i = 0; i < hashedCodes.length; i++) {
    if (await bcrypt.compare(normalized, hashedCodes[i])) {
      const remaining = [...hashedCodes];
      remaining.splice(i, 1);
      return { valid: true, remaining };
    }
  }
  return { valid: false, remaining: hashedCodes };
};

export const parseBackupCodes = (stored: string | null): string[] => {
  if (!stored) return [];
  try {
    const parsed = JSON.parse(stored);
    return Array.isArray(parsed) ? parsed.filter((c): c is string => typeof c === "string") : [];
  } catch {
    return [];
  }
};
