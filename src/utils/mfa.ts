// src/utils/mfa.ts
import speakeasy from "speakeasy";
import qrcode from "qrcode";
import { randomBytes } from "crypto";
import bcrypt from "bcryptjs";

export const generateMFASecret = async (userEmail: string) => {
  const secret = speakeasy.generateSecret({
    length: 32,
    name:   `SecureAccess (${userEmail})`,
    issuer: "SecureAccess",
  });

  const qrCode = await qrcode.toDataURL(secret.otpauth_url!);
  // 10 one-time backup codes — plaintext shown once, hashed before storage
  const backupCodes = Array.from({ length: 10 }, () =>
    randomBytes(5).toString("hex").toUpperCase()
  );

  return { secret: secret.base32, qrCode, otpauthUrl: secret.otpauth_url!, backupCodes };
};

export const verifyTOTP = (secret: string, token: string): boolean =>
  speakeasy.totp.verify({ secret, encoding: "base32", token, window: 2 });

// Hash backup codes with bcrypt before storing (NOT base64 — that's not hashing)
export const hashBackupCodes = async (codes: string[]): Promise<string[]> =>
  Promise.all(codes.map(c => bcrypt.hash(c, 10)));

// Compare a submitted code against all stored hashes, remove the matched one
export const verifyAndConsumeBackupCode = async (
  submitted: string,
  hashedCodes: string[]
): Promise<{ valid: boolean; remaining: string[] }> => {
  for (let i = 0; i < hashedCodes.length; i++) {
    const match = await bcrypt.compare(submitted, hashedCodes[i]);
    if (match) {
      const remaining = [...hashedCodes];
      remaining.splice(i, 1);
      return { valid: true, remaining };
    }
  }
  return { valid: false, remaining: hashedCodes };
};
