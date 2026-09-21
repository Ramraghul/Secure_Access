// src/services/mfa.service.ts — Second-factor checks shared by login, MFA disable and device trust
import { Response } from "express";
import { User } from "@prisma/client";
import { prisma } from "../lib/prisma";
import { verifyTOTP, verifyAndConsumeBackupCode, parseBackupCodes } from "../utils/mfa";
import { unauthorized } from "../utils/errors";
import { registerFailedAttempt } from "./user.service";

// Records a failed attempt and sets the matching audit event
export async function failAttempt(res: Response, user: Pick<User, "id" | "isProtected">, event: string): Promise<void> {
  const locked = await registerFailedAttempt(user);
  res.locals.auditEvent = locked ? "ACCOUNT_LOCKED" : event;
}

/**
 * Accepts a current TOTP code (each time-step only once) or an unused backup code.
 * Anything else counts toward lockout and throws 401 INVALID_MFA.
 */
export async function verifySecondFactor(
  res: Response,
  user: User,
  factor: { code?: string; backupCode?: string },
): Promise<void> {
  if (factor.code && user.mfaSecret) {
    const step = verifyTOTP(user.mfaSecret, factor.code, user.mfaLastUsedStep);
    if (step !== null) {
      // Conditional write: the same time-step can never be accepted twice, even concurrently
      const { count } = await prisma.user.updateMany({
        where: { id: user.id, OR: [{ mfaLastUsedStep: null }, { mfaLastUsedStep: { lt: step } }] },
        data:  { mfaLastUsedStep: step },
      });
      if (count === 1) return;
    }
  } else if (factor.backupCode) {
    const { valid, remaining } = await verifyAndConsumeBackupCode(factor.backupCode, parseBackupCodes(user.backupCodesHashed));
    if (valid) {
      const { count } = await prisma.user.updateMany({
        where: { id: user.id, backupCodesHashed: user.backupCodesHashed },
        data:  { backupCodesHashed: JSON.stringify(remaining) },
      });
      if (count === 1) {
        res.locals.auditDetails = { ...res.locals.auditDetails, backupCodeUsed: true, backupCodesRemaining: remaining.length };
        return;
      }
    }
  }

  await failAttempt(res, user, "MFA_FAILED");
  throw unauthorized("INVALID_MFA", "Invalid or expired MFA code");
}
