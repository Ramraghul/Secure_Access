// src/services/user.service.ts — Shared user helpers
import { User } from "@prisma/client";
import { prisma } from "../lib/prisma";
import { config } from "../config";
import { AppError, forbidden } from "../utils/errors";
import { toPermissionString } from "../utils/permissions";

const protectedAccountError = () =>
  forbidden("PROTECTED_ACCOUNT", "This demo account is protected and cannot be modified");

export function assertNotProtected(user: { isProtected: boolean }): void {
  if (user.isProtected) throw protectedAccountError();
}

export async function getUserAccess(userId: string): Promise<{ roles: string[]; permissions: string[] }> {
  const assignments = await prisma.userRole.findMany({
    where:   { userId },
    include: { role: { include: { permissions: true } } },
    orderBy: { assignedAt: "asc" },
  });
  const permissions = new Set<string>();
  for (const { role } of assignments) {
    role.permissions.forEach(p => permissions.add(toPermissionString(p)));
  }
  return { roles: assignments.map(a => a.role.name), permissions: [...permissions].sort() };
}

// Never return hashes, secrets or backup codes from the API
export function sanitizeUser<T extends Partial<User>>(user: T) {
  const { passwordHash, mfaSecret, backupCodesHashed, mfaLastUsedStep, ...safe } = user;
  return safe;
}

export function assertNotLocked(user: Pick<User, "lockedUntil">): void {
  if (user.lockedUntil && user.lockedUntil > new Date()) {
    throw new AppError(423, "ACCOUNT_LOCKED",
      "Too many failed attempts. Try again later.", { lockedUntil: user.lockedUntil.toISOString() });
  }
}

/**
 * Counts a failed password/MFA attempt; locks the account once the limit is hit.
 * Returns true when this attempt caused a lock.
 * Protected demo accounts publish their password, so locking them would only let
 * anyone deny the demo to everyone else — they are exempt.
 */
export async function registerFailedAttempt(user: { id: string; isProtected: boolean }): Promise<boolean> {
  if (user.isProtected) return false;
  const userId = user.id;

  const { failedLoginAttempts } = await prisma.user.update({
    where:  { id: userId },
    data:   { failedLoginAttempts: { increment: 1 } },
    select: { failedLoginAttempts: true },
  });

  if (failedLoginAttempts < config.security.maxFailedLogins) return false;

  await prisma.user.update({
    where: { id: userId },
    data:  {
      failedLoginAttempts: 0,
      lockedUntil: new Date(Date.now() + config.security.lockoutMinutes * 60 * 1000),
    },
  });
  return true;
}
