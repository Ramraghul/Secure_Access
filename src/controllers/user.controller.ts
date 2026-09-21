// src/controllers/user.controller.ts
import { Request, Response } from "express";
import { Prisma } from "@prisma/client";
import { prisma } from "../lib/prisma";
import { hashPassword, generateSecurePassword } from "../utils/password";
import { badRequest, notFound } from "../utils/errors";
import { validate, IdParamSchema, UserListQuerySchema } from "../utils/validation";
import { revokeAllSessions } from "../services/session.service";
import { assertNotProtected, sanitizeUser } from "../services/user.service";
import { TRUST_CLEARED, trustView } from "../services/device.service";

async function findUserOr404(id: string) {
  const user = await prisma.user.findUnique({ where: { id } });
  if (!user) throw notFound("USER_NOT_FOUND", "User not found");
  return user;
}

export const listUsers = async (req: Request, res: Response): Promise<void> => {
  const { page, limit, search, status } = validate(UserListQuerySchema, req.query);

  const where: Prisma.UserWhereInput = {
    ...(search ? {
      OR: [
        { email:     { contains: search, mode: "insensitive" } },
        { firstName: { contains: search, mode: "insensitive" } },
        { lastName:  { contains: search, mode: "insensitive" } },
      ],
    } : {}),
    ...(status ? { isActive: status === "active" } : {}),
  };

  const [users, total] = await Promise.all([
    prisma.user.findMany({
      where,
      select: {
        id: true, email: true, firstName: true, lastName: true,
        isActive: true, isProtected: true, mfaEnabled: true, lockedUntil: true,
        mustChangePassword: true, lastLoginAt: true, createdAt: true,
        roles: { select: { role: { select: { id: true, name: true } } } },
      },
      orderBy: { createdAt: "desc" },
      skip: (page - 1) * limit,
      take: limit,
    }),
    prisma.user.count({ where }),
  ]);

  res.json({ data: users, pagination: { page, limit, total, totalPages: Math.ceil(total / limit) } });
};

export const getUser = async (req: Request, res: Response): Promise<void> => {
  const { id } = validate(IdParamSchema, req.params);

  const user = await prisma.user.findUnique({
    where:   { id },
    include: {
      roles:   { select: { assignedAt: true, role: { select: { id: true, name: true } } } },
      devices: {
        orderBy: { lastUsedAt: "desc" },
        select:  { id: true, deviceName: true, ipAddress: true, isTrusted: true, trustedUntil: true, lastUsedAt: true },
      },
      _count: { select: { sessions: { where: { revokedAt: null, expiresAt: { gt: new Date() } } } } },
    },
  });

  if (!user) throw notFound("USER_NOT_FOUND", "User not found");

  const { _count, ...rest } = user;
  res.json({
    ...sanitizeUser(rest),
    devices: rest.devices.map(d => ({ ...d, ...trustView(d) })),
    activeSessions: _count.sessions,
  });
};

export const deactivateUser = async (req: Request, res: Response): Promise<void> => {
  const { id } = validate(IdParamSchema, req.params);
  if (id === req.user!.id) throw badRequest("CANNOT_MODIFY_SELF", "You cannot deactivate your own account");

  const user = await findUserOr404(id);
  assertNotProtected(user);

  await prisma.user.update({ where: { id }, data: { isActive: false } });
  const revokedSessions = await revokeAllSessions(id, "ACCOUNT_DEACTIVATED");

  res.locals.auditEvent   = "USER_DEACTIVATED";
  res.locals.auditDetails = { targetUserId: id, revokedSessions };
  res.json({ success: true, message: "User deactivated", revokedSessions });
};

export const activateUser = async (req: Request, res: Response): Promise<void> => {
  const { id } = validate(IdParamSchema, req.params);
  await findUserOr404(id);

  // Activation also clears any lockout
  await prisma.user.update({ where: { id }, data: { isActive: true, lockedUntil: null, failedLoginAttempts: 0 } });

  res.locals.auditEvent   = "USER_ACTIVATED";
  res.locals.auditDetails = { targetUserId: id };
  res.json({ success: true, message: "User activated" });
};

export const adminResetPassword = async (req: Request, res: Response): Promise<void> => {
  const { id } = validate(IdParamSchema, req.params);
  const user = await findUserOr404(id);
  assertNotProtected(user);

  const temporaryPassword = generateSecurePassword(16);
  await prisma.user.update({
    where: { id },
    data:  {
      passwordHash:        await hashPassword(temporaryPassword),
      passwordChangedAt:   new Date(),
      mustChangePassword:  true,
      failedLoginAttempts: 0,
      lockedUntil:         null,
    },
  });
  const revokedSessions = await revokeAllSessions(id, "ADMIN_PASSWORD_RESET");
  await prisma.device.updateMany({ where: { userId: id }, data: TRUST_CLEARED });

  res.locals.auditEvent   = "PASSWORD_RESET_BY_ADMIN";
  res.locals.auditDetails = { targetUserId: id, revokedSessions };
  res.json({
    success: true,
    temporaryPassword,
    revokedSessions,
    warning: "Shown once only — send via a secure channel. The user must change it after logging in.",
  });
};

export const deleteUser = async (req: Request, res: Response): Promise<void> => {
  const { id } = validate(IdParamSchema, req.params);
  if (id === req.user!.id) throw badRequest("CANNOT_MODIFY_SELF", "You cannot delete your own account");

  const user = await findUserOr404(id);
  assertNotProtected(user);

  // Sessions, devices and role assignments cascade; audit rows keep userId = null
  await prisma.user.delete({ where: { id } });

  res.locals.auditEvent   = "USER_DELETED";
  res.locals.auditDetails = { targetUserId: id, email: user.email };
  res.json({ success: true, message: "User deleted" });
};
