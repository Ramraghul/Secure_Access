// src/controllers/user.controller.ts
import { Request, Response } from "express";
import { hashPassword } from "../utils/password";
import { generateSecurePassword } from "../utils/password";
import { validate, PaginationSchema } from "../utils/validation";
import { prisma } from "../lib/prisma";

export const listUsers = async (req: Request, res: Response): Promise<void> => {
  const validated = validate(PaginationSchema, req.query);
  const page = validated.page || 1;
  const limit = validated.limit || 50;
  const search = validated.search;
  const skip = (page - 1) * limit;

  const where = search
    ? { OR: [
        { email:     { contains: search, mode: "insensitive" as const } },
        { firstName: { contains: search, mode: "insensitive" as const } },
        { lastName:  { contains: search, mode: "insensitive" as const } },
      ]}
    : {};

  const [users, total] = await Promise.all([
    prisma.user.findMany({
      where,
      select: {
        id: true, email: true, firstName: true, lastName: true,
        isActive: true, mfaEnabled: true, createdAt: true,
        roles: { include: { role: { select: { id: true, name: true } } } },
      },
      orderBy: { createdAt: "desc" },
      skip, take: limit,
    }),
    prisma.user.count({ where }),
  ]);

  res.json({ data: users, pagination: { page, limit, total, totalPages: Math.ceil(total / limit) } });
};

export const getUser = async (req: Request, res: Response): Promise<void> => {
  const user = await prisma.user.findUnique({
    where:   { id: req.params.id },
    include: {
      roles:   { include: { role: true } },
      devices: {
        orderBy: { lastUsedAt: "desc" },
        select:  { id: true, deviceName: true, ipAddress: true, isTrusted: true, lastUsedAt: true },
      },
    },
  });

  if (!user) { res.status(404).json({ error: "USER_NOT_FOUND" }); return; }

  // Remove passwordHash and secrets from the response
  const { passwordHash, mfaSecret, backupCodesHashed, ...safe } = user as any;
  res.json(safe);
};

export const deactivateUser = async (req: Request, res: Response): Promise<void> => {
  await prisma.user.update({ where: { id: req.params.id }, data: { isActive: false } });
  res.json({ success: true, message: "User deactivated" });
};

export const activateUser = async (req: Request, res: Response): Promise<void> => {
  await prisma.user.update({ where: { id: req.params.id }, data: { isActive: true } });
  res.json({ success: true, message: "User activated" });
};

export const adminResetPassword = async (req: Request, res: Response): Promise<void> => {
  const tempPassword   = generateSecurePassword(16);
  const passwordHash   = await hashPassword(tempPassword);
  await prisma.user.update({ where: { id: req.params.id }, data: { passwordHash } });
  res.json({
    success:           true,
    temporaryPassword: tempPassword,
    warning:           "Shown once only — send via secure channel and force change on next login",
  });
};
