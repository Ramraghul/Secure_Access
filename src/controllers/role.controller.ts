// src/controllers/role.controller.ts
import { Request, Response } from "express";
import { validate, CreateRoleSchema, AssignRoleSchema } from "../utils/validation";
import { prisma } from "../lib/prisma";

export const listRoles = async (req: Request, res: Response): Promise<void> => {
  const roles = await prisma.role.findMany({
    include: {
      permissions: true,
      users: { select: { user: { select: { id: true, email: true, firstName: true, lastName: true } } } },
    },
    orderBy: { name: "asc" },
  });
  res.json(roles);
};

export const createRole = async (req: Request, res: Response): Promise<void> => {
  const body = validate(CreateRoleSchema, req.body);

  const existing = await prisma.role.findUnique({ where: { name: body.name } });
  if (existing) { res.status(409).json({ error: "ROLE_EXISTS", message: "Role name already exists" }); return; }

  const role = await prisma.role.create({
    data: {
      name:        body.name,
      description: body.description,
      permissions: { create: body.permissions ?? [] },
    },
    include: { permissions: true },
  });
  res.status(201).json(role);
};

export const updateRole = async (req: Request, res: Response): Promise<void> => {
  const { id } = req.params;
  const body   = validate(CreateRoleSchema.partial(), req.body);

  if (body.name) {
    const conflict = await prisma.role.findFirst({ where: { name: body.name, id: { not: id } } });
    if (conflict) { res.status(409).json({ error: "ROLE_NAME_TAKEN" }); return; }
  }

  await prisma.$transaction(async tx => {
    await tx.role.update({ where: { id }, data: { name: body.name, description: body.description } });
    if (body.permissions !== undefined) {
      await tx.permission.deleteMany({ where: { roleId: id } });
      if (body.permissions.length > 0) {
        await tx.permission.createMany({ data: body.permissions.map(p => ({ ...p, roleId: id })) });
      }
    }
  });

  const updated = await prisma.role.findUnique({ where: { id }, include: { permissions: true } });
  res.json(updated);
};

export const assignRole = async (req: Request, res: Response): Promise<void> => {
  const { id: roleId } = req.params;
  const { userId }     = validate(AssignRoleSchema, req.body);

  const [role, user] = await Promise.all([
    prisma.role.findUnique({ where: { id: roleId } }),
    prisma.user.findUnique({ where: { id: userId } }),
  ]);

  if (!role) { res.status(404).json({ error: "ROLE_NOT_FOUND" }); return; }
  if (!user) { res.status(404).json({ error: "USER_NOT_FOUND" }); return; }

  await prisma.userRole.upsert({
    where:  { userId_roleId: { userId, roleId } },
    update: {},
    create: { userId, roleId },
  });

  res.json({ success: true, message: "Role assigned" });
};

export const revokeRole = async (req: Request, res: Response): Promise<void> => {
  const { id: roleId } = req.params;
  const { userId }     = validate(AssignRoleSchema, req.body);

  await prisma.userRole.delete({ where: { userId_roleId: { userId, roleId } } });
  res.json({ success: true, message: "Role revoked" });
};
