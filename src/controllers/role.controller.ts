// src/controllers/role.controller.ts
import { Request, Response } from "express";
import { prisma } from "../lib/prisma";
import { conflict, forbidden, notFound } from "../utils/errors";
import {
  validate, CreateRoleSchema, UpdateRoleSchema, AssignRoleSchema, IdParamSchema,
} from "../utils/validation";
import { assertNotProtected } from "../services/user.service";

const roleInclude = {
  permissions: { select: { id: true, action: true, resource: true } },
  users: {
    select: { assignedAt: true, user: { select: { id: true, email: true, firstName: true, lastName: true } } },
  },
} as const;

async function findRoleOr404(id: string) {
  const role = await prisma.role.findUnique({ where: { id } });
  if (!role) throw notFound("ROLE_NOT_FOUND", "Role not found");
  return role;
}

export const listRoles = async (_req: Request, res: Response): Promise<void> => {
  const roles = await prisma.role.findMany({ include: roleInclude, orderBy: { name: "asc" } });
  res.json(roles);
};

export const getRole = async (req: Request, res: Response): Promise<void> => {
  const { id } = validate(IdParamSchema, req.params);
  const role = await prisma.role.findUnique({ where: { id }, include: roleInclude });
  if (!role) throw notFound("ROLE_NOT_FOUND", "Role not found");
  res.json(role);
};

export const createRole = async (req: Request, res: Response): Promise<void> => {
  const body = validate(CreateRoleSchema, req.body);

  const existing = await prisma.role.findUnique({ where: { name: body.name } });
  if (existing) throw conflict("ROLE_EXISTS", "Role name already exists");

  const role = await prisma.role.create({
    data: {
      name:        body.name,
      description: body.description,
      permissions: { create: dedupe(body.permissions ?? []) },
    },
    include: roleInclude,
  });

  res.locals.auditEvent   = "ROLE_CREATED";
  res.locals.auditDetails = { roleId: role.id, name: role.name };
  res.status(201).json(role);
};

export const updateRole = async (req: Request, res: Response): Promise<void> => {
  const { id } = validate(IdParamSchema, req.params);
  const body   = validate(UpdateRoleSchema, req.body);
  const role   = await findRoleOr404(id);

  // System roles keep their name and permissions so nobody can lock out the admins
  if (role.isSystem && (body.name !== undefined && body.name !== role.name || body.permissions !== undefined)) {
    throw forbidden("SYSTEM_ROLE", "System roles only allow description changes");
  }

  if (body.name && body.name !== role.name) {
    const taken = await prisma.role.findUnique({ where: { name: body.name } });
    if (taken) throw conflict("ROLE_NAME_TAKEN", "Role name already exists");
  }

  await prisma.$transaction(async tx => {
    await tx.role.update({ where: { id }, data: { name: body.name, description: body.description } });
    if (body.permissions !== undefined) {
      await tx.permission.deleteMany({ where: { roleId: id } });
      const permissions = dedupe(body.permissions);
      if (permissions.length > 0) {
        await tx.permission.createMany({ data: permissions.map(p => ({ ...p, roleId: id })) });
      }
    }
  });

  const updated = await prisma.role.findUnique({ where: { id }, include: roleInclude });
  res.locals.auditEvent   = "ROLE_UPDATED";
  res.locals.auditDetails = { roleId: id, changes: Object.keys(body) };
  res.json(updated);
};

export const deleteRole = async (req: Request, res: Response): Promise<void> => {
  const { id } = validate(IdParamSchema, req.params);
  const role   = await findRoleOr404(id);
  if (role.isSystem) throw forbidden("SYSTEM_ROLE", "System roles cannot be deleted");

  await prisma.role.delete({ where: { id } });
  res.locals.auditEvent   = "ROLE_DELETED";
  res.locals.auditDetails = { roleId: id, name: role.name };
  res.json({ success: true, message: "Role deleted" });
};

export const assignRole = async (req: Request, res: Response): Promise<void> => {
  const { id: roleId } = validate(IdParamSchema, req.params);
  const { userId }     = validate(AssignRoleSchema, req.body);

  const [role, user] = await Promise.all([
    prisma.role.findUnique({ where: { id: roleId } }),
    prisma.user.findUnique({ where: { id: userId } }),
  ]);

  if (!role) throw notFound("ROLE_NOT_FOUND", "Role not found");
  if (!user) throw notFound("USER_NOT_FOUND", "User not found");
  assertNotProtected(user);

  await prisma.userRole.upsert({
    where:  { userId_roleId: { userId, roleId } },
    update: {},
    create: { userId, roleId },
  });

  res.locals.auditEvent   = "ROLE_ASSIGNED";
  res.locals.auditDetails = { roleId, role: role.name, targetUserId: userId };
  res.json({ success: true, message: "Role assigned" });
};

export const revokeRole = async (req: Request, res: Response): Promise<void> => {
  const { id: roleId } = validate(IdParamSchema, req.params);
  const { userId }     = validate(AssignRoleSchema, req.body);

  const [role, user] = await Promise.all([
    prisma.role.findUnique({ where: { id: roleId } }),
    prisma.user.findUnique({ where: { id: userId } }),
  ]);

  if (!role) throw notFound("ROLE_NOT_FOUND", "Role not found");
  if (!user) throw notFound("USER_NOT_FOUND", "User not found");
  assertNotProtected(user);

  if (role.name === "admin") {
    const admins = await prisma.userRole.count({ where: { roleId } });
    if (admins <= 1) throw conflict("LAST_ADMIN", "Cannot revoke the admin role from the last administrator");
  }

  const { count } = await prisma.userRole.deleteMany({ where: { userId, roleId } });
  if (count === 0) throw notFound("ROLE_NOT_ASSIGNED", "User does not have this role");

  res.locals.auditEvent   = "ROLE_REVOKED";
  res.locals.auditDetails = { roleId, role: role.name, targetUserId: userId };
  res.json({ success: true, message: "Role revoked" });
};

function dedupe<T extends { action: string; resource: string }>(permissions: T[]): T[] {
  const seen = new Set<string>();
  return permissions.filter(p => {
    const key = `${p.action}:${p.resource}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
