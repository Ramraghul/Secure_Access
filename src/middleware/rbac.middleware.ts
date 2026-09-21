// src/middleware/rbac.middleware.ts — Permission-based access control
import { Request, Response, NextFunction } from "express";
import { prisma } from "../lib/prisma";
import { grants, PermissionGrant } from "../utils/permissions";
import { forbidden, unauthorized } from "../utils/errors";

// Every permission granted to the user through any of their roles — one query
const loadPermissions =(userId: string): Promise<PermissionGrant[]> =>
  prisma.permission.findMany({
    where:  { role: { users: { some: { userId } } } },
    select: { action: true, resource: true },
  });

export const requirePermission =
  (action: string, resource: string) =>
  async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    if (!req.user) return next(unauthorized("AUTH_REQUIRED", "Authentication required"));

    try {
      const held = await loadPermissions(req.user.id);
      if (grants(held, action, resource)) return next();
      next(forbidden("FORBIDDEN", `Missing permission: ${action}:${resource}`));
    } catch (err) {
      next(err);
    }
  };
