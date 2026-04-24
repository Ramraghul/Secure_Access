// src/middleware/rbac.middleware.ts — Optimised RBAC (one DB query instead of two)
import { Request, Response, NextFunction } from "express";
import { prisma } from "../lib/prisma";

export const requirePermission =
  (action: string, resource: string) =>
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({ error: "AUTH_REQUIRED", message: "Authentication required" });
      return;
    }

    try {
      // Single query: check admin role OR specific permission
      const [isAdmin, hasPermission] = await Promise.all([
        prisma.userRole.findFirst({
          where: { userId, role: { name: "admin" } },
          select: { userId: true },
        }),
        prisma.permission.findFirst({
          where: {
            action,
            resource,
            role: { users: { some: { userId } } },
          },
          select: { id: true },
        }),
      ]);

      if (isAdmin || hasPermission) { next(); return; }

      res.status(403).json({
        error:   "FORBIDDEN",
        message: `Missing permission: ${action}:${resource}`,
      });
    } catch (err) {
      res.status(500).json({ error: "PERMISSION_CHECK_FAILED" });
    }
  };

export const requireAnyPermission =
  (permissions: { action: string; resource: string }[]) =>
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({ error: "AUTH_REQUIRED" });
      return;
    }

    const [isAdmin, ...checks] = await Promise.all([
      prisma.userRole.findFirst({ where: { userId, role: { name: "admin" } } }),
      ...permissions.map(({ action, resource }) =>
        prisma.permission.findFirst({
          where: { action, resource, role: { users: { some: { userId } } } },
        })
      ),
    ]);

    if (isAdmin || checks.some(Boolean)) { next(); return; }

    res.status(403).json({ error: "FORBIDDEN", message: "No matching permissions" });
  };
