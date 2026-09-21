// src/lib/prisma.ts — Singleton Prisma client
import { PrismaClient } from "@prisma/client";
import { logger } from "./logger";

const globalForPrisma = globalThis as unknown as { prisma?: PrismaClient };

const logSlowQueries = process.env.NODE_ENV === "development";

export const prisma =
  globalForPrisma.prisma ??
  new PrismaClient({
    log: logSlowQueries
      ? [{ level: "query", emit: "event" }, { level: "warn", emit: "stdout" }, { level: "error", emit: "stdout" }]
      : [{ level: "error", emit: "stdout" }],
  });

if (logSlowQueries) {
  (prisma as any).$on("query", (e: { query: string; duration: number }) => {
    if (e.duration > 200) {
      logger.warn("Slow query detected", { query: e.query, durationMs: e.duration });
    }
  });
}

// Reuse one client across hot reloads / serverless invocations of the same instance
globalForPrisma.prisma = prisma;

export async function checkDb(): Promise<boolean> {
  try {
    await prisma.$queryRaw`SELECT 1`;
    return true;
  } catch {
    return false;
  }
}
