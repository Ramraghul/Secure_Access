// src/lib/prisma.ts — Singleton Prisma client with connection pooling
import { PrismaClient } from "@prisma/client";
import { logger } from "./logger";

const globalForPrisma = globalThis as unknown as { prisma?: PrismaClient };

export const prisma =
  globalForPrisma.prisma ??
  new PrismaClient({
    log: [
      { level: "query", emit: "event" },
      { level: "warn", emit: "stdout" },
      { level: "error", emit: "stdout" },
    ],
  });

// Log slow queries in development
if (process.env.NODE_ENV !== "production") {
  (prisma as any).$on("query", (e: { query: string; duration: number }) => {
    if (e.duration > 200) {
      logger.warn("Slow query detected", { query: e.query, durationMs: e.duration });
    }
  });
  globalForPrisma.prisma = prisma;
}

export async function checkDb(): Promise<boolean> {
  try {
    await prisma.$queryRaw`SELECT 1`;
    return true;
  } catch {
    return false;
  }
}
