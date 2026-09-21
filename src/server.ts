// src/server.ts — Entry point: starts the HTTP listener (or exports the app for Vercel)
import { app } from "./app";
import { config } from "./config";
import { logger } from "./lib/logger";
import { prisma } from "./lib/prisma";
import { flushAuditLogs } from "./middleware/audit.middleware";
import { CLIENT_HINT, MIGRATE_HINT, pendingMigrations, prismaClientIsStale } from "./lib/migrations";

// Vercel imports the app and invokes it per request — no listener there
export default app;

if (!process.env.VERCEL) {
  const server = app.listen(config.port, () => {
    logger.info(`SecureAccess running on http://localhost:${config.port}`);
    logger.info(`Console:    http://localhost:${config.port}/`);
    logger.info(`Swagger UI: http://localhost:${config.port}/api-docs/`);

    // Warn loudly when the generated client or the database lags behind the code
    if (prismaClientIsStale()) {
      logger.error(`Prisma Client is older than prisma/schema.prisma. ${CLIENT_HINT}`);
    }
    pendingMigrations().then(pending => {
      if (pending?.length) {
        logger.error(`Database schema is out of date — ${pending.length} migration(s) not applied: ${pending.join(", ")}. ${MIGRATE_HINT}`);
      }
    });
  });

  const shutdown = (signal: string) => {
    logger.info(`${signal} received — shutting down`);
    // Stop accepting connections, let in-flight requests and audit writes finish
    server.close(async () => {
      await flushAuditLogs();
      await prisma.$disconnect();
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10_000).unref();
  };

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT",  () => shutdown("SIGINT"));

  process.on("unhandledRejection", reason => {
    logger.error("Unhandled promise rejection", { reason: String(reason) });
  });

  // After an uncaught exception the process state is unknown: exit and let
  // the platform (Render, Docker restart policy, nodemon) start a clean one.
  process.on("uncaughtException", err => {
    logger.error("Uncaught exception — exiting", { error: err.message, stack: err.stack });
    process.exit(1);
  });
}
