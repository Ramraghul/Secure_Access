// src/server.ts — Application entry point
import "dotenv/config";
import "./config"; // validate env vars at startup
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import morgan from "morgan";
import swaggerUi from "swagger-ui-express";
import swaggerJSDoc from "swagger-jsdoc";

import { swaggerDefinition } from "./swagger/swagger";
import { errorHandler, notFound } from "./middleware/error.middleware";
import { logger } from "./lib/logger";

import authRoutes    from "./routes/auth.routes";
import userRoutes    from "./routes/user.routes";
import roleRoutes    from "./routes/role.routes";
import auditRoutes   from "./routes/audit.routes";
import deviceRoutes  from "./routes/device.routes";
import openidRoutes  from "./routes/openid.routes";
import { discovery } from "./openid/well-known";

const app = express();

// ── Core middleware ────────────────────────────────────────────────────────────
app.set("trust proxy", 1);
app.use(helmet());
app.use(cors({ origin: process.env.ALLOWED_ORIGINS?.split(",") ?? "*", credentials: true }));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan("combined", { stream: { write: msg => logger.http(msg.trim()) } }));

app.use(rateLimit({
  windowMs:       15 * 60 * 1000,
  max:            100,
  standardHeaders: true,
  legacyHeaders:  false,
  message:        { error: "RATE_LIMITED", message: "Too many requests, please try again later" },
}));

// ── Routes ────────────────────────────────────────────────────────────────────
app.use("/api/v1/auth",    authRoutes);
app.use("/api/v1/users",   userRoutes);
app.use("/api/v1/roles",   roleRoutes);
app.use("/api/v1/audit",   auditRoutes);
app.use("/api/v1/devices", deviceRoutes);
app.use("/api/v1/openid",  openidRoutes);
app.get("/.well-known/openid-configuration", discovery);

app.get("/", (_req, res) =>
  res.json({ project: "SecureAccess", version: "2.0.0", docs: "/api-docs", status: "OK" })
);

// ── Swagger docs ───────────────────────────────────────────────────────────────
const specs = swaggerJSDoc({
  definition: swaggerDefinition,
  apis: ["./src/routes/*.ts", "./src/controllers/*.ts"],
});
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(specs, { explorer: false }));

// ── Error handling (MUST be last) ─────────────────────────────────────────────
app.use(notFound);
app.use(errorHandler);

const PORT = process.env.PORT ?? 4000;

let server: any;
let isRestarting = false;

// ── Server start function ──────────────────────────────────────────────────────
const startServer = (retryCount = 0, maxRetries = 3) => {
  try {
    server = app.listen(PORT, () => {
      isRestarting = false;
      logger.info(`SecureAccess v2 running on http://localhost:${PORT}`);
      logger.info(`Swagger UI: http://localhost:${PORT}/api-docs`);
    });

    // Handle server errors
    server.on("error", (err: any) => {
      logger.error("Server error:", err);
      if (err.code === "EADDRINUSE") {
        logger.error(`Port ${PORT} is already in use. Attempting restart...`);
        setTimeout(() => restartServer(), 2000);
      } else {
        logger.error("Critical server error. Restarting...");
        setTimeout(() => restartServer(), 3000);
      }
    });
  } catch (err) {
    logger.error("Failed to start server:", err);
    if (retryCount < maxRetries) {
      logger.info(`Retry attempt ${retryCount + 1}/${maxRetries}...`);
      setTimeout(() => startServer(retryCount + 1, maxRetries), 3000);
    } else {
      logger.error("Max retry attempts reached. Exiting...");
      process.exit(1);
    }
  }
};

// ── Restart function ──────────────────────────────────────────────────────────
const restartServer = () => {
  if (isRestarting) {
    logger.warn("Restart already in progress...");
    return;
  }

  isRestarting = true;
  logger.warn("Restarting server...");

  if (server) {
    server.close(() => {
      logger.info("Server closed. Starting new instance...");
      setTimeout(() => startServer(), 1000);
    });

    // Force close after 5 seconds if graceful shutdown fails
    setTimeout(() => {
      if (isRestarting) {
        logger.error("Forced shutdown of server");
        process.exit(1);
      }
    }, 5000);
  } else {
    startServer();
  }
};

// ── Global error handlers ──────────────────────────────────────────────────────
// Only restart for critical errors, not validation/user errors
const isCriticalError = (err: any): boolean => {
  // Don't restart for validation or user input errors
  if (err?.code === "VALIDATION_ERROR") return false;
  if (err?.statusCode === 400 || err?.statusCode === 401 || err?.statusCode === 403) return false;
  
  // Restart for system/database/critical errors
  return true;
};

process.on("uncaughtException", (err: Error) => {
  logger.error("Uncaught Exception:", err);
  logger.error("Stack:", err.stack);
  if (isCriticalError(err)) {
    logger.error("Critical error detected. Restarting server...");
    restartServer();
  } else {
    logger.warn("Non-critical error. Server will continue running.");
  }
});

process.on("unhandledRejection", (reason: any, promise: Promise<any>) => {
  logger.warn("Unhandled Rejection at:", promise);
  logger.warn("Reason:", reason);
  if (isCriticalError(reason)) {
    logger.error("Critical error detected. Restarting server...");
    restartServer();
  } else {
    logger.warn("Non-critical rejection. Server will continue running.");
  }
});

// ── Graceful shutdown ──────────────────────────────────────────────────────────
process.on("SIGTERM", () => {
  logger.info("SIGTERM signal received: closing HTTP server");
  if (server) {
    server.close(() => {
      logger.info("HTTP server closed");
      process.exit(0);
    });
  }
});

process.on("SIGINT", () => {
  logger.info("SIGINT signal received: closing HTTP server");
  if (server) {
    server.close(() => {
      logger.info("HTTP server closed");
      process.exit(0);
    });
  }
});

// Start the server
startServer();

export { app, restartServer, startServer };
