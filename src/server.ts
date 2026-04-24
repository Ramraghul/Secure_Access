// src/server.ts — Application entry point
import "dotenv/config";
import "./config";
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

import authRoutes from "./routes/auth.routes";
import userRoutes from "./routes/user.routes";
import roleRoutes from "./routes/role.routes";
import auditRoutes from "./routes/audit.routes";
import deviceRoutes from "./routes/device.routes";
import openidRoutes from "./routes/openid.routes";
import { discovery } from "./openid/well-known";
import path from "path";

const app = express();

// ── Core middleware ─────────────────────────────────────────────
app.set("trust proxy", 1);

app.use(helmet());

app.use(
  cors({
    origin: process.env.ALLOWED_ORIGINS?.split(",") ?? "*",
    credentials: true,
  })
);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(
  morgan("combined", {
    stream: { write: (msg) => logger.http(msg.trim()) },
  })
);

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
      error: "RATE_LIMITED",
      message: "Too many requests, please try again later",
    },
  })
);

// ── Routes ──────────────────────────────────────────────────────
app.use("/api/v1/auth", authRoutes);
app.use("/api/v1/users", userRoutes);
app.use("/api/v1/roles", roleRoutes);
app.use("/api/v1/audit", auditRoutes);
app.use("/api/v1/devices", deviceRoutes);
app.use("/api/v1/openid", openidRoutes);

app.get("/.well-known/openid-configuration", discovery);

app.get("/", (_req, res) => {
  res.json({
    project: "SecureAccess",
    version: "2.0.0",
    docs: "/api-docs",
    status: "OK",
  });
});

// ── Swagger docs (FIXED for Vercel) ─────────────────────────────
let specs: any;

try {
  specs = swaggerJSDoc({
    definition: swaggerDefinition,
    apis: [
      path.join(__dirname, "routes/*.ts"),
      path.join(__dirname, "controllers/*.ts"),
    ],
  });
  
  // Fallback: ensure specs has required fields
  if (!specs.paths) {
    specs.paths = {};
  }
} catch (error) {
  logger.error("Failed to generate Swagger specs:", error);
  // Fallback specs object
  specs = swaggerDefinition;
  specs.paths = {};
}

app.get("/swagger.json", (_req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.send(specs);
});

app.use('/swagger-ui-assets', express.static(path.join(__dirname, '../node_modules/swagger-ui-dist')));

app.use(
  "/api-docs",
  swaggerUi.serve,
  swaggerUi.setup(specs, {
    explorer: true,
    swaggerOptions: {
      url: "/swagger.json",
    },
    customCss: `
      .swagger-ui .topbar { display: none }
      body { background: #fafafa; }
    `,
  })
);

// ── Error handling ──────────────────────────────────────────────
app.use(notFound);
app.use(errorHandler);

// ── Server config ───────────────────────────────────────────────
const PORT = process.env.PORT ?? 4000;

let server: any;
let isRestarting = false;

// ── Start server ────────────────────────────────────────────────
const startServer = (retryCount = 0, maxRetries = 3) => {
  try {
    server = app.listen(PORT, () => {
      isRestarting = false;
      logger.info(`SecureAccess v2 running on http://localhost:${PORT}`);
      logger.info(`Swagger UI: http://localhost:${PORT}/api-docs`);
    });

    server.on("error", (err: any) => {
      logger.error("Server error:", err);

      if (err.code === "EADDRINUSE") {
        logger.error(`Port ${PORT} is already in use. Restarting...`);
        setTimeout(() => restartServer(), 2000);
      } else {
        logger.error("Critical server error. Restarting...");
        setTimeout(() => restartServer(), 3000);
      }
    });
  } catch (err) {
    logger.error("Failed to start server:", err);

    if (retryCount < maxRetries) {
      logger.info(`Retry ${retryCount + 1}/${maxRetries}...`);
      setTimeout(() => startServer(retryCount + 1, maxRetries), 3000);
    } else {
      logger.error("Max retries reached. Exiting...");
      process.exit(1);
    }
  }
};

// ── Restart logic ───────────────────────────────────────────────
const restartServer = () => {
  if (isRestarting) {
    logger.warn("Restart already in progress...");
    return;
  }

  isRestarting = true;
  logger.warn("Restarting server...");

  if (server) {
    server.close(() => {
      logger.info("Server closed. Restarting...");
      setTimeout(() => startServer(), 1000);
    });

    setTimeout(() => {
      if (isRestarting) {
        logger.error("Forced shutdown");
        process.exit(1);
      }
    }, 5000);
  } else {
    startServer();
  }
};

// ── Critical error detection ────────────────────────────────────
const isCriticalError = (err: any): boolean => {
  if (err?.code === "VALIDATION_ERROR") return false;
  if ([400, 401, 403].includes(err?.statusCode)) return false;
  return true;
};

// ── Global error handlers ───────────────────────────────────────
process.on("uncaughtException", (err: Error) => {
  logger.error("Uncaught Exception:", err);
  if (isCriticalError(err)) restartServer();
});

process.on("unhandledRejection", (reason: any) => {
  logger.error("Unhandled Rejection:", reason);
  if (isCriticalError(reason)) restartServer();
});

// ── Graceful shutdown ───────────────────────────────────────────
process.on("SIGTERM", () => {
  logger.info("SIGTERM received");
  server?.close(() => process.exit(0));
});

process.on("SIGINT", () => {
  logger.info("SIGINT received");
  server?.close(() => process.exit(0));
});

// ── Export for Vercel ───────────────────────────────────────────
export default app;

// ── Start only if NOT Vercel ────────────────────────────────────
if (!process.env.VERCEL) {
  startServer();
}