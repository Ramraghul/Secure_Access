// src/app.ts — Builds the Express application (no network listener; see server.ts)
import express, { Router } from "express";
import cors, { CorsOptions } from "cors";
import helmet from "helmet";
import morgan from "morgan";
import path from "path";

import { config } from "./config";
import { logger } from "./lib/logger";
import { checkDb } from "./lib/prisma";
import { MIGRATE_HINT, pendingMigrations } from "./lib/migrations";
import { requestId } from "./middleware/requestId.middleware";
import { auditLog } from "./middleware/audit.middleware";
import { apiLimiter } from "./middleware/rateLimit.middleware";
import { asyncHandler } from "./middleware/asyncHandler.middleware";
import { errorHandler, notFound } from "./middleware/error.middleware";
import { docsRouter } from "./swagger/docs";
import { discovery } from "./controllers/openid.controller";

import authRoutes from "./routes/auth.routes";
import userRoutes from "./routes/user.routes";
import roleRoutes from "./routes/role.routes";
import auditRoutes from "./routes/audit.routes";
import deviceRoutes from "./routes/device.routes";
import openidRoutes from "./routes/openid.routes";

export const API_PREFIX = "/api/v1";
const VERSION           = "3.0.0";

// Exported so tests can check every route is documented in the OpenAPI spec
export const apiRouters: ReadonlyArray<[string, Router]> = [
  ["/auth",    authRoutes],
  ["/users",   userRoutes],
  ["/roles",   roleRoutes],
  ["/audit",   auditRoutes],
  ["/devices", deviceRoutes],
  ["/openid",  openidRoutes],
];

// Bearer tokens (not cookies) authenticate requests, so credentials are never needed cross-origin
function corsOptions(): CorsOptions {
  const { origins } = config.cors;
  return {
    origin:         origins.includes("*") ? "*" : (origin, cb) => cb(null, !origin || origins.includes(origin)),
    methods:        ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Request-Id"],
    exposedHeaders: ["X-Request-Id", "RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset"],
    maxAge:         600,
  };
}

function createApp() {
  const app = express();
  const startedAt = Date.now();

  app.set("trust proxy", config.trustProxy);
  app.disable("x-powered-by");

  // ── Core middleware ───────────────────────────────────────────
  app.use(requestId);
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        "script-src": ["'self'"],
        "img-src":    ["'self'", "data:"],
        // Only when served over HTTPS — upgrading would break plain-http localhost/Docker
        "upgrade-insecure-requests": config.publicUrl.startsWith("https://") ? [] : null,
      },
    },
  }));
  app.use(cors(corsOptions()));
  app.use(express.json({ limit: "100kb" }));
  app.use(express.urlencoded({ extended: false, limit: "100kb" }));

  if (!config.isTest) {
    app.use(morgan(config.isProd ? "combined" : "dev", {
      stream: { write: msg => logger.http(msg.trim()) },
    }));
  }

  // ── Health & metadata ─────────────────────────────────────────
  app.get("/health", asyncHandler(async (_req, res) => {
    const dbUp       = await checkDb();
    const pending    = dbUp ? await pendingMigrations() : null;
    const migrations = pending === null ? "unknown" : pending.length > 0 ? "pending" : "up-to-date";
    const healthy    = dbUp && migrations !== "pending";

    res.status(healthy ? 200 : 503).json({
      status:        healthy ? "ok" : "degraded",
      database:      dbUp ? "up" : "down",
      migrations,
      ...(pending?.length ? { pendingMigrations: pending, hint: MIGRATE_HINT } : {}),
      version:       VERSION,
      uptimeSeconds: Math.round((Date.now() - startedAt) / 1000),
      timestamp:     new Date().toISOString(),
    });
  }));

  app.get(API_PREFIX, (_req, res) => {
    res.json({
      project: "SecureAccess",
      version: VERSION,
      docs:    "/api-docs",
      openapi: "/swagger.json",
      health:  "/health",
      console: "/",
      oidc:    "/.well-known/openid-configuration",
    });
  });

  // OpenID discovery lives at the issuer root, as the spec requires
  app.get("/.well-known/openid-configuration", discovery);

  // ── API docs ──────────────────────────────────────────────────
  app.use(docsRouter);

  // ── API routes (rate limited, every request audited) ─────────
  app.use(API_PREFIX, apiLimiter, auditLog);
  for (const [prefix, router] of apiRouters) {
    app.use(`${API_PREFIX}${prefix}`, router);
  }
  app.use(API_PREFIX, notFound);

  // ── Interactive console (static HTML/JS, same origin as the API) ──
  app.use(express.static(path.join(__dirname, "..", "public"), {
    extensions: ["html"],
    maxAge:     config.isProd ? "1h" : 0,
  }));

  // ── Error handling ────────────────────────────────────────────
  app.use(notFound);
  app.use(errorHandler);

  return app;
}

export const app = createApp();
