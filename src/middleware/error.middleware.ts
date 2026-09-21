// src/middleware/error.middleware.ts — Global error handler (catches everything)
import { Request, Response, NextFunction } from "express";
import { Prisma } from "@prisma/client";
import { ZodError } from "zod";
import { logger } from "../lib/logger";
import { AppError } from "../utils/errors";
import { CLIENT_HINT, MIGRATE_HINT } from "../lib/migrations";

interface HttpErrorShape {
  status: number;
  code: string;
  message: string;
  details?: unknown;
  hint?: string; // logged, never sent to the client
}

function toHttpError(err: unknown): HttpErrorShape {
  if (err instanceof AppError) {
    return { status: err.statusCode, code: err.code, message: err.message, details: err.details };
  }

  if (err instanceof ZodError) {
    return { status: 400, code: "VALIDATION_ERROR", message: "Request validation failed", details: err.flatten().fieldErrors };
  }

  if (err instanceof Prisma.PrismaClientKnownRequestError) {
    switch (err.code) {
      case "P2025": return { status: 404, code: "NOT_FOUND", message: "Resource not found" };
      case "P2002": return { status: 409, code: "CONFLICT", message: "Resource already exists" };
      case "P2003": return { status: 409, code: "CONFLICT", message: "Operation violates a relation constraint" };
      // Table / column missing: the code is newer than the database schema
      case "P2021":
      case "P2022":
        return {
          status:  503,
          code:    "SCHEMA_OUT_OF_DATE",
          message: "The service is being updated. Please try again shortly.",
          hint:    `Database schema is out of date. ${MIGRATE_HINT}`,
        };
    }
  }

  // Raised before any query runs when the generated client does not know a field the code uses
  if (err instanceof Prisma.PrismaClientValidationError && /Unknown (argument|field)/.test(err.message)) {
    return {
      status:  500,
      code:    "INTERNAL_ERROR",
      message: "An unexpected error occurred",
      hint:    `Prisma Client does not match the code — usually it is out of date. ${CLIENT_HINT}`,
    };
  }

  // body-parser errors carry a `type`
  const type = (err as { type?: string })?.type;
  if (type === "entity.parse.failed") return { status: 400, code: "INVALID_JSON", message: "Malformed JSON body" };
  if (type === "entity.too.large")    return { status: 413, code: "PAYLOAD_TOO_LARGE", message: "Request body too large" };

  return { status: 500, code: "INTERNAL_ERROR", message: "An unexpected error occurred" };
}

export const errorHandler = (err: unknown, req: Request, res: Response, next: NextFunction): void => {
  if (res.headersSent) return next(err);

  const { status, code, message, details, hint } = toHttpError(err);

  if (status >= 500) {
    logger.error(hint ?? "Unhandled error", {
      error:     err instanceof Error ? err.message : String(err),
      stack:     err instanceof Error ? err.stack : undefined,
      requestId: req.requestId,
      path:      req.path,
      method:    req.method,
    });
  }

  res.status(status).json({
    error: code,
    message,
    ...(details ? { details } : {}),
    ...(req.requestId ? { requestId: req.requestId } : {}),
  });
};

export const notFound = (req: Request, res: Response): void => {
  // originalUrl, not path: inside a mounted router req.path drops the mount prefix
  res.status(404).json({
    error:   "NOT_FOUND",
    message: `Cannot ${req.method} ${req.originalUrl.split("?")[0]}`,
  });
};
