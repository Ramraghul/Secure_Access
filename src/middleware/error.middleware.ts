// src/middleware/error.middleware.ts — Global error handler (catches everything)
import { Request, Response, NextFunction } from "express";
import { logger } from "../lib/logger";
import { ZodError } from "zod";

interface AppError extends Error {
  statusCode?: number;
  code?:       string;
  details?:    unknown;
}

export const errorHandler = (
  err: AppError,
  req: Request,
  res: Response,
  _next: NextFunction
): void => {
  // ZodError from manual validate() calls
  if (err instanceof ZodError) {
    res.status(400).json({
      error:   "VALIDATION_ERROR",
      message: "Request validation failed",
      details: err.flatten().fieldErrors,
    });
    return;
  }

  const statusCode = err.statusCode ?? 500;
  const code       = err.code ?? "INTERNAL_ERROR";
  const message    = statusCode === 500 ? "An unexpected error occurred" : err.message;

  if (statusCode === 500) {
    logger.error("Unhandled error", {
      error:     err.message,
      stack:     err.stack,
      requestId: req.requestId,
      path:      req.path,
      method:    req.method,
    });
  }

  res.status(statusCode).json({
    error:   code,
    message,
    ...(err.details ? { details: err.details } : {}),
    ...(req.requestId ? { requestId: req.requestId } : {}),
  });
};

export const notFound = (req: Request, res: Response): void => {
  res.status(404).json({
    error:   "NOT_FOUND",
    message: `Cannot ${req.method} ${req.path}`,
  });
};
