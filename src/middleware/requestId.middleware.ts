// src/middleware/requestId.middleware.ts — Correlation id for logs, audit rows and error responses
import { Request, Response, NextFunction } from "express";
import { randomUUID } from "crypto";

const VALID_ID = /^[A-Za-z0-9-]{8,64}$/;

export const requestId = (req: Request, res: Response, next: NextFunction): void => {
  const incoming = req.headers["x-request-id"];
  req.requestId = typeof incoming === "string" && VALID_ID.test(incoming) ? incoming : randomUUID();
  res.setHeader("X-Request-Id", req.requestId);
  next();
};
