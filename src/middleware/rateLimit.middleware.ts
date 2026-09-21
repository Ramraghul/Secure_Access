// src/middleware/rateLimit.middleware.ts
// In-memory store: limits are per process. Good enough for a single Render
// instance; on serverless each warm instance counts separately.
import rateLimit from "express-rate-limit";
import { config } from "../config";

const skip = () => !config.rateLimit.enabled;

export const apiLimiter = rateLimit({
  windowMs:        config.rateLimit.windowMs,
  limit:           config.rateLimit.max,
  standardHeaders: true,
  legacyHeaders:   false,
  skip,
  message: { error: "RATE_LIMITED", message: "Too many requests, please try again later" },
});

// Credential endpoints: only failed attempts count toward the limit
export const authLimiter = rateLimit({
  windowMs:               config.rateLimit.windowMs,
  limit:                  config.rateLimit.authMax,
  standardHeaders:        true,
  legacyHeaders:          false,
  skipSuccessfulRequests: true,
  skip,
  message: { error: "RATE_LIMITED", message: "Too many authentication attempts, please try again later" },
});
