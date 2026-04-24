// src/lib/logger.ts — Winston structured logger (replaces all console.log)
import { createLogger, format, transports } from "winston";
import "winston-daily-rotate-file";

const { combine, timestamp, errors, json, colorize, simple } = format;

const isDev = process.env.NODE_ENV !== "production";

export const logger = createLogger({
  level: isDev ? "debug" : "info",
  format: combine(
    timestamp(),
    errors({ stack: true }),
    json()
  ),
  transports: [
    // Console — colourised in dev, plain JSON in prod
    new transports.Console({
      format: isDev ? combine(colorize(), simple()) : json(),
    }),
    // Rotating daily file for production
    new (transports as any).DailyRotateFile({
      filename:     "logs/secureaccess-%DATE%.log",
      datePattern:  "YYYY-MM-DD",
      maxFiles:     "30d",
      maxSize:      "20m",
      zippedArchive: true,
    }),
    // Separate error log
    new (transports as any).DailyRotateFile({
      filename:    "logs/errors-%DATE%.log",
      datePattern: "YYYY-MM-DD",
      level:       "error",
      maxFiles:    "90d",
    }),
  ],
});
