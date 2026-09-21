// src/lib/logger.ts — Winston structured logger (replaces all console.log)
import { createLogger, format, transports } from "winston";
import "winston-daily-rotate-file";
import fs from "fs";
import path from "path";

const { combine, timestamp, errors, json, colorize, simple } = format;

const env    = process.env.NODE_ENV ?? "development";
const isDev  = env === "development";
const isTest = env === "test";

// Serverless filesystems are read-only except /tmp
const LOG_DIR = process.env.LOG_DIR ?? (process.env.VERCEL ? "/tmp/logs" : "logs");

function isWritable(dir: string): boolean {
  try {
    fs.mkdirSync(dir, { recursive: true });
    const testFile = path.join(dir, ".tmp-write-test");
    fs.writeFileSync(testFile, "");
    fs.unlinkSync(testFile);
    return true;
  } catch {
    return false;
  }
}

const fileTransports: transports.FileTransportInstance[] = [];

if (!isTest && process.env.LOG_TO_FILE !== "false" && isWritable(LOG_DIR)) {
  fileTransports.push(
    new (transports as any).DailyRotateFile({
      filename: path.join(LOG_DIR, "secureaccess-%DATE%.log"),
      datePattern: "YYYY-MM-DD",
      maxFiles: "14d",
      maxSize: "20m",
      zippedArchive: true,
    }),
    new (transports as any).DailyRotateFile({
      filename: path.join(LOG_DIR, "errors-%DATE%.log"),
      datePattern: "YYYY-MM-DD",
      level: "error",
      maxFiles: "30d",
    })
  );
}

export const logger = createLogger({
  level: process.env.LOG_LEVEL ?? (isDev ? "debug" : "info"),
  silent: isTest && process.env.LOG_LEVEL === undefined,
  format: combine(timestamp(), errors({ stack: true }), json()),
  transports: [
    // Console — colourised in dev, plain JSON elsewhere (what Render/Vercel log viewers expect)
    new transports.Console({
      format: isDev ? combine(colorize(), simple()) : json(),
    }),
    ...fileTransports,
  ],
});
