// src/lib/logger.ts — Winston structured logger (replaces all console.log)
import { createLogger, format, transports } from "winston";
import "winston-daily-rotate-file";
import fs from "fs";
import path from "path";

const { combine, timestamp, errors, json, colorize, simple } = format;

const isDev = process.env.NODE_ENV !== "production";

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

if (isWritable(LOG_DIR)) {
  fileTransports.push(
    new (transports as any).DailyRotateFile({
      filename: path.join(LOG_DIR, "secureaccess-%DATE%.log"),
      datePattern: "YYYY-MM-DD",
      maxFiles: "30d",
      maxSize: "20m",
      zippedArchive: true,
    }),
    new (transports as any).DailyRotateFile({
      filename: path.join(LOG_DIR, "errors-%DATE%.log"),
      datePattern: "YYYY-MM-DD",
      level: "error",
      maxFiles: "90d",
    })
  );
} else {
  // eslint-disable-next-line no-console
  console.warn(
    `[logger] Log directory '${LOG_DIR}' is not writable. File logging disabled. ` +
      `Set LOG_DIR env var to a writable path (e.g., '/tmp/logs') to enable file logs.`
  );
}

export const logger = createLogger({
  level: isDev ? "debug" : "info",
  format: combine(timestamp(), errors({ stack: true }), json()),
  transports: [
    // Console — colourised in dev, plain JSON in prod
    new transports.Console({
      format: isDev ? combine(colorize(), simple()) : json(),
    }),
    ...fileTransports,
  ],
});
