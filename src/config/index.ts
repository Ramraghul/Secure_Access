// src/config/index.ts — All environment config in one place
// Never scatter process.env across the codebase
import dotenv from "dotenv";

// Tests read .env.test; everything else reads .env. Variables already present
// in the environment (CI, Render, Vercel) always win over file values.
dotenv.config({ path: process.env.NODE_ENV === "test" ? ".env.test" : ".env" });

function required(key: string): string {
  const val = process.env[key];
  if (!val) throw new Error(`Missing required env var: ${key}`);
  return val;
}

function optional(key: string, fallback: string): string {
  const val = process.env[key];
  return val === undefined || val === "" ? fallback : val;
}

function int(key: string, fallback: number): number {
  const parsed = parseInt(optional(key, String(fallback)), 10);
  return Number.isNaN(parsed) ? fallback : parsed;
}

function bool(key: string, fallback: boolean): boolean {
  const val = optional(key, String(fallback)).toLowerCase();
  return val === "true" || val === "1" || val === "yes";
}

const nodeEnv = optional("NODE_ENV", "development");

export const config = {
  port:    int("PORT", 4000),
  nodeEnv,
  isProd:  nodeEnv === "production",
  isTest:  nodeEnv === "test",
  // Public base URL (no trailing slash). Used as the OIDC issuer.
  // When empty, it is derived from each request's protocol + host.
  publicUrl: optional("PUBLIC_URL", "").replace(/\/+$/, ""),
  trustProxy: int("TRUST_PROXY", 1),

  db: {
    url: required("DATABASE_URL"),
  },

  jwt: {
    secret:          required("JWT_SECRET"),
    accessTokenTtl:  optional("JWT_EXPIRES_IN", "15m"),
    refreshTokenTtlDays: int("REFRESH_TOKEN_TTL_DAYS", 7),
    mfaTokenTtl:     "5m",
  },

  security: {
    bcryptRounds:     int("BCRYPT_ROUNDS", 12),
    maxFailedLogins:  int("MAX_FAILED_LOGINS", 5),
    lockoutMinutes:   int("LOCKOUT_MINUTES", 15),
    // How long "remember this device" lets a device skip the MFA code
    trustedDeviceDays: int("TRUSTED_DEVICE_DAYS", 30),
  },

  rateLimit: {
    enabled:  bool("RATE_LIMIT_ENABLED", nodeEnv !== "test"),
    windowMs: int("RATE_LIMIT_WINDOW_MS", 15 * 60 * 1000),
    max:      int("RATE_LIMIT_MAX", 300),
    authMax:  int("RATE_LIMIT_AUTH_MAX", 20),
  },

  cors: {
    // Comma-separated list, or "*" to allow any origin
    origins: optional("ALLOWED_ORIGINS", "*").split(",").map(o => o.trim()).filter(Boolean),
  },

  audit: {
    logReads:      bool("AUDIT_LOG_READS", true),
    retentionDays: int("AUDIT_RETENTION_DAYS", 90),
  },

  oidc: {
    // PEM (or base64-encoded PEM) RSA private key. Generated per process when absent.
    privateKey:      optional("OIDC_PRIVATE_KEY", ""),
    codeTtlSeconds:  120,
    accessTokenTtl:  "15m",
  },
} as const;

if (config.jwt.secret.length < 32) {
  throw new Error("JWT_SECRET must be at least 32 characters");
}
