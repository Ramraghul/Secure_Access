// src/config/index.ts — All environment config in one place
// Never scatter process.env across the codebase

function required(key: string): string {
  const val = process.env[key];
  if (!val) throw new Error(`Missing required env var: ${key}`);
  return val;
}

function optional(key: string, fallback: string): string {
  return process.env[key] ?? fallback;
}

export const config = {
  port:    parseInt(optional("PORT", "4000"), 10),
  nodeEnv: optional("NODE_ENV", "development"),

  db: {
    url: required("DATABASE_URL"),
  },

  jwt: {
    secret:    required("JWT_SECRET"),
    expiresIn: optional("JWT_EXPIRES_IN", "7d"),
  },

  rateLimit: {
    windowMs: parseInt(optional("RATE_LIMIT_WINDOW_MS", "900000"), 10),
    max:      parseInt(optional("RATE_LIMIT_MAX", "100"), 10),
  },

  cors: {
    origins: optional("ALLOWED_ORIGINS", "*"),
  },
} as const;

// Validate JWT secret length at startup
if (config.jwt.secret.length < 32) {
  console.error("FATAL: JWT_SECRET must be at least 32 characters");
  process.exit(1);
}
