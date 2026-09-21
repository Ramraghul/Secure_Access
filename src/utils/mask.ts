// src/utils/mask.ts — Deep masking of secrets before anything is written to the audit log

// Keys are compared lower-cased, so list them lower-case here.
const SENSITIVE_KEYS = new Set([
  "password", "confirmpassword", "currentpassword", "newpassword", "passwordhash",
  "temporarypassword",
  "token", "accesstoken", "access_token", "refreshtoken", "refresh_token",
  "idtoken", "id_token", "mfatoken", "authorization",
  "secret", "mfasecret", "client_secret", "clientsecret", "apikey",
  "totp_code", "otp", "code", "code_verifier", "backupcode", "backupcodes",
  "qrcode", "otpauthurl", "redirectto",
  "cvv", "cardnumber", "pin",
]);

export const MASK = "••••••";

export function maskSensitive(value: unknown, seen = new WeakSet<object>()): unknown {
  if (value === null || typeof value !== "object") return value;
  if (seen.has(value)) return "[Circular]";
  seen.add(value);
  if (Array.isArray(value)) return value.map(i => maskSensitive(i, seen));
  const masked: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    masked[k] = SENSITIVE_KEYS.has(k.toLowerCase()) ? MASK : maskSensitive(v, seen);
  }
  return masked;
}

// Serialises a (masked) response body for the audit log, capped at 500 chars
export function responseSnippet(data: unknown): string | null {
  if (data == null) return null;
  let str: string;
  if (Buffer.isBuffer(data)) {
    str = data.toString("utf8");
  } else if (typeof data === "object") {
    try { str = JSON.stringify(maskSensitive(data)); } catch { return "[Unserializable]"; }
  } else {
    str = String(data);
  }
  return str.length > 500 ? str.slice(0, 500) + "…" : str;
}
