// src/utils/validation.ts — Zod schemas for every request body, query and path param
// Centralised here so controllers stay clean
import { z } from "zod";
import { badRequest } from "./errors";
import { PERMISSION_ACTIONS } from "./permissions";

// ── Shared field schemas ─────────────────────────────────────────
const email      = z.string().trim().toLowerCase().max(254).email("Invalid email format");
const personName = z.string().trim().min(1).max(100);
const password   = z.string().min(1, "Password required").max(128);
const totpCode   = z.string().trim().regex(/^\d{6}$/, "Code must be 6 digits");
const backupCode = z.string().trim().min(8).max(20);
const page       = z.coerce.number().int().min(1).default(1);
const optionalDate = z.coerce.date().optional();

const hasSecondFactor = (d: { code?: string; backupCode?: string }) => Boolean(d.code || d.backupCode);
const secondFactorMessage = { message: "Provide either code or backupCode", path: ["code"] };

// ── Auth ─────────────────────────────────────────────────────────
export const RegisterSchema = z.object({
  email,
  password:  z.string().min(12, "Password must be at least 12 characters").max(128),
  firstName: personName,
  lastName:  personName,
});

export const LoginSchema = z.object({
  email,
  password,
  // Optional single-step MFA (instead of the two-step /auth/login/mfa flow)
  totp_code:      totpCode.optional(),
  backupCode:     backupCode.optional(),
  rememberDevice: z.boolean().default(false),
});

export const LoginMfaSchema = z.object({
  mfaToken:       z.string().min(1).max(2000),
  code:           totpCode.optional(),
  backupCode:     backupCode.optional(),
  rememberDevice: z.boolean().default(false),
}).refine(hasSecondFactor, secondFactorMessage);

export const RefreshSchema = z.object({
  refreshToken: z.string().min(10).max(500),
});

export const ChangePasswordSchema = z.object({
  currentPassword: password,
  newPassword:     z.string().min(12, "Password must be at least 12 characters").max(128),
});

export const UpdateProfileSchema = z.object({
  firstName: personName.optional(),
  lastName:  personName.optional(),
}).refine(d => d.firstName !== undefined || d.lastName !== undefined, { message: "Nothing to update" });

export const MfaVerifySchema = z.object({
  token: totpCode,
});

export const MfaDisableSchema = z.object({
  password,
  code:       totpCode.optional(),
  backupCode: backupCode.optional(),
}).refine(hasSecondFactor, secondFactorMessage);

// Trusting a device skips MFA there, so it takes a fresh second factor
export const TrustDeviceSchema = z.object({
  code:       totpCode.optional(),
  backupCode: backupCode.optional(),
}).refine(hasSecondFactor, secondFactorMessage);

// ── Params ───────────────────────────────────────────────────────
export const IdParamSchema = z.object({
  id: z.string().uuid("Invalid ID"),
});

// ── Users ────────────────────────────────────────────────────────
export const UserListQuerySchema = z.object({
  page,
  limit:  z.coerce.number().int().min(1).max(100).default(20),
  search: z.string().trim().max(100).optional(),
  status: z.enum(["active", "inactive"]).optional(),
});

// ── Roles ────────────────────────────────────────────────────────
const PermissionSchema = z.object({
  action:   z.enum(PERMISSION_ACTIONS),
  resource: z.string().trim().regex(/^(\*|[a-z][a-z0-9-]{0,49})$/, "Resource must be '*' or lowercase letters, digits and dashes"),
});

export const CreateRoleSchema = z.object({
  name:        z.string().trim().min(2).max(50).regex(/^[a-z0-9][a-z0-9_-]*$/, "Role name must be lowercase letters, digits, '_' or '-'"),
  description: z.string().trim().max(255).optional(),
  permissions: z.array(PermissionSchema).max(100).optional(),
});

export const UpdateRoleSchema = CreateRoleSchema.partial();

export const AssignRoleSchema = z.object({
  userId: z.string().uuid("Invalid user ID"),
});

// ── Audit ────────────────────────────────────────────────────────
const httpMethod = z.string().trim().toUpperCase().pipe(z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]));

export const AuditListQuerySchema = z.object({
  page,
  limit:      z.coerce.number().int().min(1).max(500).default(50),
  userId:     z.string().uuid().optional(),
  event:      z.string().trim().max(100).optional(),
  action:     httpMethod.optional(),
  resource:   z.string().trim().max(500).optional(),
  ipAddress:  z.string().trim().max(100).optional(),
  statusCode: z.coerce.number().int().min(100).max(599).optional(),
  startDate:  optionalDate,
  endDate:    optionalDate,
});

export const AuditSearchQuerySchema = z.object({
  userId:    z.string().uuid().optional(),
  email:     z.string().trim().max(254).optional(),
  event:     z.string().trim().max(100).optional(),
  action:    httpMethod.optional(),
  resource:  z.string().trim().max(500).optional(),
  ip:        z.string().trim().max(100).optional(),
  status:    z.coerce.number().int().min(100).max(599).optional(),
  before:    optionalDate,
  after:     optionalDate,
  sensitive: z.enum(["true", "false"]).optional(),
  limit:     z.coerce.number().int().min(1).max(1000).default(200),
});

export const AuditPurgeSchema = z.object({
  olderThanDays: z.number().int().min(1).max(3650),
});

// ── OpenID Connect ───────────────────────────────────────────────
// Absolute http(s) URL without fragment, or a same-origin path like "/oauth/callback.html"
export function isValidRedirectUri(uri: string): boolean {
  if (uri.startsWith("/")) return !uri.startsWith("//");
  try {
    const url = new URL(uri);
    return (url.protocol === "https:" || url.protocol === "http:") && !url.hash;
  } catch {
    return false;
  }
}

export const CreateClientSchema = z.object({
  name:           z.string().trim().min(2).max(100),
  redirectUris:   z.array(z.string().trim().max(2000).refine(isValidRedirectUri, "Invalid redirect URI")).min(1).max(10),
  isConfidential: z.boolean().default(false),
});

export const AuthorizeRequestSchema = z.object({
  response_type:         z.string().max(50),
  client_id:             z.string().min(1).max(100),
  redirect_uri:          z.string().min(1).max(2000),
  scope:                 z.string().trim().max(500).default("openid"),
  state:                 z.string().max(500).optional(),
  nonce:                 z.string().max(500).optional(),
  code_challenge:        z.string().regex(/^[A-Za-z0-9\-._~]{43,128}$/, "Invalid code_challenge").optional(),
  code_challenge_method: z.string().max(10).optional(),
});

export const ConsentSchema = AuthorizeRequestSchema.extend({
  decision: z.enum(["allow", "deny"]),
});

// Helper: validate and throw 400 VALIDATION_ERROR if invalid
export function validate<T>(schema: z.ZodType<T, z.ZodTypeDef, unknown>, data: unknown): T {
  const result = schema.safeParse(data);
  if (!result.success) {
    const flat = result.error.flatten();
    const details = Object.keys(flat.fieldErrors).length > 0
      ? flat.fieldErrors
      : { _errors: flat.formErrors };
    throw badRequest("VALIDATION_ERROR", "Request validation failed", details);
  }
  return result.data;
}
