// src/utils/validation.ts — Zod schemas for every request body
// Centralised here so controllers stay clean
import { z } from "zod";

export const RegisterSchema = z.object({
  email:     z.string().email("Invalid email format").toLowerCase().trim(),
  password:  z.string().min(12, "Password must be at least 12 characters"),
  firstName: z.string().min(1).max(100).trim(),
  lastName:  z.string().min(1).max(100).trim(),
});

export const LoginSchema = z.object({
  email:    z.string().email().toLowerCase().trim(),
  password: z.string().min(1, "Password required"),
  totp_code: z.string().optional(),
});

export const MfaVerifySchema = z.object({
  token: z.string().length(6, "TOTP code must be 6 digits").regex(/^\d+$/, "TOTP must be numeric"),
});

export const CreateRoleSchema = z.object({
  name:        z.string().min(1).max(50).trim(),
  description: z.string().max(255).optional(),
  permissions: z.array(z.object({
    action:   z.enum(["create", "read", "update", "delete", "manage", "export"]),
    resource: z.string().min(1).max(100),
  })).optional(),
});

export const AssignRoleSchema = z.object({
  userId: z.string().uuid("Invalid user ID"),
});

export const PaginationSchema = z.object({
  page:  z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  search: z.string().trim().optional(),
});

// Helper: validate and throw 400 if invalid
export function validate<T>(schema: z.ZodSchema<T>, data: unknown): T {
  const result = schema.safeParse(data);
  if (!result.success) {
    const err = new Error("Validation failed") as any;
    err.statusCode = 400;
    err.code = "VALIDATION_ERROR";
    err.details = result.error.flatten().fieldErrors;
    throw err;
  }
  return result.data;
}
