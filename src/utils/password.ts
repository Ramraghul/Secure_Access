// src/utils/password.ts
import bcrypt from "bcryptjs";
import { randomBytes, getRandomValues } from "crypto";

const SALT_ROUNDS = 12; // Banking standard

export const hashPassword = (plain: string): Promise<string> =>
  bcrypt.hash(plain, SALT_ROUNDS);

export const verifyPassword = (plain: string, hash: string): Promise<boolean> =>
  bcrypt.compare(plain, hash);

export function isStrongPassword(password: string): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (password.length < 12)          errors.push("Minimum 12 characters");
  if (!/[A-Z]/.test(password))       errors.push("At least one uppercase letter");
  if (!/[a-z]/.test(password))       errors.push("At least one lowercase letter");
  if (!/[0-9]/.test(password))       errors.push("At least one number");
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?]/.test(password))
    errors.push("At least one special character");
  if (/(.)\\1{3,}/.test(password))   errors.push("No more than 3 repeated characters");

  const WEAK = ["password", "123456", "qwerty", "admin", "letmein"];
  if (WEAK.some(w => password.toLowerCase().includes(w)))
    errors.push("Contains common weak patterns");

  return { valid: errors.length === 0, errors };
}

// Uses crypto.randomBytes — cryptographically secure (unlike Math.random)
export function generateSecurePassword(length = 16): string {
  const charset =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*_-+=";
  const bytes = randomBytes(length + 4); // extra bytes to ensure all char classes
  let result = "";
  for (let i = 0; i < length; i++) {
    result += charset[bytes[i] % charset.length];
  }
  // Guarantee one of each required class
  const required = [
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "!@#$%^&*_-+=",
  ];
  const positions = Array.from({ length: 4 }, (_, i) => i);
  required.forEach((set, i) => {
    const pos = positions[i];
    result = result.substring(0, pos) + set[randomBytes(1)[0] % set.length] + result.substring(pos + 1);
  });
  return result;
}
