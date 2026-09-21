// src/utils/password.ts
import bcrypt from "bcryptjs";
import { randomInt } from "crypto";
import { config } from "../config";

export const hashPassword = (plain: string): Promise<string> =>
  bcrypt.hash(plain, config.security.bcryptRounds);

export const verifyPassword = (plain: string, hash: string): Promise<boolean> =>
  bcrypt.compare(plain, hash);

// Compared against when the email does not exist, so a login for an unknown
// account takes as long as one for a real account (no user enumeration by timing).
const DUMMY_HASH = bcrypt.hashSync("dummy-password-for-timing", config.security.bcryptRounds);
export const burnPasswordCheck = (plain: string): Promise<boolean> => bcrypt.compare(plain, DUMMY_HASH);

const WEAK_PATTERNS = ["password", "123456", "qwerty", "admin", "letmein"];

export function isStrongPassword(password: string): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (password.length < 12)          errors.push("Minimum 12 characters");
  if (password.length > 128)         errors.push("Maximum 128 characters");
  if (!/[A-Z]/.test(password))       errors.push("At least one uppercase letter");
  if (!/[a-z]/.test(password))       errors.push("At least one lowercase letter");
  if (!/[0-9]/.test(password))       errors.push("At least one number");
  if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?~`]/.test(password))
    errors.push("At least one special character");
  if (/(.)\1{3,}/.test(password))    errors.push("No more than 3 repeated characters in a row");
  if (WEAK_PATTERNS.some(w => password.toLowerCase().includes(w)))
    errors.push("Contains common weak patterns");

  return { valid: errors.length === 0, errors };
}

const UPPER   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER   = "abcdefghijklmnopqrstuvwxyz";
const DIGITS  = "0123456789";
const SYMBOLS = "!@#$%^&*_-+=";
const ALL     = UPPER + LOWER + DIGITS + SYMBOLS;

// crypto.randomInt is unbiased and cryptographically secure (unlike Math.random or byte % n)
export function generateSecurePassword(length = 16): string {
  for (;;) {
    const chars = [UPPER, LOWER, DIGITS, SYMBOLS].map(set => set[randomInt(set.length)]);
    while (chars.length < length) chars.push(ALL[randomInt(ALL.length)]);
    // Fisher–Yates shuffle so the guaranteed classes are not at fixed positions
    for (let i = chars.length - 1; i > 0; i--) {
      const j = randomInt(i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    const candidate = chars.join("");
    if (isStrongPassword(candidate).valid) return candidate;
  }
}
