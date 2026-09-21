import {
  isStrongPassword, generateSecurePassword, hashPassword, verifyPassword,
} from "../../src/utils/password";

describe("isStrongPassword", () => {
  it("accepts a password that meets every rule", () => {
    expect(isStrongPassword("Str0ng!Passphrase")).toEqual({ valid: true, errors: [] });
  });

  it("allows up to three repeated characters in a row", () => {
    expect(isStrongPassword("Aaaa!bcdef12345").valid).toBe(true);
  });

  it.each([
    ["too short",          "Sh0rt!pw",           "Minimum 12 characters"],
    ["no uppercase",       "lowercase!only123",  "At least one uppercase letter"],
    ["no lowercase",       "UPPERCASE!ONLY123",  "At least one lowercase letter"],
    ["no digit",           "NoDigits!Anywhere",  "At least one number"],
    ["no symbol",          "NoSymbols1234Here",  "At least one special character"],
    ["4 repeated chars",   "Aaaaa!bcdef12345",   "No more than 3 repeated characters in a row"],
    ["common weak word",   "MyPassword!2026xx",  "Contains common weak patterns: password"],
    ["two weak words",     "Admin!Qwerty2026x",  "Contains common weak patterns: qwerty, admin"],
  ])("rejects a password with %s", (_label, password, expectedError) => {
    const result = isStrongPassword(password);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain(expectedError);
  });

  it("rejects passwords longer than 128 characters", () => {
    expect(isStrongPassword(`Aa1!${"x".repeat(125)}`).errors).toContain("Maximum 128 characters");
  });
});

describe("generateSecurePassword", () => {
  it("always produces a strong password of the requested length", () => {
    const generated = new Set<string>();
    for (let i = 0; i < 50; i++) {
      const password = generateSecurePassword(16);
      expect(password).toHaveLength(16);
      expect(isStrongPassword(password).valid).toBe(true);
      generated.add(password);
    }
    expect(generated.size).toBe(50);
  });
});

describe("hashPassword / verifyPassword", () => {
  it("verifies the original password and rejects others", async () => {
    const hash = await hashPassword("Str0ng!Passphrase");
    expect(hash).not.toContain("Str0ng");
    await expect(verifyPassword("Str0ng!Passphrase", hash)).resolves.toBe(true);
    await expect(verifyPassword("Wr0ng!Passphrase", hash)).resolves.toBe(false);
  });
});
