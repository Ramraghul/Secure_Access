import speakeasy from "speakeasy";
import {
  generateMFASecret, verifyTOTP, currentTotpStep, hashBackupCodes,
  verifyAndConsumeBackupCode, normalizeBackupCode, parseBackupCodes,
} from "../../src/utils/mfa";

const codeAt = (secret: string, secondsOffset = 0) =>
  speakeasy.totp({ secret, encoding: "base32", time: Math.floor(Date.now() / 1000) + secondsOffset });

describe("generateMFASecret", () => {
  it("returns a base32 secret, QR code, otpauth URL and 10 unique backup codes", async () => {
    const result = await generateMFASecret("jane@example.com");

    expect(result.secret).toMatch(/^[A-Z2-7]+=*$/);
    expect(result.qrCode).toMatch(/^data:image\/png;base64,/);
    expect(result.otpauthUrl).toContain("issuer=SecureAccess");
    expect(result.backupCodes).toHaveLength(10);
    expect(new Set(result.backupCodes).size).toBe(10);
    result.backupCodes.forEach(code => expect(code).toMatch(/^[0-9A-F]{10}$/));
  });
});

describe("verifyTOTP", () => {
  const { base32: secret } = speakeasy.generateSecret({ length: 20 });

  it("accepts the current code and returns its time-step", () => {
    const step = verifyTOTP(secret, codeAt(secret));
    expect(step).not.toBeNull();
    expect(Math.abs(step! - currentTotpStep())).toBeLessThanOrEqual(1);
  });

  it("rejects wrong and malformed codes", () => {
    const valid = codeAt(secret);
    const wrong = String((Number(valid) + 1) % 1_000_000).padStart(6, "0");
    expect(verifyTOTP(secret, wrong)).toBeNull();
    expect(verifyTOTP(secret, "12ab56")).toBeNull();
    expect(verifyTOTP(secret, "12345")).toBeNull();
  });

  it("tolerates one step of clock drift but not more", () => {
    expect(verifyTOTP(secret, codeAt(secret, -30))).not.toBeNull();
    expect(verifyTOTP(secret, codeAt(secret, -120))).toBeNull();
  });

  it("rejects a replayed code (step not newer than the last accepted one)", () => {
    const code = codeAt(secret);
    const step = verifyTOTP(secret, code);
    expect(step).not.toBeNull();
    expect(verifyTOTP(secret, code, step)).toBeNull();
  });
});

describe("backup codes", () => {
  it("normalises separators and case", () => {
    expect(normalizeBackupCode(" a1b2-c3d4 e5 ")).toBe("A1B2C3D4E5");
  });

  it("consumes a code exactly once", async () => {
    const codes  = ["A1B2C3D4E5", "F6A7B8C9D0", "0123456789"];
    const hashes = await hashBackupCodes(codes);
    hashes.forEach((h, i) => expect(h).not.toContain(codes[i]));

    const first = await verifyAndConsumeBackupCode("f6a7-b8c9-d0", hashes);
    expect(first.valid).toBe(true);
    expect(first.remaining).toHaveLength(2);

    const replay = await verifyAndConsumeBackupCode("F6A7B8C9D0", first.remaining);
    expect(replay.valid).toBe(false);
    expect(replay.remaining).toHaveLength(2);
  });

  it("parses stored codes defensively", () => {
    expect(parseBackupCodes(null)).toEqual([]);
    expect(parseBackupCodes("not json")).toEqual([]);
    expect(parseBackupCodes('{"a":1}')).toEqual([]);
    expect(parseBackupCodes('["x", 1, "y"]')).toEqual(["x", "y"]);
  });
});
