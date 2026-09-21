import { randomToken, sha256Hex, safeEqual, verifyPkce, splitRefreshToken } from "../../src/utils/crypto";

describe("crypto helpers", () => {
  it("generates unique URL-safe random tokens", () => {
    const tokens = new Set(Array.from({ length: 100 }, () => randomToken(32)));
    expect(tokens.size).toBe(100);
    tokens.forEach(t => expect(t).toMatch(/^[A-Za-z0-9_-]{43}$/));
  });

  it("hashes with SHA-256", () => {
    expect(sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  it("compares strings safely", () => {
    expect(safeEqual("same", "same")).toBe(true);
    expect(safeEqual("same", "diff")).toBe(false);
    expect(safeEqual("short", "longer-value")).toBe(false);
  });
});

describe("verifyPkce (RFC 7636)", () => {
  // Test vector from RFC 7636 Appendix B
  const verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

  it("accepts the matching S256 verifier", () => {
    expect(verifyPkce(verifier, challenge, "S256")).toBe(true);
  });

  it("rejects a wrong verifier", () => {
    expect(verifyPkce(`${verifier}x`, challenge, "S256")).toBe(false);
  });

  it("rejects the insecure plain method", () => {
    expect(verifyPkce(challenge, challenge, "plain")).toBe(false);
  });
});

describe("splitRefreshToken", () => {
  it("splits <sessionId>.<secret>", () => {
    expect(splitRefreshToken("abc.def")).toEqual({ sessionId: "abc", secret: "def" });
  });

  it.each(["", "nodot", ".secret", "session."])("rejects %p", token => {
    expect(splitRefreshToken(token)).toBeNull();
  });
});
