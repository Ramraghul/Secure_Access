import jwt from "jsonwebtoken";
import { config } from "../../src/config";
import { signAccessToken, signMfaToken, verifyToken, secondsUntilExpiry } from "../../src/utils/jwt";

const USER_ID    = "5b0c8a3e-1f2d-4c5b-8a9e-0d1c2b3a4f5e";
const SESSION_ID = "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b";

describe("first-party JWTs", () => {
  it("round-trips an access token", () => {
    const token   = signAccessToken(USER_ID, "jane@example.com", SESSION_ID);
    const payload = verifyToken(token, "access");
    expect(payload).toMatchObject({ sub: USER_ID, email: "jane@example.com", sid: SESSION_ID, type: "access" });
    expect(jwt.decode(token, { complete: true })?.header.alg).toBe("HS512");
  });

  it("expires access tokens after the configured TTL (15m by default)", () => {
    const token = signAccessToken(USER_ID, "jane@example.com", SESSION_ID);
    expect(secondsUntilExpiry(token)).toBeGreaterThan(890);
    expect(secondsUntilExpiry(token)).toBeLessThanOrEqual(900);
  });

  it("never accepts an MFA token as an access token, or the reverse", () => {
    const mfa    = signMfaToken(USER_ID, "fingerprint");
    const access = signAccessToken(USER_ID, "jane@example.com", SESSION_ID);
    expect(() => verifyToken(mfa, "access")).toThrow("WRONG_TOKEN_TYPE");
    expect(() => verifyToken(access, "mfa")).toThrow("WRONG_TOKEN_TYPE");
    expect(verifyToken(mfa, "mfa").fp).toBe("fingerprint");
  });

  it("rejects tampered tokens", () => {
    const token = signAccessToken(USER_ID, "jane@example.com", SESSION_ID);
    const [header, , signature] = token.split(".");
    const forgedPayload = Buffer.from(JSON.stringify({ sub: "attacker", sid: SESSION_ID, type: "access", iss: "secureaccess" })).toString("base64url");
    expect(() => verifyToken(`${header}.${forgedPayload}.${signature}`, "access")).toThrow();
  });

  it("rejects tokens signed with another secret, algorithm or issuer", () => {
    const claims = { sub: USER_ID, sid: SESSION_ID, type: "access" };
    const otherSecret = jwt.sign(claims, "another-secret-that-is-at-least-32-characters", { algorithm: "HS512", issuer: "secureaccess" });
    const weakerAlg   = jwt.sign(claims, config.jwt.secret, { algorithm: "HS256", issuer: "secureaccess" });
    const otherIssuer = jwt.sign(claims, config.jwt.secret, { algorithm: "HS512", issuer: "someone-else" });
    const unsigned    = jwt.sign(claims, "", { algorithm: "none" as jwt.Algorithm });

    for (const token of [otherSecret, weakerAlg, otherIssuer, unsigned]) {
      expect(() => verifyToken(token, "access")).toThrow();
    }
  });

  it("rejects expired tokens", () => {
    const expired = jwt.sign(
      { sub: USER_ID, sid: SESSION_ID, type: "access", exp: Math.floor(Date.now() / 1000) - 10 },
      config.jwt.secret,
      { algorithm: "HS512", issuer: "secureaccess" },
    );
    expect(() => verifyToken(expired, "access")).toThrow(/expired/);
  });
});
