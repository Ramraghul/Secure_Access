import {
  validate, RegisterSchema, LoginSchema, LoginMfaSchema, CreateRoleSchema, AuditListQuerySchema,
  AuthorizeRequestSchema, IdParamSchema, isValidRedirectUri,
} from "../../src/utils/validation";
import { AppError } from "../../src/utils/errors";

describe("validate", () => {
  it("returns parsed data and applies transforms", () => {
    const body = validate(RegisterSchema, {
      email: "  Jane@Example.COM ", password: "Str0ng!Passphrase", firstName: " Jane ", lastName: "Doe",
    });
    expect(body.email).toBe("jane@example.com");
    expect(body.firstName).toBe("Jane");
  });

  it("throws a 400 AppError with field details", () => {
    try {
      validate(RegisterSchema, { email: "not-an-email", password: "short" });
      fail("expected validation to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AppError);
      const appError = err as AppError;
      expect(appError.statusCode).toBe(400);
      expect(appError.code).toBe("VALIDATION_ERROR");
      expect(appError.details).toHaveProperty("email");
      expect(appError.details).toHaveProperty("password");
      expect(appError.details).toHaveProperty("firstName");
    }
  });

  it("reports object-level refinements under _errors", () => {
    try {
      validate(IdParamSchema.refine(() => false, "always fails"), { id: "3b241101-e2bb-4255-8caf-4136c566a962" });
      fail("expected validation to throw");
    } catch (err) {
      expect((err as AppError).details).toEqual({ _errors: ["always fails"] });
    }
  });
});

describe("schemas", () => {
  it("defaults rememberDevice to false on login", () => {
    expect(validate(LoginSchema, { email: "a@b.co", password: "x" }).rememberDevice).toBe(false);
  });

  it("requires a code or backup code to finish MFA login", () => {
    expect(() => validate(LoginMfaSchema, { mfaToken: "t" })).toThrow(AppError);
    expect(validate(LoginMfaSchema, { mfaToken: "t", code: "123456" }).code).toBe("123456");
    expect(validate(LoginMfaSchema, { mfaToken: "t", backupCode: "A1B2C3D4E5" }).backupCode).toBe("A1B2C3D4E5");
  });

  it("validates role names and permission resources", () => {
    expect(() => validate(CreateRoleSchema, { name: "Support Team" })).toThrow(AppError);
    expect(() => validate(CreateRoleSchema, { name: "support", permissions: [{ action: "read", resource: "Users!" }] })).toThrow(AppError);
    expect(() => validate(CreateRoleSchema, { name: "support", permissions: [{ action: "fly", resource: "user" }] })).toThrow(AppError);
    expect(validate(CreateRoleSchema, { name: "support", permissions: [{ action: "manage", resource: "*" }] }).permissions).toHaveLength(1);
  });

  it("coerces audit query parameters", () => {
    const q = validate(AuditListQuerySchema, { page: "2", limit: "10", action: "post", statusCode: "401", startDate: "2026-01-01" });
    expect(q).toMatchObject({ page: 2, limit: 10, action: "POST", statusCode: 401 });
    expect(q.startDate).toBeInstanceOf(Date);
    expect(() => validate(AuditListQuerySchema, { startDate: "not-a-date" })).toThrow(AppError);
    expect(() => validate(AuditListQuerySchema, { limit: "5000" })).toThrow(AppError);
  });

  it("checks PKCE challenge format on authorization requests", () => {
    const base = { response_type: "code", client_id: "c", redirect_uri: "/cb" };
    expect(AuthorizeRequestSchema.safeParse({ ...base, code_challenge: "too-short" }).success).toBe(false);
    expect(AuthorizeRequestSchema.safeParse({ ...base, code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" }).success).toBe(true);
    expect(AuthorizeRequestSchema.parse(base).scope).toBe("openid");
  });
});

describe("isValidRedirectUri", () => {
  it.each([
    ["https://app.example.com/callback", true],
    ["http://localhost:3000/cb", true],
    ["/oauth/callback.html", true],
    ["//evil.example.com/cb", false],
    ["javascript:alert(1)", false],
    ["https://app.example.com/cb#fragment", false],
    ["not a url", false],
  ])("%s → %s", (uri, expected) => {
    expect(isValidRedirectUri(uri)).toBe(expected);
  });
});
