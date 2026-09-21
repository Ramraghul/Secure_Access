import { maskSensitive, responseSnippet, MASK } from "../../src/utils/mask";

describe("maskSensitive", () => {
  it("masks secrets at any depth, case-insensitively", () => {
    const input = {
      email: "jane@example.com",
      Password: "hunter2",
      nested: { ACCESS_TOKEN: "abc", refreshToken: "def", keep: 1 },
      list: [{ backupCodes: ["A", "B"] }, { totp_code: "123456" }],
    };

    expect(maskSensitive(input)).toEqual({
      email: "jane@example.com",
      Password: MASK,
      nested: { ACCESS_TOKEN: MASK, refreshToken: MASK, keep: 1 },
      list: [{ backupCodes: MASK }, { totp_code: MASK }],
    });
  });

  it("masks OAuth artefacts such as codes and redirect URLs carrying them", () => {
    expect(maskSensitive({ code: "xyz", code_verifier: "v", redirectTo: "https://app/cb?code=xyz", client_secret: "s" }))
      .toEqual({ code: MASK, code_verifier: MASK, redirectTo: MASK, client_secret: MASK });
  });

  it("does not modify the original object", () => {
    const input = { password: "secret" };
    maskSensitive(input);
    expect(input.password).toBe("secret");
  });

  it("handles primitives, null and circular references", () => {
    expect(maskSensitive("text")).toBe("text");
    expect(maskSensitive(null)).toBeNull();
    const circular: Record<string, unknown> = { name: "loop" };
    circular.self = circular;
    expect(maskSensitive(circular)).toEqual({ name: "loop", self: "[Circular]" });
  });
});

describe("responseSnippet", () => {
  it("masks secrets in response bodies", () => {
    const snippet = responseSnippet({ accessToken: "eyJ.secret", user: { email: "a@b.c" } });
    expect(snippet).not.toContain("eyJ.secret");
    expect(snippet).toContain(MASK);
    expect(snippet).toContain("a@b.c");
  });

  it("truncates long bodies to 500 characters", () => {
    const snippet = responseSnippet({ data: "x".repeat(2000) })!;
    expect(snippet).toHaveLength(501);
    expect(snippet.endsWith("…")).toBe(true);
  });

  it("returns null for empty bodies", () => {
    expect(responseSnippet(undefined)).toBeNull();
    expect(responseSnippet(null)).toBeNull();
  });
});
