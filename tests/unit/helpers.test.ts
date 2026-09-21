// Pure helpers exported from modules that also touch the database (no queries are made here)
import { csvCell, isPrivateIp } from "../../src/controllers/audit.controller";
import { buildRedirect, resolveRedirectUri } from "../../src/openid/clients";
import { userClaims } from "../../src/openid/tokens";

describe("csvCell", () => {
  it("quotes values and escapes embedded quotes", () => {
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell(null)).toBe('""');
    expect(csvCell(401)).toBe('"401"');
  });

  it.each(["=SUM(A1)", "+cmd", "-2+3", "@import"])("neutralises formula injection in %p", value => {
    expect(csvCell(value)).toBe(`"'${value}"`);
  });
});

describe("isPrivateIp", () => {
  it.each([
    ["127.0.0.1", true], ["::1", true], ["::ffff:127.0.0.1", true], ["10.1.2.3", true],
    ["192.168.0.10", true], ["172.16.5.4", true], ["172.31.255.1", true],
    ["172.32.0.1", false], ["8.8.8.8", false], ["203.0.113.9", false],
  ])("%s → %s", (ip, expected) => {
    expect(isPrivateIp(ip)).toBe(expected);
  });
});

describe("OIDC helpers", () => {
  it("resolves relative redirect URIs against the issuer", () => {
    expect(resolveRedirectUri("/oauth/callback.html", "https://sa.example.com")).toBe("https://sa.example.com/oauth/callback.html");
    expect(resolveRedirectUri("https://app.example.com/cb", "https://sa.example.com")).toBe("https://app.example.com/cb");
  });

  it("builds redirect URLs, preserving existing query and skipping undefined values", () => {
    const url = new URL(buildRedirect("https://app.example.com/cb?x=1", { code: "abc", state: undefined, iss: "https://sa" }));
    expect(url.searchParams.get("x")).toBe("1");
    expect(url.searchParams.get("code")).toBe("abc");
    expect(url.searchParams.has("state")).toBe(false);
  });

  it("releases claims only for granted scopes", () => {
    const user = { id: "u1", email: "jane@example.com", firstName: "Jane", lastName: "Doe" };
    expect(userClaims(user, new Set(["openid"]))).toEqual({});
    expect(userClaims(user, new Set(["openid", "email"]))).toEqual({ email: "jane@example.com", email_verified: false });
    expect(userClaims(user, new Set(["profile"]))).toEqual({ name: "Jane Doe", given_name: "Jane", family_name: "Doe" });
  });
});
