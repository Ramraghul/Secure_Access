import { grants, toPermissionString } from "../../src/utils/permissions";

describe("grants", () => {
  it("matches an exact action and resource", () => {
    expect(grants([{ action: "read", resource: "user" }], "read", "user")).toBe(true);
  });

  it("does not leak to other actions or resources", () => {
    const held = [{ action: "read", resource: "user" }];
    expect(grants(held, "update", "user")).toBe(false);
    expect(grants(held, "read", "role")).toBe(false);
  });

  it("treats manage as every action on that resource", () => {
    const held = [{ action: "manage", resource: "user" }];
    expect(grants(held, "delete", "user")).toBe(true);
    expect(grants(held, "export", "user")).toBe(true);
    expect(grants(held, "read", "audit")).toBe(false);
  });

  it("treats * as every resource for that action", () => {
    const held = [{ action: "read", resource: "*" }];
    expect(grants(held, "read", "audit")).toBe(true);
    expect(grants(held, "delete", "audit")).toBe(false);
  });

  it("lets manage:* do anything", () => {
    const held = [{ action: "manage", resource: "*" }];
    expect(grants(held, "delete", "client")).toBe(true);
    expect(grants(held, "manage", "user-role")).toBe(true);
  });

  it("denies when no permissions are held", () => {
    expect(grants([], "read", "user")).toBe(false);
  });

  it("formats permission strings", () => {
    expect(toPermissionString({ action: "export", resource: "audit" })).toBe("export:audit");
  });
});
