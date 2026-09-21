import SwaggerParser from "@apidevtools/swagger-parser";
import { apiRouters, API_PREFIX } from "../../src/app";
import { openApiSpec } from "../../src/swagger/openapi";
import { localMigrations, pendingMigrations, prismaClientIsStale } from "../../src/lib/migrations";
import { api, closeAll } from "./helpers";

afterAll(closeAll);

describe("system endpoints", () => {
  it("reports health including the database and migration state", async () => {
    const res = await api().get("/health");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: "ok", database: "up", migrations: "up-to-date", version: "3.0.0" });
    expect(res.body.pendingMigrations).toBeUndefined();
  });

  it("finds no pending migrations after migrate reset", async () => {
    expect(localMigrations()).toEqual(expect.arrayContaining(["20260915000000_sessions_oidc_lockout"]));
    await expect(pendingMigrations()).resolves.toEqual([]);
  });

  it("detects that the generated Prisma Client matches schema.prisma", () => {
    expect(prismaClientIsStale()).toBe(false);
  });

  it("describes the API", async () => {
    const res = await api().get("/api/v1");
    expect(res.body).toMatchObject({ project: "SecureAccess", docs: "/api-docs", openapi: "/swagger.json" });
  });

  it("returns JSON 404s for unknown API routes", async () => {
    const res = await api().get("/api/v1/does-not-exist");
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: "NOT_FOUND", message: "Cannot GET /api/v1/does-not-exist" });
  });

  it("sets security headers", async () => {
    const res = await api().get("/health");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.headers["content-security-policy"]).toContain("script-src 'self'");
    expect(res.headers["x-powered-by"]).toBeUndefined();
    expect(res.headers["x-request-id"]).toEqual(expect.any(String));
  });

  it("answers CORS preflight requests", async () => {
    const res = await api().options("/api/v1/auth/login")
      .set("Origin", "https://portfolio.example.com")
      .set("Access-Control-Request-Method", "POST")
      .set("Access-Control-Request-Headers", "content-type,authorization");
    expect(res.status).toBe(204);
    expect(res.headers["access-control-allow-origin"]).toBe("*");
  });
});

describe("interactive console", () => {
  it("serves the console and OAuth pages", async () => {
    const index = await api().get("/");
    expect(index.status).toBe(200);
    expect(index.headers["content-type"]).toContain("text/html");
    expect(index.text).toContain("SecureAccess");

    for (const page of ["/oauth/consent.html", "/oauth/callback.html", "/app.js", "/styles.css"]) {
      expect((await api().get(page)).status).toBe(200);
    }
  });
});

describe("OpenAPI documentation", () => {
  it("serves a valid OpenAPI 3 document", async () => {
    const res = await api().get("/swagger.json");
    expect(res.status).toBe(200);
    // validate() dereferences in place, so give it a copy
    await expect(SwaggerParser.validate(structuredClone(res.body))).resolves.toBeDefined();
  });

  it("documents every API route", () => {
    const paths = openApiSpec.paths as Record<string, Record<string, unknown>>;
    const missing: string[] = [];

    for (const [prefix, router] of apiRouters) {
      for (const layer of (router as unknown as { stack: Array<{ route?: { path: string; methods: Record<string, boolean> } }> }).stack) {
        if (!layer.route) continue;
        const path = `${API_PREFIX}${prefix}${layer.route.path}`.replace(/:(\w+)/g, "{$1}").replace(/\/$/, "");
        for (const method of Object.keys(layer.route.methods)) {
          if (!paths[path]?.[method]) missing.push(`${method.toUpperCase()} ${path}`);
        }
      }
    }

    expect(missing).toEqual([]);
  });

  it("redirects /api-docs to /api-docs/ so relative asset URLs resolve", async () => {
    const res = await api().get("/api-docs?tag=Users");
    expect(res.status).toBe(301);
    expect(res.headers.location).toBe("/api-docs/?tag=Users");
  });

  it("serves Swagger UI with assets from swagger-ui-dist (no CDN)", async () => {
    const page = await api().get("/api-docs/");
    expect(page.status).toBe(200);
    expect(page.headers["content-type"]).toContain("text/html");
    expect(page.text).toContain("<title>SecureAccess API Docs</title>");
    expect(page.text).toContain("./swagger-ui-bundle.js");
    expect(page.text).not.toContain("cdn.jsdelivr.net");

    for (const asset of [
      "/api-docs/swagger-ui.css",
      "/api-docs/swagger-ui-bundle.js",
      "/api-docs/swagger-ui-standalone-preset.js",
      "/swagger-ui-assets/swagger-ui.css",
      "/swagger-ui-assets/swagger-ui-bundle.js",
      "/swagger-ui-assets/favicon-32x32.png",
    ]) {
      expect({ asset, status: (await api().get(asset)).status }).toEqual({ asset, status: 200 });
    }

    const init = await api().get("/api-docs/swagger-ui-init.js");
    expect(init.headers["content-type"]).toContain("javascript");
    expect(init.text).toContain("SecureAccess — Authentication, RBAC & OpenID Connect API"); // spec embedded
    expect(init.text).toContain('"validatorUrl": null');
  });
});
