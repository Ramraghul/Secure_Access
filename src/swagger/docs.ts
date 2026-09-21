// src/swagger/docs.ts — Swagger UI (served from node_modules/swagger-ui-dist) + raw OpenAPI spec
//
// Why this works on Vercel:
//  1. The asset folder is referenced with a literal __dirname-relative path, which Vercel's
//     file tracer (@vercel/nft) recognises and copies into the serverless bundle.
//     vercel.json also lists it under includeFiles as a guarantee.
//  2. "/api-docs" redirects to "/api-docs/". Swagger UI's HTML loads ./swagger-ui.css,
//     ./swagger-ui-bundle.js … relatively; without the trailing slash they resolve to
//     /swagger-ui.css (404) and the page stays blank.
import express, { Router } from "express";
import fs from "fs";
import path from "path";
import swaggerUi from "swagger-ui-express";
import { openApiSpec } from "./openapi";

const LITERAL_ASSETS_DIR = path.join(__dirname, "../../node_modules/swagger-ui-dist");

// Falls back to Node's resolver if node_modules is laid out differently
const SWAGGER_ASSETS_DIR =fs.existsSync(LITERAL_ASSETS_DIR)
  ? LITERAL_ASSETS_DIR
  : path.dirname(require.resolve("swagger-ui-dist/package.json"));

const uiOptions: swaggerUi.SwaggerUiOptions = {
  customSiteTitle: "SecureAccess API Docs",
  customfavIcon:   "/swagger-ui-assets/favicon-32x32.png",
  // Swagger UI follows the visitor's light/dark preference on its own
  customCss:       ".swagger-ui .topbar { display: none }",
  swaggerOptions: {
    persistAuthorization:   true,
    displayRequestDuration: true,
    filter:                 true,
    tryItOutEnabled:        true,
    docExpansion:           "none",
    deepLinking:            true,
    validatorUrl:           null, // no requests to validator.swagger.io
  },
};

export const docsRouter = Router();

// Raw OpenAPI document (Postman, code generators, other viewers)
docsRouter.get("/swagger.json", (_req, res) => {
  res.json(openApiSpec);
});

// Direct access to Swagger UI's static files (css, js, favicons)
docsRouter.use("/swagger-ui-assets", express.static(SWAGGER_ASSETS_DIR, { index: false, maxAge: "7d" }));

// Add the trailing slash so relative asset URLs resolve under /api-docs/
docsRouter.get("/api-docs", (req, res, next) => {
  const [pathname, query] = req.originalUrl.split("?");
  if (pathname.endsWith("/")) return next();
  res.redirect(301, `${pathname}/${query ? `?${query}` : ""}`);
});

// Swagger UI page + its init script and assets, with the spec embedded
docsRouter.use("/api-docs", swaggerUi.serveFiles(openApiSpec, uiOptions), swaggerUi.setup(openApiSpec, uiOptions));
