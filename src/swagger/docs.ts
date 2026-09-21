// src/swagger/docs.ts — Swagger UI (served from node_modules/swagger-ui-dist) + raw OpenAPI spec
//
// Why this works on Vercel:
//  1. The asset folder is referenced with a literal __dirname-relative path, which Vercel's
//     file tracer (@vercel/nft) recognises and copies into the serverless bundle.
//     vercel.json also lists it under includeFiles as a guarantee.
//  2. "/api-docs" redirects to "/api-docs/". Swagger UI's HTML loads ./swagger-ui.css,
//     ./swagger-ui-bundle.js … relatively; without the trailing slash they resolve to
//     /swagger-ui.css (404) and the page stays blank.
import express, { Request, RequestHandler, Router } from "express";
import fs from "fs";
import helmet from "helmet";
import path from "path";
import swaggerUi from "swagger-ui-express";
import { config } from "../config";
import { openApiSpec } from "./openapi";

const LITERAL_ASSETS_DIR = path.join(__dirname, "../../node_modules/swagger-ui-dist");

// Falls back to Node's resolver if node_modules is laid out differently
const SWAGGER_ASSETS_DIR = fs.existsSync(LITERAL_ASSETS_DIR)
  ? LITERAL_ASSETS_DIR
  : path.dirname(require.resolve("swagger-ui-dist/package.json"));

interface ServerEntry {
  url: string;
  description: string;
}

/**
 * The "Servers" dropdown: Local and Deployed, with the server that is serving
 * these docs listed first so "Try it out" works without changing the selection.
 */
export function serversFor(req: Request): ServerEntry[] {
  const known: ServerEntry[] = [
    { url: config.urls.local,    description: "Local (localhost)" },
    { url: config.urls.deployed, description: "Deployed (Vercel)" },
  ];
  const origin  = `${req.protocol}://${req.get("host")}`;
  const current = known.find(server => server.url === origin);
  return current
    ? [current, ...known.filter(server => server !== current)]
    : [{ url: origin, description: "This server" }, ...known];
}

const specFor = (req: Request) => ({ ...openApiSpec, servers: serversFor(req) });

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

// "Try it out" may call the other server in the dropdown, so allow both origins.
// No upgrade-insecure-requests here: it would rewrite http://localhost calls to https.
const docsCsp = helmet.contentSecurityPolicy({
  directives: {
    "script-src":  ["'self'"],
    "img-src":     ["'self'", "data:"],
    "connect-src": ["'self'", config.urls.local, config.urls.deployed],
    "upgrade-insecure-requests": null,
  },
});

export const docsRouter = Router();

// Raw OpenAPI document (Postman, code generators, other viewers)
docsRouter.get("/swagger.json", (req, res) => {
  res.json(specFor(req));
});

// Direct access to Swagger UI's static files (css, js, favicons)
docsRouter.use("/swagger-ui-assets", express.static(SWAGGER_ASSETS_DIR, { index: false, maxAge: "7d" }));

// Add the trailing slash so relative asset URLs resolve under /api-docs/
docsRouter.get("/api-docs", (req, res, next) => {
  const [pathname, query] = req.originalUrl.split("?");
  if (pathname.endsWith("/")) return next();
  res.redirect(301, `${pathname}/${query ? `?${query}` : ""}`);
});

// swagger-ui-express reads req.swaggerDoc, which lets each request carry
// a server list ordered for the host it arrived on
const attachSpec: RequestHandler = (req, _res, next) => {
  Object.assign(req, { swaggerDoc: specFor(req) });
  next();
};

// Swagger UI page + its init script and assets
docsRouter.use(
  "/api-docs",
  docsCsp,
  attachSpec,
  swaggerUi.serveFiles(openApiSpec, uiOptions),
  swaggerUi.setup(openApiSpec, uiOptions),
);
