import { Request, Response } from "express";
import { Prisma } from "@prisma/client";
import { z } from "zod";
import { errorHandler, notFound } from "../../src/middleware/error.middleware";
import { AppError } from "../../src/utils/errors";

interface CapturedResponse {
  statusCode: number;
  body: Record<string, unknown>;
}

function run(err: unknown, headersSent = false) {
  const captured: CapturedResponse = { statusCode: 0, body: {} };
  const res = {
    headersSent,
    status(code: number) { captured.statusCode = code; return this; },
    json(body: Record<string, unknown>) { captured.body = body; return this; },
  } as unknown as Response;
  const req = { requestId: "req-123", path: "/x", method: "GET", originalUrl: "/api/v1/x?y=1" } as Request;
  const next = jest.fn();
  errorHandler(err, req, res, next);
  return { ...captured, next };
}

const prismaError = (code: string) =>
  new Prisma.PrismaClientKnownRequestError("database said no", { code, clientVersion: "5.22.0" });

describe("errorHandler", () => {
  it("returns AppErrors with their status, code, details and the request id", () => {
    const out = run(new AppError(423, "ACCOUNT_LOCKED", "Locked", { lockedUntil: "later" }));
    expect(out.statusCode).toBe(423);
    expect(out.body).toEqual({ error: "ACCOUNT_LOCKED", message: "Locked", details: { lockedUntil: "later" }, requestId: "req-123" });
  });

  it("maps Zod errors to 400 VALIDATION_ERROR", () => {
    const zodError = z.object({ email: z.string().email() }).safeParse({ email: "x" }).error;
    const out = run(zodError);
    expect(out.statusCode).toBe(400);
    expect(out.body.error).toBe("VALIDATION_ERROR");
    expect(out.body.details).toHaveProperty("email");
  });

  it.each([
    ["P2025", 404, "NOT_FOUND"],
    ["P2002", 409, "CONFLICT"],
    ["P2003", 409, "CONFLICT"],
    ["P2021", 503, "SCHEMA_OUT_OF_DATE"],
    ["P2022", 503, "SCHEMA_OUT_OF_DATE"],
  ])("maps Prisma %s to %i %s", (code, status, error) => {
    const out = run(prismaError(code));
    expect(out.statusCode).toBe(status);
    expect(out.body.error).toBe(error);
  });

  it("never exposes database details for schema errors", () => {
    const out = run(prismaError("P2022"));
    expect(JSON.stringify(out.body)).not.toContain("database said no");
    expect(JSON.stringify(out.body)).not.toContain("migrate");
  });

  it("hides a stale-Prisma-Client error behind a generic 500", () => {
    const stale = new Prisma.PrismaClientValidationError("Unknown argument `trustedUntil`. Available options are marked with ?.", { clientVersion: "5.22.0" });
    const out = run(stale);
    expect(out.statusCode).toBe(500);
    expect(out.body).toEqual({ error: "INTERNAL_ERROR", message: "An unexpected error occurred", requestId: "req-123" });
  });

  it("maps body-parser errors", () => {
    expect(run({ type: "entity.parse.failed" }).body.error).toBe("INVALID_JSON");
    expect(run({ type: "entity.too.large" }).statusCode).toBe(413);
  });

  it("hides unexpected errors behind a generic 500", () => {
    const out = run(new Error("secret stack detail"));
    expect(out.statusCode).toBe(500);
    expect(out.body).toEqual({ error: "INTERNAL_ERROR", message: "An unexpected error occurred", requestId: "req-123" });
  });

  it("delegates to Express when headers were already sent", () => {
    const err = new Error("late");
    const out = run(err, true);
    expect(out.next).toHaveBeenCalledWith(err);
    expect(out.statusCode).toBe(0);
  });
});

describe("notFound", () => {
  it("reports the full path without the query string", () => {
    let body: unknown;
    const res = { status() { return this; }, json(b: unknown) { body = b; return this; } } as unknown as Response;
    notFound({ method: "GET", originalUrl: "/api/v1/nope?x=1" } as Request, res);
    expect(body).toEqual({ error: "NOT_FOUND", message: "Cannot GET /api/v1/nope" });
  });
});
