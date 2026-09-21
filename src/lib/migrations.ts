// src/lib/migrations.ts — Detects migrations that exist in the repo but not in the database
// Running new code against an old schema fails with "column … does not exist";
// this turns that into a clear warning at startup and in /health.
import fs from "fs";
import path from "path";
import { prisma } from "./prisma";

// Literal __dirname-relative path so Vercel's file tracer bundles the folder
const MIGRATIONS_DIR = path.join(__dirname, "../../prisma/migrations");

export function localMigrations(): string[] | null {
  try {
    return fs.readdirSync(MIGRATIONS_DIR, { withFileTypes: true })
      .filter(entry => entry.isDirectory())
      .map(entry => entry.name)
      .sort();
  } catch {
    return null; // folder not shipped with this build
  }
}

/** Names of migrations not yet applied, or null when that cannot be determined. */
export async function pendingMigrations(): Promise<string[] | null> {
  const local = localMigrations();
  if (!local) return null;

  try {
    const rows = await prisma.$queryRaw<{ migration_name: string }[]>`
      SELECT migration_name FROM _prisma_migrations
      WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL`;
    const applied = new Set(rows.map(row => row.migration_name));
    return local.filter(name => !applied.has(name));
  } catch (err) {
    // No _prisma_migrations table means nothing has been applied yet;
    // any other failure (database down) means "unknown"
    return /42P01|relation "_prisma_migrations" does not exist/.test(String(err)) ? local : null;
  }
}

export const MIGRATE_HINT = "Run `npm run migrate:deploy` (prisma migrate deploy) against this DATABASE_URL, then `npm run seed`.";

export const CLIENT_HINT = "Run `npx prisma generate` and restart the server (`npm run dev` does both automatically).";

const SCHEMA_FILE = path.join(__dirname, "../../prisma/schema.prisma");

const normalizeSchema = (text: string): string =>
  text.replace(/\/\/.*$/gm, "").replace(/\s+/g, " ").trim();

/**
 * True when the generated Prisma Client was built from an older schema.prisma.
 * A running server keeps the client it loaded at startup, so after the schema
 * changes it fails with "Unknown argument …" until it is regenerated and restarted.
 * Returns null when either file is unavailable (e.g. a serverless bundle).
 */
export function prismaClientIsStale(): boolean | null {
  try {
    const generatedDir = path.dirname(require.resolve(".prisma/client/index.js"));
    const generated    = fs.readFileSync(path.join(generatedDir, "schema.prisma"), "utf8");
    const source       = fs.readFileSync(SCHEMA_FILE, "utf8");
    return normalizeSchema(generated) !== normalizeSchema(source);
  } catch {
    return null;
  }
}
