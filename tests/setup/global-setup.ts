// Runs once before the integration tests: fresh schema from migrations + seed data
import { execSync } from "child_process";
import dotenv from "dotenv";

export default async function globalSetup(): Promise<void> {
  process.env.NODE_ENV = "test";
  dotenv.config({ path: ".env.test" });

  const url = process.env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL is not set for tests (see .env.test)");

  // `migrate reset` drops everything — never let it touch a non-test database
  const dbName = new URL(url).pathname.replace(/^\//, "");
  if (!/test/i.test(dbName)) {
    throw new Error(`Refusing to reset database "${dbName}": test database names must contain "test"`);
  }

  execSync("npx prisma migrate reset --force --skip-seed --skip-generate", {
    stdio: "pipe",
    env:   process.env,
  });

  const { PrismaClient } = await import("@prisma/client");
  const { seed } = await import("../../src/db/seed");
  const prisma = new PrismaClient();
  try {
    await seed(prisma, () => undefined);
  } finally {
    await prisma.$disconnect();
  }
}
