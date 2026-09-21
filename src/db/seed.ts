// src/db/seed.ts — Idempotent seed: system roles, admin, demo accounts, demo OIDC client
// Safe to run on every deploy: existing data is never duplicated.
// Development: `npm run seed` (ts-node) · Production: `npm run seed:prod` (compiled)
import { PrismaClient } from "@prisma/client";
import { hashPassword, generateSecurePassword, isStrongPassword } from "../utils/password";

const SYSTEM_ROLES = [
  {
    name: "admin",
    description: "Full system access",
    permissions: [{ action: "manage", resource: "*" }],
  },
  {
    name: "auditor",
    description: "Read-only access to users, roles, clients and the audit trail",
    permissions: [
      { action: "read",   resource: "user" },
      { action: "read",   resource: "role" },
      { action: "read",   resource: "client" },
      { action: "read",   resource: "audit" },
      { action: "export", resource: "audit" },
    ],
  },
  {
    name: "user",
    description: "Standard self-service user",
    permissions: [],
  },
] as const;

export const DEFAULT_ADMIN_EMAIL    = "admin@secureaccess.dev";
export const DEFAULT_ADMIN_PASSWORD = "ChangeMe!Local#2026"; // development only

// Public, protected demo logins for a portfolio deployment
export const DEMO_ACCOUNTS = [
  { email: "auditor@secureaccess.dev", password: "Auditor!Demo#2026", firstName: "Avery", lastName: "Auditor", role: "auditor" },
  { email: "demo@secureaccess.dev",    password: "DemoUser!Try#2026", firstName: "Dana",  lastName: "Demo",    role: "user" },
] as const;

export const DEMO_CLIENT = {
  clientId:     "secureaccess-demo",
  name:         "SecureAccess Demo App",
  redirectUris: ["/oauth/callback.html"],
};

export async function seed(prisma: PrismaClient, log: (msg: string) => void = console.log): Promise<void> {
  // ── Roles ─────────────────────────────────────────────────────
  const roleIds: Record<string, string> = {};
  for (const def of SYSTEM_ROLES) {
    const role = await prisma.role.upsert({
      where:  { name: def.name },
      update: { isSystem: true },
      create: { name: def.name, description: def.description, isSystem: true },
    });
    if (def.permissions.length > 0) {
      await prisma.permission.createMany({
        data: def.permissions.map(p => ({ ...p, roleId: role.id })),
        skipDuplicates: true,
      });
    }
    roleIds[def.name] = role.id;
  }

  // ── Admin ─────────────────────────────────────────────────────
  const adminEmail = (process.env.SEED_ADMIN_EMAIL || DEFAULT_ADMIN_EMAIL).toLowerCase();
  const existingAdmin = await prisma.user.findUnique({ where: { email: adminEmail } });

  if (!existingAdmin) {
    let password = process.env.SEED_ADMIN_PASSWORD;
    let generated = false;

    if (!password) {
      if (process.env.NODE_ENV === "production") {
        password  = generateSecurePassword(20);
        generated = true;
      } else {
        password = DEFAULT_ADMIN_PASSWORD;
      }
    } else if (!isStrongPassword(password).valid) {
      throw new Error(
        `SEED_ADMIN_PASSWORD is too weak: ${isStrongPassword(password).errors.join("; ")}. ` +
        "Use 12+ characters with upper and lower case, a digit and a symbol, and none of: password, 123456, qwerty, admin, letmein.",
      );
    }

    const admin = await prisma.user.create({
      data: {
        email:             adminEmail,
        passwordHash:      await hashPassword(password),
        firstName:         "System",
        lastName:          "Admin",
        passwordChangedAt: new Date(),
        roles:             { create: { roleId: roleIds.admin } },
      },
    });
    log(`Created admin ${admin.email}${generated ? ` with generated password: ${password}  (shown once — store it now)` : ""}`);
  } else {
    await prisma.userRole.upsert({
      where:  { userId_roleId: { userId: existingAdmin.id, roleId: roleIds.admin } },
      update: {},
      create: { userId: existingAdmin.id, roleId: roleIds.admin },
    });
    log(`Admin ${adminEmail} already exists — left unchanged`);
  }

  // ── Demo accounts (reset to a known state on every run) ───────
  if (process.env.SEED_DEMO_ACCOUNTS !== "false") {
    for (const demo of DEMO_ACCOUNTS) {
      const passwordHash = await hashPassword(demo.password);
      const user = await prisma.user.upsert({
        where:  { email: demo.email },
        update: {
          passwordHash, isProtected: true, isActive: true, failedLoginAttempts: 0, lockedUntil: null,
          mfaEnabled: false, mfaSecret: null, backupCodesHashed: null, mfaLastUsedStep: null,
        },
        create: {
          email: demo.email, passwordHash, firstName: demo.firstName, lastName: demo.lastName,
          isProtected: true, passwordChangedAt: new Date(),
        },
      });
      await prisma.userRole.upsert({
        where:  { userId_roleId: { userId: user.id, roleId: roleIds[demo.role] } },
        update: {},
        create: { userId: user.id, roleId: roleIds[demo.role] },
      });
    }
    log(`Demo accounts ready: ${DEMO_ACCOUNTS.map(d => d.email).join(", ")}`);
  }

  // ── Demo OpenID Connect client (public, PKCE) ─────────────────
  await prisma.oAuthClient.upsert({
    where:  { clientId: DEMO_CLIENT.clientId },
    update: { redirectUris: DEMO_CLIENT.redirectUris },
    create: { ...DEMO_CLIENT, isConfidential: false },
  });
  log(`OIDC client ready: ${DEMO_CLIENT.clientId}`);
}

if (require.main === module) {
  const prisma = new PrismaClient();
  seed(prisma)
    .then(() => console.log("Seed complete"))
    .catch(err => {
      console.error(err);
      process.exitCode = 1;
    })
    .finally(() => prisma.$disconnect());
}
