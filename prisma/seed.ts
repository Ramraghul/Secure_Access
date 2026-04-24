import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();

async function main() {
  // Seed roles
  const adminRole = await prisma.role.upsert({
    where: { name: "admin" },
    update: {},
    create: {
      name: "admin",
      description: "Full system access",
      permissions: {
        create: [
          { action: "manage", resource: "*" },
          { action: "read",   resource: "audit" },
          { action: "export", resource: "audit" },
        ],
      },
    },
  });

  const userRole = await prisma.role.upsert({
    where: { name: "user" },
    update: {},
    create: { name: "user", description: "Standard user" },
  });

  // Seed admin user
  const hash = await bcrypt.hash("Admin@SecureAccess123", 12);
  const admin = await prisma.user.upsert({
    where: { email: "admin@secureaccess.ca" },
    update: {},
    create: {
      email:        "admin@secureaccess.ca",
      passwordHash: hash,
      firstName:    "System",
      lastName:     "Admin",
    },
  });

  await prisma.userRole.upsert({
    where:  { userId_roleId: { userId: admin.id, roleId: adminRole.id } },
    update: {},
    create: { userId: admin.id, roleId: adminRole.id },
  });

  console.log("Seeded: admin@secureaccess.ca / Admin@SecureAccess123");
}

main().catch(console.error).finally(() => prisma.$disconnect());
