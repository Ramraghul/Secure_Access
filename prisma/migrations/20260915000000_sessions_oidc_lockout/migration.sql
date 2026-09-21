-- AlterTable
ALTER TABLE "users" ADD COLUMN     "failedLoginAttempts" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "isProtected" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "lastLoginAt" TIMESTAMP(3),
ADD COLUMN     "lockedUntil" TIMESTAMP(3),
ADD COLUMN     "mfaLastUsedStep" INTEGER,
ADD COLUMN     "mustChangePassword" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "passwordChangedAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "roles" ADD COLUMN     "isSystem" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE "audit_logs" ADD COLUMN     "event" TEXT,
ADD COLUMN     "statusCode" INTEGER;

-- CreateTable
CREATE TABLE "sessions" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "deviceId" TEXT,
    "clientId" TEXT,
    "scope" TEXT,
    "refreshTokenHash" TEXT NOT NULL,
    "ipAddress" TEXT NOT NULL,
    "userAgent" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastUsedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "revokedReason" TEXT,

    CONSTRAINT "sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "oauth_clients" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "clientSecretHash" TEXT,
    "name" TEXT NOT NULL,
    "redirectUris" TEXT[],
    "isConfidential" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "oauth_clients_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "authorization_codes" (
    "id" TEXT NOT NULL,
    "codeHash" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "redirectUri" TEXT NOT NULL,
    "scope" TEXT NOT NULL,
    "nonce" TEXT,
    "codeChallenge" TEXT,
    "codeChallengeMethod" TEXT,
    "authTime" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "authorization_codes_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "sessions_userId_idx" ON "sessions"("userId");

-- CreateIndex
CREATE INDEX "sessions_deviceId_idx" ON "sessions"("deviceId");

-- CreateIndex
CREATE INDEX "sessions_clientId_idx" ON "sessions"("clientId");

-- CreateIndex
CREATE UNIQUE INDEX "oauth_clients_clientId_key" ON "oauth_clients"("clientId");

-- CreateIndex
CREATE UNIQUE INDEX "authorization_codes_codeHash_key" ON "authorization_codes"("codeHash");

-- CreateIndex
CREATE INDEX "authorization_codes_userId_idx" ON "authorization_codes"("userId");

-- CreateIndex
CREATE INDEX "authorization_codes_clientId_idx" ON "authorization_codes"("clientId");

-- CreateIndex
CREATE INDEX "user_roles_roleId_idx" ON "user_roles"("roleId");

-- CreateIndex
CREATE INDEX "audit_logs_event_idx" ON "audit_logs"("event");

-- CreateIndex
CREATE INDEX "audit_logs_statusCode_idx" ON "audit_logs"("statusCode");

-- AddForeignKey
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "devices"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "oauth_clients"("clientId") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "authorization_codes" ADD CONSTRAINT "authorization_codes_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "oauth_clients"("clientId") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "authorization_codes" ADD CONSTRAINT "authorization_codes_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

