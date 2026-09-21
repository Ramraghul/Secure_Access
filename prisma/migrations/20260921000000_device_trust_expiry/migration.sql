-- Device trust ("remember this device") now expires after TRUSTED_DEVICE_DAYS (default 30).
-- AlterTable
ALTER TABLE "devices" ADD COLUMN     "trustedUntil" TIMESTAMP(3);

-- Trust granted before this release never expired and could be set without an MFA code,
-- so it is reset: every MFA-enabled user enters a code on each device once more.
UPDATE "devices" SET "isTrusted" = false;
