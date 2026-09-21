// src/controllers/device.controller.ts
import { Request, Response } from "express";
import { prisma } from "../lib/prisma";
import { badRequest, notFound } from "../utils/errors";
import { validate, IdParamSchema, TrustDeviceSchema } from "../utils/validation";
import { revokeAllSessions } from "../services/session.service";
import { assertNotLocked } from "../services/user.service";
import { verifySecondFactor } from "../services/mfa.service";
import { TRUST_CLEARED, newTrustExpiry, trustView } from "../services/device.service";

const activeSessionFilter = () => ({ revokedAt: null, expiresAt: { gt: new Date() } });

export const listMyDevices = async (req: Request, res: Response): Promise<void> => {
  const devices = await prisma.device.findMany({
    where:   { userId: req.user!.id },
    orderBy: { lastUsedAt: "desc" },
    select:  {
      id: true, deviceName: true, ipAddress: true, userAgent: true, isTrusted: true, trustedUntil: true,
      firstUsedAt: true, lastUsedAt: true,
      _count: { select: { sessions: { where: activeSessionFilter() } } },
    },
  });

  res.json({
    devices: devices.map(({ _count, ...d }) => ({
      ...d,
      ...trustView(d),
      activeSessions: _count.sessions,
      current:        d.id === req.user!.deviceId,
    })),
  });
};

export const getCurrentDevice = async (req: Request, res: Response): Promise<void> => {
  const device = req.device!;
  const record = await prisma.device.findUnique({
    where:  { userId_fingerprint: { userId: req.user!.id, fingerprint: device.fingerprint } },
    select: { id: true, isTrusted: true, trustedUntil: true, firstUsedAt: true },
  });
  const trust = record ? trustView(record) : { isTrusted: false, trustedUntil: null };

  res.json({
    currentDevice: {
      id:           record?.id ?? null,
      fingerprint:  device.fingerprint,
      name:         device.name,
      ipAddress:    device.ipAddress,
      userAgent:    device.userAgent,
      isKnown:      Boolean(record),
      isTrusted:    trust.isTrusted,
      trustedUntil: trust.trustedUntil,
      firstUsedAt:  record?.firstUsedAt ?? null,
    },
  });
};

async function findOwnedDevice(req: Request) {
  const { id } = validate(IdParamSchema, req.params);
  const device = await prisma.device.findFirst({ where: { id, userId: req.user!.id } });
  // 404 (not 403) for other users' devices so ids cannot be probed
  if (!device) throw notFound("DEVICE_NOT_FOUND", "Device not found");
  return device;
}

export const trustDevice = async (req: Request, res: Response): Promise<void> => {
  const device = await findOwnedDevice(req);
  const user   = await prisma.user.findUniqueOrThrow({ where: { id: req.user!.id } });

  // Trust exists only to skip the MFA code, so it must be earned with a second factor.
  // Otherwise any signed-in session could quietly switch MFA off for a device.
  if (!user.mfaEnabled) {
    throw badRequest("MFA_NOT_ENABLED", "Enable MFA first — a trusted device only skips the MFA code");
  }
  const factor = validate(TrustDeviceSchema, req.body ?? {});
  assertNotLocked(user);
  await verifySecondFactor(res, user, factor);

  const trustedUntil = newTrustExpiry();
  await prisma.device.update({ where: { id: device.id }, data: { isTrusted: true, trustedUntil } });

  res.locals.auditEvent   = "DEVICE_TRUSTED";
  res.locals.auditDetails = { ...res.locals.auditDetails, deviceId: device.id, trustedUntil };
  res.json({ success: true, message: "Device trusted — the MFA code is skipped there until trustedUntil", trustedUntil });
};

export const revokeDevice = async (req: Request, res: Response): Promise<void> => {
  const device = await findOwnedDevice(req);
  await prisma.device.update({ where: { id: device.id }, data: TRUST_CLEARED });
  res.locals.auditEvent   = "DEVICE_TRUST_REVOKED";
  res.locals.auditDetails = { deviceId: device.id };
  res.json({ success: true, message: "Trust revoked — MFA required on next login" });
};

export const deleteDevice = async (req: Request, res: Response): Promise<void> => {
  const device = await findOwnedDevice(req);
  const revokedSessions = await revokeAllSessions(req.user!.id, "DEVICE_REMOVED", { deviceId: device.id });
  await prisma.device.delete({ where: { id: device.id } });
  res.locals.auditEvent   = "DEVICE_REMOVED";
  res.locals.auditDetails = { deviceId: device.id, revokedSessions };
  res.json({ success: true, message: "Device removed and its sessions signed out", revokedSessions });
};
