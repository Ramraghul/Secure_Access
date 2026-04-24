// src/controllers/device.controller.ts
import { Request, Response } from "express";
import { prisma } from "../lib/prisma";

export const listMyDevices = async (req: Request, res: Response): Promise<void> => {
  const devices = await prisma.device.findMany({
    where: { userId: req.user!.id },
    orderBy: { lastUsedAt: "desc" },
  });
  res.json({ devices });
};

export const getCurrentDevice = async (req: Request, res: Response): Promise<void> => {
  if (!req.device) { res.status(400).json({ error: "DEVICE_INFO_UNAVAILABLE" }); return; }
  res.json({
    currentDevice: {
      fingerprint: req.device.fingerprint,
      name:        req.device.name,
      ipAddress:   req.device.ipAddress,
      userAgent:   req.device.userAgent,
      isTrusted:   req.device.isTrusted ?? false,
    },
  });
};

const getOwnedDevice = async (id: string, userId: string) => {
  const device = await prisma.device.findUnique({ where: { id } });
  return device?.userId === userId ? device : null;
};

export const trustDevice = async (req: Request, res: Response): Promise<void> => {
  const device = await getOwnedDevice(req.params.id, req.user!.id);
  if (!device) { res.status(404).json({ error: "DEVICE_NOT_FOUND" }); return; }
  await prisma.device.update({ where: { id: req.params.id }, data: { isTrusted: true } });
  res.json({ success: true, message: "Device trusted" });
};

export const revokeDevice = async (req: Request, res: Response): Promise<void> => {
  const device = await getOwnedDevice(req.params.id, req.user!.id);
  if (!device) { res.status(404).json({ error: "DEVICE_NOT_FOUND" }); return; }
  await prisma.device.update({ where: { id: req.params.id }, data: { isTrusted: false } });
  res.json({ success: true, message: "Trust revoked — MFA required on next login" });
};

export const deleteDevice = async (req: Request, res: Response): Promise<void> => {
  const device = await getOwnedDevice(req.params.id, req.user!.id);
  if (!device) { res.status(404).json({ error: "DEVICE_NOT_FOUND" }); return; }
  await prisma.device.delete({ where: { id: req.params.id } });
  res.json({ success: true, message: "Device record removed" });
};
