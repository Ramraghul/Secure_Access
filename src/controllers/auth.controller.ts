// src/controllers/auth.controller.ts
import { Request, Response } from "express";
import { hashPassword, verifyPassword, isStrongPassword } from "../utils/password";
import { signJwt, signRefreshToken } from "../utils/jwt";
import { generateMFASecret, verifyTOTP, hashBackupCodes } from "../utils/mfa";
import { trustCurrentDevice } from "../middleware/device.middleware";
import { validate, RegisterSchema, LoginSchema, MfaVerifySchema } from "../utils/validation";
import { prisma } from "../lib/prisma";

export const register = async (req: Request, res: Response): Promise<void> => {
  const body = validate(RegisterSchema, req.body);

  const existing = await prisma.user.findUnique({ where: { email: body.email } });
  if (existing) { res.status(409).json({ error: "EMAIL_EXISTS", message: "Email already registered" }); return; }

  const strength = isStrongPassword(body.password);
  if (!strength.valid) { res.status(400).json({ error: "WEAK_PASSWORD", details: strength.errors }); return; }

  const user = await prisma.user.create({
    data: {
      email:        body.email,
      passwordHash: await hashPassword(body.password),
      firstName:    body.firstName,
      lastName:     body.lastName,
    },
  });

  res.status(201).json({ message: "User registered successfully", userId: user.id });
};

export const login = async (req: Request, res: Response): Promise<void> => {
  const body   = validate(LoginSchema, req.body);
  const device = req.device;

  const user = await prisma.user.findUnique({
    where:   { email: body.email },
    include: { devices: true },
  });

  if (!user || !user.isActive || !(await verifyPassword(body.password, user.passwordHash))) {
    res.status(401).json({ error: "INVALID_CREDENTIALS", message: "Invalid email or password" });
    return;
  }

  const requireMfa = user.mfaEnabled && !req.trustedDevice;

  if (requireMfa && !body.totp_code) {
    res.status(206).json({
      mfaRequired: true,
      message:     "Please provide your MFA code",
    });
    return;
  }

  if (requireMfa && body.totp_code && !verifyTOTP(user.mfaSecret!, body.totp_code)) {
    res.status(401).json({ error: "INVALID_MFA", message: "Invalid or expired MFA code" });
    return;
  }

  if (requireMfa && body.totp_code) {
    await trustCurrentDevice(req, user.id);
  }

  const token        = signJwt({ id: user.id, email: user.email, deviceId: device?.fingerprint });
  const refreshToken = signRefreshToken(user.id, device?.fingerprint);

  if (device) {
    await prisma.device.upsert({
      where:  { userId_fingerprint: { userId: user.id, fingerprint: device.fingerprint } },
      update: { lastUsedAt: new Date(), isTrusted: true, deviceName: device.name },
      create: {
        userId:      user.id,
        userAgent:   device.userAgent,
        ipAddress:   device.ipAddress,
        deviceName:  device.name,
        fingerprint: device.fingerprint,
        isTrusted:   true,
      },
    });
  }

  res.json({
    token,
    refreshToken,
    user: { id: user.id, email: user.email, mfaEnabled: user.mfaEnabled },
  });
};

export const setupMFA = async (req: Request, res: Response): Promise<void> => {
  const userId = req.user!.id;
  const { secret, qrCode, backupCodes } = await generateMFASecret(req.user!.email);
  const hashedBackupCodes = await hashBackupCodes(backupCodes);

  await prisma.user.update({
    where: { id: userId },
    data:  { mfaSecret: secret, backupCodesHashed: JSON.stringify(hashedBackupCodes) },
  });

  res.json({
    qrCode,
    secret,
    backupCodes, // shown once — not stored in plaintext
    message: "Scan QR with your authenticator app, then call /mfa/verify",
  });
};

export const verifyMFA = async (req: Request, res: Response): Promise<void> => {
  const { token } = validate(MfaVerifySchema, req.body);
  const user = await prisma.user.findUnique({ where: { id: req.user!.id } });

  if (!user?.mfaSecret || !verifyTOTP(user.mfaSecret, token)) {
    res.status(400).json({ error: "INVALID_MFA_CODE", message: "Invalid or expired code" });
    return;
  }

  await prisma.user.update({
    where: { id: req.user!.id },
    data:  { mfaEnabled: true },
  });

  res.json({ success: true, message: "MFA enabled successfully" });
};

export const me = async (req: Request, res: Response): Promise<void> => {
  const user = await prisma.user.findUnique({
    where:  { id: req.user!.id },
    select: { id: true, email: true, firstName: true, lastName: true, mfaEnabled: true, createdAt: true },
  });
  const devices = await prisma.device.findMany({
    where:   { userId: req.user!.id },
    orderBy: { lastUsedAt: "desc" },
    select:  { id: true, deviceName: true, ipAddress: true, isTrusted: true, lastUsedAt: true, firstUsedAt: true },
  });
  res.json({ user, devices });
};
