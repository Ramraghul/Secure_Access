// src/controllers/auth.controller.ts
import { Request, Response } from "express";
import { User } from "@prisma/client";
import { prisma } from "../lib/prisma";
import { hashPassword, verifyPassword, isStrongPassword, burnPasswordCheck } from "../utils/password";
import { signAccessToken, signMfaToken, verifyToken, secondsUntilExpiry } from "../utils/jwt";
import { generateMFASecret, verifyTOTP, hashBackupCodes } from "../utils/mfa";
import { AppError, badRequest, conflict, forbidden, notFound, unauthorized } from "../utils/errors";
import { clientIp, clientUserAgent } from "../utils/request";
import {
  validate, RegisterSchema, LoginSchema, LoginMfaSchema, RefreshSchema, ChangePasswordSchema,
  UpdateProfileSchema, MfaVerifySchema, MfaDisableSchema, IdParamSchema,
} from "../utils/validation";
import { createSession, rotateRefreshToken, revokeSession, revokeAllSessions } from "../services/session.service";
import { assertNotLocked, assertNotProtected, getUserAccess } from "../services/user.service";
import { failAttempt, verifySecondFactor } from "../services/mfa.service";
import { TRUST_CLEARED, isTrustActive, newTrustExpiry, trustView } from "../services/device.service";

const invalidCredentials = () => unauthorized("INVALID_CREDENTIALS", "Invalid email or password");

// ── Registration ────────────────────────────────────────────────
export const register = async (req: Request, res: Response): Promise<void> => {
  const body = validate(RegisterSchema, req.body);

  const strength = isStrongPassword(body.password);
  if (!strength.valid) {
    throw badRequest("WEAK_PASSWORD", "Password does not meet the requirements", { password: strength.errors });
  }

  const existing = await prisma.user.findUnique({ where: { email: body.email } });
  if (existing) throw conflict("EMAIL_EXISTS", "Email already registered");

  const defaultRole = await prisma.role.findUnique({ where: { name: "user" } });

  const user = await prisma.user.create({
    data: {
      email:             body.email,
      passwordHash:      await hashPassword(body.password),
      firstName:         body.firstName,
      lastName:          body.lastName,
      passwordChangedAt: new Date(),
      ...(defaultRole ? { roles: { create: { roleId: defaultRole.id } } } : {}),
    },
  });

  res.locals.auditUserId = user.id;
  res.locals.auditEvent  = "USER_REGISTERED";
  res.status(201).json({ message: "User registered successfully", userId: user.id });
};

// ── Login ───────────────────────────────────────────────────────

async function completeLogin(
  req: Request,
  res: Response,
  user: User,
  opts: { mfaVerified: boolean; rememberDevice: boolean },
): Promise<void> {
  const device = req.device!;
  const trust  = opts.mfaVerified && opts.rememberDevice;
  // How the second factor was handled — returned to the client and written to the audit log
  const mfa = opts.mfaVerified ? "verified" : user.mfaEnabled ? "trusted_device" : "not_enabled";

  // A device only becomes trusted after passing MFA with "remember this device",
  // and only for TRUSTED_DEVICE_DAYS (default 30)
  const dbDevice = await prisma.device.upsert({
    where:  { userId_fingerprint: { userId: user.id, fingerprint: device.fingerprint } },
    update: {
      lastUsedAt: new Date(),
      ipAddress:  device.ipAddress,
      userAgent:  device.userAgent,
      deviceName: device.name,
      ...(trust ? { isTrusted: true, trustedUntil: newTrustExpiry() } : {}),
    },
    create: {
      userId:      user.id,
      userAgent:   device.userAgent,
      ipAddress:   device.ipAddress,
      deviceName:  device.name,
      fingerprint: device.fingerprint,
      isTrusted:   trust,
      trustedUntil: trust ? newTrustExpiry() : null,
    },
  });

  const { session, refreshToken } = await createSession({
    userId:    user.id,
    deviceId:  dbDevice.id,
    ipAddress: device.ipAddress,
    userAgent: device.userAgent,
  });

  await prisma.user.update({
    where: { id: user.id },
    data:  { failedLoginAttempts: 0, lockedUntil: null, lastLoginAt: new Date() },
  });

  const accessToken = signAccessToken(user.id, user.email, session.id);

  res.locals.auditEvent = "LOGIN_SUCCESS";
  res.locals.auditDetails = { ...res.locals.auditDetails, sessionId: session.id, mfa };
  res.json({
    accessToken,
    refreshToken,
    tokenType: "Bearer",
    expiresIn: secondsUntilExpiry(accessToken),
    user: {
      id:                 user.id,
      email:              user.email,
      firstName:          user.firstName,
      lastName:           user.lastName,
      mfaEnabled:         user.mfaEnabled,
      mustChangePassword: user.mustChangePassword,
    },
    mfa,
    device: { id: dbDevice.id, name: dbDevice.deviceName, ...trustView(dbDevice) },
  });
}

export const login = async (req: Request, res: Response): Promise<void> => {
  const body   = validate(LoginSchema, req.body);
  const device = req.device!;

  const user = await prisma.user.findUnique({ where: { email: body.email } });
  if (!user) {
    await burnPasswordCheck(body.password);
    res.locals.auditEvent = "LOGIN_FAILED";
    throw invalidCredentials();
  }

  res.locals.auditUserId = user.id;

  try {
    assertNotLocked(user);
  } catch (err) {
    res.locals.auditEvent = "LOGIN_BLOCKED_LOCKED";
    throw err;
  }

  if (!(await verifyPassword(body.password, user.passwordHash))) {
    await failAttempt(res, user,"LOGIN_FAILED");
    throw invalidCredentials();
  }

  if (!user.isActive) {
    res.locals.auditEvent = "LOGIN_BLOCKED_INACTIVE";
    throw forbidden("ACCOUNT_DISABLED", "This account has been deactivated");
  }

  const knownDevice = await prisma.device.findUnique({
    where: { userId_fingerprint: { userId: user.id, fingerprint: device.fingerprint } },
  });

  // A remembered device skips the code only while its trust has not expired
  if (user.mfaEnabled && !isTrustActive(knownDevice)) {
    // Single-step: code supplied together with the password
    if (body.totp_code || body.backupCode) {
      await verifySecondFactor(res, user, { code: body.totp_code, backupCode: body.backupCode });
      return completeLogin(req, res, user, { mfaVerified: true, rememberDevice: body.rememberDevice });
    }

    // Two-step: hand out a short-lived MFA token instead of asking for the password again
    const mfaToken = signMfaToken(user.id, device.fingerprint);
    res.locals.auditEvent = "LOGIN_MFA_REQUIRED";
    res.status(202).json({
      mfaRequired: true,
      mfaToken,
      expiresIn:   secondsUntilExpiry(mfaToken),
      message:     "MFA code required. POST it with the mfaToken to /auth/login/mfa",
    });
    return;
  }

  return completeLogin(req, res, user, { mfaVerified: false, rememberDevice: false });
};

export const loginMfa = async (req: Request, res: Response): Promise<void> => {
  const body = validate(LoginMfaSchema, req.body);
  const invalidMfaToken = () => unauthorized("INVALID_MFA_TOKEN", "MFA session invalid or expired — log in again");

  let payload;
  try {
    payload = verifyToken(body.mfaToken, "mfa");
  } catch {
    throw invalidMfaToken();
  }

  // The MFA step must come from the same device that passed the password step
  if (payload.fp !== req.device!.fingerprint) throw invalidMfaToken();

  const user = await prisma.user.findUnique({ where: { id: payload.sub } });
  if (!user || !user.isActive || !user.mfaEnabled) throw invalidMfaToken();

  res.locals.auditUserId = user.id;
  assertNotLocked(user);

  await verifySecondFactor(res, user, body);
  await completeLogin(req, res, user, { mfaVerified: true, rememberDevice: body.rememberDevice });
};

// ── Tokens & sessions ───────────────────────────────────────────
export const refresh = async (req: Request, res: Response): Promise<void> => {
  const { refreshToken } = validate(RefreshSchema, req.body);

  try {
    const result = await rotateRefreshToken(refreshToken, {
      clientId:  null,
      ipAddress: clientIp(req),
      userAgent: clientUserAgent(req),
    });

    const accessToken = signAccessToken(result.user.id, result.user.email, result.session.id);
    res.locals.auditUserId = result.user.id;
    res.locals.auditEvent  = "TOKEN_REFRESHED";
    res.json({
      accessToken,
      refreshToken: result.refreshToken,
      tokenType:    "Bearer",
      expiresIn:    secondsUntilExpiry(accessToken),
    });
  } catch (err) {
    res.locals.auditEvent = err instanceof AppError && err.code === "REFRESH_TOKEN_REUSED"
      ? "REFRESH_TOKEN_REUSED"
      : "TOKEN_REFRESH_FAILED";
    throw err;
  }
};

export const logout = async (req: Request, res: Response): Promise<void> => {
  await revokeSession(req.user!.sessionId, "LOGOUT");
  res.locals.auditEvent = "LOGOUT";
  res.json({ success: true, message: "Logged out" });
};

export const logoutAll = async (req: Request, res: Response): Promise<void> => {
  const revokedSessions = await revokeAllSessions(req.user!.id, "LOGOUT_ALL");
  res.locals.auditEvent = "LOGOUT_ALL";
  res.json({ success: true, message: "All sessions signed out", revokedSessions });
};

export const listSessions = async (req: Request, res: Response): Promise<void> => {
  const sessions = await prisma.session.findMany({
    where:   { userId: req.user!.id, revokedAt: null, expiresAt: { gt: new Date() } },
    include: { device: { select: { id: true, deviceName: true, isTrusted: true, trustedUntil: true } }, client: { select: { name: true } } },
    orderBy: { lastUsedAt: "desc" },
  });

  res.json({
    sessions: sessions.map(s => ({
      id:         s.id,
      current:    s.id === req.user!.sessionId,
      type:       s.clientId ? "oidc" : "first-party",
      clientId:   s.clientId,
      clientName: s.client?.name ?? null,
      scope:      s.scope,
      device:     s.device ? { id: s.device.id, deviceName: s.device.deviceName, ...trustView(s.device) } : null,
      ipAddress:  s.ipAddress,
      userAgent:  s.userAgent,
      createdAt:  s.createdAt,
      lastUsedAt: s.lastUsedAt,
      expiresAt:  s.expiresAt,
    })),
  });
};

export const revokeSessionById = async (req: Request, res: Response): Promise<void> => {
  const { id } = validate(IdParamSchema, req.params);
  const session = await prisma.session.findFirst({ where: { id, userId: req.user!.id, revokedAt: null } });
  if (!session) throw notFound("SESSION_NOT_FOUND", "Session not found");

  await revokeSession(id, "USER_REVOKED");
  res.locals.auditEvent   = "SESSION_REVOKED";
  res.locals.auditDetails = { sessionId: id };
  res.json({ success: true, message: "Session revoked" });
};

// ── Profile ─────────────────────────────────────────────────────
export const me = async (req: Request, res: Response): Promise<void> => {
  const userId = req.user!.id;
  const [user, access, devices] = await Promise.all([
    prisma.user.findUnique({
      where:  { id: userId },
      select: {
        id: true, email: true, firstName: true, lastName: true, mfaEnabled: true, isProtected: true,
        mustChangePassword: true, lastLoginAt: true, createdAt: true,
      },
    }),
    getUserAccess(userId),
    prisma.device.findMany({
      where:   { userId },
      orderBy: { lastUsedAt: "desc" },
      select:  { id: true, deviceName: true, ipAddress: true, isTrusted: true, trustedUntil: true, lastUsedAt: true, firstUsedAt: true },
    }),
  ]);

  res.json({
    user: { ...user, ...access },
    devices: devices.map(d => ({ ...d, ...trustView(d), current: d.id === req.user!.deviceId })),
    sessionId: req.user!.sessionId,
  });
};

export const updateProfile = async (req: Request, res: Response): Promise<void> => {
  const body = validate(UpdateProfileSchema, req.body);
  assertNotProtected(req.user!);

  const user = await prisma.user.update({
    where:  { id: req.user!.id },
    data:   { firstName: body.firstName, lastName: body.lastName },
    select: { id: true, email: true, firstName: true, lastName: true },
  });

  res.locals.auditEvent = "PROFILE_UPDATED";
  res.json({ success: true, user });
};

export const changePassword = async (req: Request, res: Response): Promise<void> => {
  const body = validate(ChangePasswordSchema, req.body);
  assertNotProtected(req.user!);

  const user = await prisma.user.findUniqueOrThrow({ where: { id: req.user!.id } });
  assertNotLocked(user);

  if (!(await verifyPassword(body.currentPassword, user.passwordHash))) {
    await failAttempt(res, user,"PASSWORD_CHANGE_FAILED");
    throw unauthorized("INVALID_CREDENTIALS", "Current password is incorrect");
  }

  if (body.currentPassword === body.newPassword) {
    throw badRequest("PASSWORD_REUSE", "New password must be different from the current password");
  }

  const strength = isStrongPassword(body.newPassword);
  if (!strength.valid) {
    throw badRequest("WEAK_PASSWORD", "Password does not meet the requirements", { newPassword: strength.errors });
  }

  await prisma.user.update({
    where: { id: user.id },
    data:  {
      passwordHash:        await hashPassword(body.newPassword),
      passwordChangedAt:   new Date(),
      mustChangePassword:  false,
      failedLoginAttempts: 0,
    },
  });

  // Every other session is signed out; the current one stays logged in
  const revokedSessions = await revokeAllSessions(user.id, "PASSWORD_CHANGED", { exceptSessionId: req.user!.sessionId });
  // A new password also means every device must pass MFA again
  await prisma.device.updateMany({ where: { userId: user.id }, data: TRUST_CLEARED });

  res.locals.auditEvent = "PASSWORD_CHANGED";
  res.json({ success: true, message: "Password changed. Other sessions were signed out.", revokedSessions });
};

// ── MFA ─────────────────────────────────────────────────────────
export const setupMFA = async (req: Request, res: Response): Promise<void> => {
  assertNotProtected(req.user!);
  if (req.user!.mfaEnabled) {
    throw conflict("MFA_ALREADY_ENABLED", "MFA is already enabled. Disable it first to re-enroll.");
  }

  const { secret, qrCode, otpauthUrl, backupCodes } = await generateMFASecret(req.user!.email);

  await prisma.user.update({
    where: { id: req.user!.id },
    data:  {
      mfaSecret:         secret,
      backupCodesHashed: JSON.stringify(await hashBackupCodes(backupCodes)),
      mfaLastUsedStep:   null,
    },
  });

  res.locals.auditEvent = "MFA_SETUP_STARTED";
  res.json({
    qrCode,
    secret,
    otpauthUrl,
    backupCodes, // shown once — stored only as bcrypt hashes
    message: "Scan the QR code with your authenticator app, then call /auth/mfa/verify",
  });
};

export const verifyMFA = async (req: Request, res: Response): Promise<void> => {
  const { token } = validate(MfaVerifySchema, req.body);
  const user = await prisma.user.findUniqueOrThrow({ where: { id: req.user!.id } });

  if (user.mfaEnabled) throw conflict("MFA_ALREADY_ENABLED", "MFA is already enabled");
  if (!user.mfaSecret) throw badRequest("MFA_NOT_INITIALIZED", "Call /auth/mfa/setup first");

  const step = verifyTOTP(user.mfaSecret, token);
  if (step === null) {
    res.locals.auditEvent = "MFA_VERIFY_FAILED";
    throw badRequest("INVALID_MFA_CODE", "Invalid or expired code");
  }

  await prisma.$transaction([
    prisma.user.update({ where: { id: user.id }, data: { mfaEnabled: true, mfaLastUsedStep: step } }),
    // Every device must pass MFA once before it can be trusted again
    prisma.device.updateMany({ where: { userId: user.id }, data: TRUST_CLEARED }),
  ]);

  res.locals.auditEvent = "MFA_ENABLED";
  res.json({ success: true, message: "MFA enabled successfully" });
};

export const disableMFA = async (req: Request, res: Response): Promise<void> => {
  const body = validate(MfaDisableSchema, req.body);
  assertNotProtected(req.user!);

  const user = await prisma.user.findUniqueOrThrow({ where: { id: req.user!.id } });
  if (!user.mfaEnabled) throw badRequest("MFA_NOT_ENABLED", "MFA is not enabled");
  assertNotLocked(user);

  if (!(await verifyPassword(body.password, user.passwordHash))) {
    await failAttempt(res, user,"MFA_DISABLE_FAILED");
    throw unauthorized("INVALID_CREDENTIALS", "Password is incorrect");
  }

  await verifySecondFactor(res, user, body);

  await prisma.$transaction([
    prisma.user.update({
      where: { id: user.id },
      data:  { mfaEnabled: false, mfaSecret: null, backupCodesHashed: null, mfaLastUsedStep: null },
    }),
    prisma.device.updateMany({ where: { userId: user.id }, data: TRUST_CLEARED }),
  ]);

  res.locals.auditEvent = "MFA_DISABLED";
  res.json({ success: true, message: "MFA disabled" });
};
