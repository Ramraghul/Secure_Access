// Shared helpers for integration tests (real Express app + real PostgreSQL)
import request from "supertest";
import speakeasy from "speakeasy";
import { app } from "../../src/app";
import { prisma } from "../../src/lib/prisma";
import { flushAuditLogs } from "../../src/middleware/audit.middleware";
import { DEFAULT_ADMIN_EMAIL, DEFAULT_ADMIN_PASSWORD, DEMO_ACCOUNTS, DEMO_CLIENT } from "../../src/db/seed";

export { prisma, DEMO_ACCOUNTS, DEMO_CLIENT };

export const api = () => request(app);

export const STRONG_PASSWORD = "Str0ng!Passphrase#1";
export const BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";

export const bearer = (token: string) => ({ Authorization: `Bearer ${token}` });

export const uniqueEmail = (prefix = "user") =>
  `${prefix}.${Date.now()}.${Math.random().toString(36).slice(2, 8)}@test.dev`;

export async function registerUser(overrides: Record<string, unknown> = {}) {
  const email = uniqueEmail();
  const res = await api()
    .post("/api/v1/auth/register")
    .send({ email, password: STRONG_PASSWORD, firstName: "Test", lastName: "User", ...overrides });
  if (res.status !== 201) throw new Error(`register failed: ${res.status} ${JSON.stringify(res.body)}`);
  return { email: (overrides.email as string) ?? email, password: (overrides.password as string) ?? STRONG_PASSWORD, userId: res.body.userId as string };
}

export const login = (email: string, password: string, extra: Record<string, unknown> = {}, userAgent = BROWSER_UA) =>
  api().post("/api/v1/auth/login").set("User-Agent", userAgent).send({ email, password, ...extra });

export interface TestSession {
  email: string;
  password: string;
  userId: string;
  accessToken: string;
  refreshToken: string;
}

export async function loginOk(email: string, password: string, userAgent = BROWSER_UA): Promise<TestSession> {
  const res = await login(email, password, {}, userAgent);
  if (res.status !== 200) throw new Error(`login failed: ${res.status} ${JSON.stringify(res.body)}`);
  return { email, password, userId: res.body.user.id, accessToken: res.body.accessToken, refreshToken: res.body.refreshToken };
}

export async function createUserSession(): Promise<TestSession> {
  const { email, password } = await registerUser();
  return loginOk(email, password);
}

export const loginAdmin = () => loginOk(DEFAULT_ADMIN_EMAIL, DEFAULT_ADMIN_PASSWORD);

export const loginDemo = (role: "auditor" | "user") => {
  const account = DEMO_ACCOUNTS.find(a => a.role === role)!;
  return loginOk(account.email, account.password);
};

export const totpCode = (secret: string, secondsOffset = 0) =>
  speakeasy.totp({ secret, encoding: "base32", time: Math.floor(Date.now() / 1000) + secondsOffset });

// Replay protection rejects a second use of the same 30-second code. Tests that need
// several MFA steps in quick succession clear the marker explicitly with this helper.
export async function freshTotp(userId: string, secret: string): Promise<string> {
  await prisma.user.update({ where: { id: userId }, data: { mfaLastUsedStep: null } });
  return totpCode(secret);
}

// Enrols MFA for a session's user and returns the secret + backup codes
export async function enableMfa(session: TestSession) {
  const setup = await api().post("/api/v1/auth/mfa/setup").set(bearer(session.accessToken));
  if (setup.status !== 200) throw new Error(`mfa setup failed: ${setup.status}`);
  const verify = await api()
    .post("/api/v1/auth/mfa/verify")
    .set(bearer(session.accessToken))
    .send({ token: totpCode(setup.body.secret) });
  if (verify.status !== 200) throw new Error(`mfa verify failed: ${verify.status} ${JSON.stringify(verify.body)}`);
  return { secret: setup.body.secret as string, backupCodes: setup.body.backupCodes as string[] };
}

export async function closeAll(): Promise<void> {
  await flushAuditLogs();
  await prisma.$disconnect();
}
