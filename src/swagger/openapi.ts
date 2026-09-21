// src/swagger/openapi.ts — OpenAPI 3.0 specification (served at /swagger.json)
// No `servers` entry: Swagger UI then targets whichever host serves the docs,
// so the same spec works on localhost, Render, Docker and Vercel.
// tests/integration/docs.test.ts fails if a route is missing from this file.

type Json = Record<string, unknown>;

const ref  = (name: string): Json => ({ $ref: `#/components/schemas/${name}` });
const json = (schema: Json, example?: unknown): Json => ({
  "application/json": { schema, ...(example !== undefined ? { example } : {}) },
});
const body = (schema: Json, example?: unknown): Json => ({ required: true, content: json(schema, example) });
const ok   = (description: string, schema?: Json): Json => ({ description, ...(schema ? { content: json(schema) } : {}) });
const err  = (description: string): Json => ({ description, content: json(ref("ErrorResponse")) });
const oauthErr = (description: string): Json => ({ description, content: json(ref("OAuthError")) });

const idParam = { name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } };
const query   = (name: string, schema: Json, description?: string, required = false): Json =>
  ({ name, in: "query", required, schema, ...(description ? { description } : {}) });

const R400 = err("Validation error (`VALIDATION_ERROR`) — see `details`");
const R401 = err("Missing/invalid access token, or the session was revoked");
const R403 = err("Authenticated but missing the required permission (`FORBIDDEN`)");
const R404 = err("Resource not found");
const needs = (permission: string) => `**Requires permission:** \`${permission}\``;

const success = ref("SuccessResponse");
const PUBLIC: Json[] = [];

const str   = { type: "string" };
const bool  = { type: "boolean" };
const int   = { type: "integer" };
const uuid  = { type: "string", format: "uuid" };
const date  = { type: "string", format: "date-time" };
const nDate = { type: "string", format: "date-time", nullable: true };
const arr   = (items: Json): Json => ({ type: "array", items });
const obj   = (properties: Json, required?: string[]): Json =>
  ({ type: "object", properties, ...(required ? { required } : {}) });

export const openApiSpec = {
  openapi: "3.0.3",
  info: {
    title: "SecureAccess — Authentication, RBAC & OpenID Connect API",
    version: "3.0.0",
    description: [
      "Production-style identity backend: registration, login with account lockout, TOTP MFA with backup codes,",
      "trusted devices, rotating refresh tokens with reuse detection, permission-based RBAC, a masked audit trail,",
      "and an OpenID Connect provider (Authorization Code + PKCE).",
      "",
      "**Quick start:** call `POST /api/v1/auth/login`, copy `accessToken`, click **Authorize** and paste it.",
      "Access tokens last 15 minutes; use `POST /api/v1/auth/refresh` with the `refreshToken` for a new pair.",
      "",
      "Every error has the shape `{ error, message, details?, requestId }`. OAuth endpoints use `{ error, error_description }`.",
    ].join("\n"),
    contact: { name: "Raghul", email: "raghulraghul111@gmail.com" },
    license: { name: "MIT", url: "https://opensource.org/licenses/MIT" },
  },
  tags: [
    { name: "System",              description: "Health and metadata" },
    { name: "Authentication",      description: "Registration, login, tokens, sessions and profile" },
    { name: "MFA",                 description: "TOTP multi-factor authentication" },
    { name: "Users",               description: "User administration" },
    { name: "Roles & Permissions", description: "Role-based access control" },
    { name: "Devices",             description: "Device recognition and trust" },
    { name: "Audit Trail",         description: "Security audit log" },
    { name: "OpenID Connect",      description: "OpenID Connect provider endpoints" },
    { name: "OIDC Clients",        description: "Registered OpenID Connect clients" },
  ],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: "http", scheme: "bearer", bearerFormat: "JWT",
        description: "First-party access token (`accessToken`) from /api/v1/auth/login",
      },
      oidcAccessToken: {
        type: "http", scheme: "bearer", bearerFormat: "JWT",
        description: "RS256 `access_token` issued to an OpenID Connect client by /api/v1/openid/token",
      },
      clientBasic: {
        type: "http", scheme: "basic",
        description: "Confidential client credentials (client_secret_basic)",
      },
    },
    schemas: {
      // ── Common ────────────────────────────────────────────────
      ErrorResponse: obj({
        error:     { type: "string", example: "INVALID_CREDENTIALS" },
        message:   { type: "string", example: "Invalid email or password" },
        details:   { type: "object", additionalProperties: true },
        requestId: { type: "string", example: "3f1c2a8e-5b7d-4e8a-9c1f-2d3e4f5a6b7c" },
      }),
      OAuthError: obj({
        error:             { type: "string", example: "invalid_grant" },
        error_description: { type: "string", example: "PKCE verification failed" },
      }),
      SuccessResponse: obj({ success: { type: "boolean", example: true }, message: str }),
      Pagination: obj({
        page: { type: "integer", example: 1 }, limit: { type: "integer", example: 20 },
        total: { type: "integer", example: 42 }, totalPages: { type: "integer", example: 3 },
      }),
      Health: obj({
        status: { type: "string", enum: ["ok", "degraded"] }, database: { type: "string", enum: ["up", "down"] },
        version: str, uptimeSeconds: int, timestamp: date,
      }),

      // ── Auth ──────────────────────────────────────────────────
      RegisterRequest: obj({
        email:     { type: "string", format: "email", example: "jane@example.com" },
        password:  { type: "string", minLength: 12, maxLength: 128, example: "Str0ng!Passphrase",
          description: "12+ chars with upper, lower, digit and symbol; no 4 repeated chars; no common words" },
        firstName: { type: "string", example: "Jane" },
        lastName:  { type: "string", example: "Doe" },
      }, ["email", "password", "firstName", "lastName"]),
      RegisterResponse: obj({ message: { type: "string", example: "User registered successfully" }, userId: uuid }),
      LoginRequest: obj({
        email:          { type: "string", format: "email", example: "admin@secureaccess.dev" },
        password:       { type: "string", example: "Admin@Secure#2026" },
        totp_code:      { type: "string", pattern: "^\\d{6}$", description: "Optional single-step MFA code" },
        backupCode:     { type: "string", description: "Optional single-step backup code" },
        rememberDevice: { type: "boolean", default: false, description: "After MFA succeeds, skip the code on this device for TRUSTED_DEVICE_DAYS (default 30)" },
      }, ["email", "password"]),
      TokenPair: obj({
        accessToken:  { type: "string", description: "HS512 JWT, 15 minutes" },
        refreshToken: { type: "string", description: "Opaque `<sessionId>.<secret>`, single use (rotates)" },
        tokenType:    { type: "string", example: "Bearer" },
        expiresIn:    { type: "integer", example: 900 },
      }),
      LoginResponse: {
        allOf: [ref("TokenPair"), obj({
          user: obj({ id: uuid, email: str, firstName: str, lastName: str, mfaEnabled: bool, mustChangePassword: bool }),
          mfa: { type: "string", enum: ["verified", "trusted_device", "not_enabled"],
            description: "verified = code checked · trusted_device = no code asked because this device is remembered · not_enabled = account has no MFA" },
          device: obj({ id: uuid, name: str, isTrusted: bool, trustedUntil: nDate }),
        })],
      },
      MfaChallenge: obj({
        mfaRequired: { type: "boolean", example: true },
        mfaToken:    { type: "string", description: "5-minute token for POST /auth/login/mfa" },
        expiresIn:   { type: "integer", example: 300 },
        message:     str,
      }),
      LoginMfaRequest: obj({
        mfaToken:       str,
        code:           { type: "string", pattern: "^\\d{6}$", example: "123456" },
        backupCode:     { type: "string", example: "A1B2C3D4E5" },
        rememberDevice: { type: "boolean", default: false },
      }, ["mfaToken"]),
      RefreshRequest: obj({ refreshToken: str }, ["refreshToken"]),
      ChangePasswordRequest: obj({ currentPassword: str, newPassword: { type: "string", minLength: 12 } }, ["currentPassword", "newPassword"]),
      UpdateProfileRequest: obj({ firstName: str, lastName: str }),
      MeResponse: obj({
        user: obj({
          id: uuid, email: str, firstName: str, lastName: str, mfaEnabled: bool, isProtected: bool,
          mustChangePassword: bool, lastLoginAt: nDate, createdAt: date,
          roles:       arr({ type: "string", example: "admin" }),
          permissions: arr({ type: "string", example: "manage:*" }),
        }),
        devices: arr(obj({
          id: uuid, deviceName: str, ipAddress: str, isTrusted: bool, trustedUntil: nDate, current: bool, lastUsedAt: date, firstUsedAt: date,
        })),
        sessionId: uuid,
      }),
      Session: obj({
        id: uuid, current: bool, type: { type: "string", enum: ["first-party", "oidc"] },
        clientId: { type: "string", nullable: true }, clientName: { type: "string", nullable: true },
        scope: { type: "string", nullable: true },
        device: { ...obj({ id: uuid, deviceName: str, isTrusted: bool, trustedUntil: nDate }), nullable: true },
        ipAddress: str, userAgent: str, createdAt: date, lastUsedAt: date, expiresAt: date,
      }),

      // ── MFA ───────────────────────────────────────────────────
      MfaSetupResponse: obj({
        qrCode:      { type: "string", description: "data:image/png;base64 QR code" },
        secret:      { type: "string", example: "JBSWY3DPEHPK3PXP" },
        otpauthUrl:  str,
        backupCodes: arr({ type: "string", example: "9F2A7C1B3D" }),
        message:     str,
      }),
      MfaVerifyRequest: obj({ token: { type: "string", pattern: "^\\d{6}$", example: "123456" } }, ["token"]),
      TrustDeviceRequest: obj({
        code:       { type: "string", pattern: "^[0-9]{6}$", example: "123456", description: "Current authenticator code" },
        backupCode: { type: "string", description: "Or an unused backup code" },
      }),
      MfaDisableRequest: obj({ password: str, code: { type: "string", pattern: "^\\d{6}$" }, backupCode: str }, ["password"]),

      // ── Users ─────────────────────────────────────────────────
      UserSummary: obj({
        id: uuid, email: str, firstName: str, lastName: str, isActive: bool, isProtected: bool,
        mfaEnabled: bool, lockedUntil: nDate, mustChangePassword: bool, lastLoginAt: nDate, createdAt: date,
        roles: arr(obj({ role: obj({ id: uuid, name: str }) })),
      }),
      UserDetail: obj({
        id: uuid, email: str, firstName: str, lastName: str, isActive: bool, isProtected: bool,
        mfaEnabled: bool, failedLoginAttempts: int, lockedUntil: nDate, mustChangePassword: bool,
        passwordChangedAt: nDate, lastLoginAt: nDate, createdAt: date, updatedAt: date, activeSessions: int,
        roles:   arr(obj({ assignedAt: date, role: obj({ id: uuid, name: str }) })),
        devices: arr(obj({ id: uuid, deviceName: str, ipAddress: str, isTrusted: bool, trustedUntil: nDate, lastUsedAt: date })),
      }),
      PasswordResetResponse: obj({
        success: bool, temporaryPassword: { type: "string", example: "k8#Qm2!xVr7@pL4z" },
        revokedSessions: int, warning: str,
      }),

      // ── Roles ─────────────────────────────────────────────────
      PermissionInput: obj({
        action:   { type: "string", enum: ["create", "read", "update", "delete", "manage", "export"] },
        resource: { type: "string", example: "user", description: "user, role, user-role, audit, client — or * for all" },
      }, ["action", "resource"]),
      Permission: { allOf: [obj({ id: uuid }), ref("PermissionInput")] },
      Role: obj({
        id: uuid, name: { type: "string", example: "support" }, description: { type: "string", nullable: true },
        isSystem: bool, createdAt: date,
        permissions: arr(ref("Permission")),
        users: arr(obj({ assignedAt: date, user: obj({ id: uuid, email: str, firstName: str, lastName: str }) })),
      }),
      CreateRoleRequest: obj({
        name:        { type: "string", pattern: "^[a-z0-9][a-z0-9_-]*$", example: "support" },
        description: { type: "string", example: "Can view users" },
        permissions: arr(ref("PermissionInput")),
      }, ["name"]),
      UpdateRoleRequest: obj({ name: str, description: str, permissions: arr(ref("PermissionInput")) }),
      AssignRoleRequest: obj({ userId: uuid }, ["userId"]),

      // ── Devices ───────────────────────────────────────────────
      Device: obj({
        id: uuid, deviceName: { type: "string", example: "Apple Mac OS 14 Chrome" }, ipAddress: str,
        userAgent: str, isTrusted: bool, trustedUntil: nDate, current: bool, activeSessions: int, firstUsedAt: date, lastUsedAt: date,
      }),
      CurrentDevice: obj({
        id: { ...uuid, nullable: true }, fingerprint: str, name: str, ipAddress: str, userAgent: str,
        isKnown: bool, isTrusted: bool, trustedUntil: nDate, firstUsedAt: nDate,
      }),

      // ── Audit ─────────────────────────────────────────────────
      AuditLog: obj({
        id: uuid, userId: { ...uuid, nullable: true }, event: { type: "string", nullable: true, example: "LOGIN_SUCCESS" },
        action: { type: "string", example: "POST" }, resource: { type: "string", example: "/api/v1/auth/login" },
        statusCode: { type: "integer", example: 200 }, ipAddress: str, userAgent: str, timestamp: date,
        metadata: obj({
          requestId: str, device: str, durationMs: int, aborted: bool,
          requestBody: { type: "object", nullable: true, description: "Secrets replaced with ••••••" },
          responseSnippet: { type: "string", nullable: true }, details: { type: "object", nullable: true },
        }),
        user: { ...obj({ id: uuid, email: str, firstName: str, lastName: str }), nullable: true },
      }),
      AuditEvent: obj({
        id: uuid, timestamp: date, user: { type: "string", example: "Jane Doe (jane@example.com)" },
        event: { type: "string", nullable: true }, action: str, resource: str, ip: str, device: str,
        status: { type: "integer", nullable: true }, durationMs: { type: "integer", nullable: true },
        requestId: { type: "string", nullable: true },
        suspicious: { type: "string", nullable: true, example: "Off-hours (00:00–05:59 UTC) external access" },
      }),
      RetentionStats: obj({
        totalRecords: int, last30Days: int, failedLoginsLast24h: int, oldestRecord: nDate,
        oldestRecordAgeDays: int, configuredRetentionDays: int,
        eventCounts: { type: "object", additionalProperties: { type: "integer" }, example: { LOGIN_SUCCESS: 12 } },
        note: str,
      }),
      PurgeRequest: obj({ olderThanDays: { type: "integer", minimum: 1, maximum: 3650, example: 90 } }),

      // ── OpenID Connect ────────────────────────────────────────
      OidcDiscovery: obj({
        issuer: str, authorization_endpoint: str, token_endpoint: str, userinfo_endpoint: str,
        jwks_uri: str, revocation_endpoint: str,
        response_types_supported: arr(str), grant_types_supported: arr(str), scopes_supported: arr(str),
        code_challenge_methods_supported: arr(str), id_token_signing_alg_values_supported: arr(str),
        token_endpoint_auth_methods_supported: arr(str), claims_supported: arr(str),
      }),
      Jwks: obj({
        keys: arr(obj({ kty: { type: "string", example: "RSA" }, use: { type: "string", example: "sig" },
          alg: { type: "string", example: "RS256" }, kid: str, n: str, e: { type: "string", example: "AQAB" } })),
      }),
      ConsentDetails: obj({
        client: obj({ clientId: str, name: str, isConfidential: bool }),
        scopes: arr(obj({ name: str, description: str })),
        redirectUri: str,
      }),
      ConsentRequest: obj({
        decision: { type: "string", enum: ["allow", "deny"] },
        response_type: { type: "string", example: "code" },
        client_id: { type: "string", example: "secureaccess-demo" },
        redirect_uri: { type: "string", example: "http://localhost:4000/oauth/callback.html" },
        scope: { type: "string", example: "openid profile email offline_access" },
        state: str, nonce: str, code_challenge: str,
        code_challenge_method: { type: "string", enum: ["S256"] },
      }, ["decision", "response_type", "client_id", "redirect_uri"]),
      TokenRequest: obj({
        grant_type:    { type: "string", enum: ["authorization_code", "refresh_token"] },
        code:          { type: "string", description: "authorization_code grant" },
        redirect_uri:  { type: "string", description: "authorization_code grant — must match the authorize request" },
        code_verifier: { type: "string", description: "PKCE verifier (required for public clients)" },
        refresh_token: { type: "string", description: "refresh_token grant" },
        client_id:     str,
        client_secret: { type: "string", description: "Confidential clients using client_secret_post" },
      }, ["grant_type"]),
      TokenResponse: obj({
        access_token: str, token_type: { type: "string", example: "Bearer" }, expires_in: { type: "integer", example: 900 },
        id_token: str, scope: { type: "string", example: "openid profile email offline_access" },
        refresh_token: { type: "string", description: "Only when the offline_access scope was granted" },
      }),
      UserInfo: obj({
        sub: uuid, name: str, given_name: str, family_name: str, email: str, email_verified: bool,
      }),
      OAuthClient: obj({
        id: uuid, clientId: { type: "string", example: "client_Yp3kq9LzA0bX" }, name: str,
        redirectUris: arr({ type: "string", example: "/oauth/callback.html" }),
        isConfidential: bool, hasSecret: bool, createdAt: date,
      }),
      CreateClientRequest: obj({
        name:           { type: "string", example: "My SPA" },
        redirectUris:   arr({ type: "string", example: "https://app.example.com/callback" }),
        isConfidential: { type: "boolean", default: false },
      }, ["name", "redirectUris"]),
    },
  },
  security: [{ bearerAuth: [] }],
  paths: {
    // ── System ──────────────────────────────────────────────────
    "/health": {
      get: {
        tags: ["System"], summary: "Liveness + database check", operationId: "health", security: PUBLIC,
        responses: { 200: ok("Healthy", ref("Health")), 503: ok("Database unreachable", ref("Health")) },
      },
    },

    // ── Authentication ──────────────────────────────────────────
    "/api/v1/auth/register": {
      post: {
        tags: ["Authentication"], summary: "Register a new user", operationId: "register", security: PUBLIC,
        description: "Creates the account and assigns the default `user` role.",
        requestBody: body(ref("RegisterRequest")),
        responses: {
          201: ok("Registered", ref("RegisterResponse")),
          400: err("`VALIDATION_ERROR` or `WEAK_PASSWORD`"),
          409: err("`EMAIL_EXISTS`"),
          429: err("Too many failed attempts"),
        },
      },
    },
    "/api/v1/auth/login": {
      post: {
        tags: ["Authentication"], summary: "Log in with email and password", operationId: "login", security: PUBLIC,
        description: [
          "- **200** — tokens issued.",
          "- **202** — MFA is enabled and this device is not trusted: send the `mfaToken` + code to `/auth/login/mfa`",
          "  (or include `totp_code`/`backupCode` in this request).",
          `- After ${5} failed password/MFA attempts the account is locked for 15 minutes (**423**).`,
        ].join("\n"),
        requestBody: body(ref("LoginRequest")),
        responses: {
          200: ok("Logged in", ref("LoginResponse")),
          202: ok("MFA required", ref("MfaChallenge")),
          400: R400,
          401: err("`INVALID_CREDENTIALS` or `INVALID_MFA`"),
          403: err("`ACCOUNT_DISABLED`"),
          423: err("`ACCOUNT_LOCKED` — `details.lockedUntil`"),
          429: err("Too many failed attempts"),
        },
      },
    },
    "/api/v1/auth/login/mfa": {
      post: {
        tags: ["Authentication", "MFA"], summary: "Complete login with a TOTP or backup code", operationId: "loginMfa",
        security: PUBLIC,
        requestBody: body(ref("LoginMfaRequest")),
        responses: {
          200: ok("Logged in", ref("LoginResponse")),
          400: R400,
          401: err("`INVALID_MFA_TOKEN` or `INVALID_MFA`"),
          423: err("`ACCOUNT_LOCKED`"),
        },
      },
    },
    "/api/v1/auth/refresh": {
      post: {
        tags: ["Authentication"], summary: "Rotate the refresh token and get a new access token", operationId: "refresh",
        security: PUBLIC,
        description: "Each refresh token works once. Re-using an old one revokes the whole session (`REFRESH_TOKEN_REUSED`).",
        requestBody: body(ref("RefreshRequest")),
        responses: {
          200: ok("New token pair", ref("TokenPair")),
          401: err("`INVALID_REFRESH_TOKEN` or `REFRESH_TOKEN_REUSED`"),
        },
      },
    },
    "/api/v1/auth/logout": {
      post: {
        tags: ["Authentication"], summary: "Revoke the current session", operationId: "logout",
        responses: { 200: ok("Logged out", success), 401: R401 },
      },
    },
    "/api/v1/auth/logout-all": {
      post: {
        tags: ["Authentication"], summary: "Revoke every session of the current user", operationId: "logoutAll",
        responses: {
          200: ok("All sessions revoked", { allOf: [success, obj({ revokedSessions: int })] }),
          401: R401,
        },
      },
    },
    "/api/v1/auth/me": {
      get: {
        tags: ["Authentication"], summary: "Current user, roles, permissions and devices", operationId: "me",
        responses: { 200: ok("Profile", ref("MeResponse")), 401: R401 },
      },
      patch: {
        tags: ["Authentication"], summary: "Update first/last name", operationId: "updateProfile",
        requestBody: body(ref("UpdateProfileRequest")),
        responses: {
          200: ok("Updated", obj({ success: bool, user: obj({ id: uuid, email: str, firstName: str, lastName: str }) })),
          400: R400, 401: R401, 403: err("`PROTECTED_ACCOUNT`"),
        },
      },
    },
    "/api/v1/auth/change-password": {
      post: {
        tags: ["Authentication"], summary: "Change password (signs out other sessions)", operationId: "changePassword",
        requestBody: body(ref("ChangePasswordRequest")),
        responses: {
          200: ok("Changed", { allOf: [success, obj({ revokedSessions: int })] }),
          400: err("`WEAK_PASSWORD`, `PASSWORD_REUSE` or `VALIDATION_ERROR`"),
          401: err("`INVALID_CREDENTIALS` — current password wrong"),
          403: err("`PROTECTED_ACCOUNT`"),
          423: err("`ACCOUNT_LOCKED`"),
        },
      },
    },
    "/api/v1/auth/sessions": {
      get: {
        tags: ["Authentication"], summary: "List active sessions", operationId: "listSessions",
        responses: { 200: ok("Sessions", obj({ sessions: arr(ref("Session")) })), 401: R401 },
      },
    },
    "/api/v1/auth/sessions/{id}": {
      delete: {
        tags: ["Authentication"], summary: "Revoke one of your sessions", operationId: "revokeSession",
        parameters: [idParam],
        responses: { 200: ok("Revoked", success), 401: R401, 404: err("`SESSION_NOT_FOUND`") },
      },
    },

    // ── MFA ─────────────────────────────────────────────────────
    "/api/v1/auth/mfa/setup": {
      post: {
        tags: ["MFA"], summary: "Start MFA enrolment (QR code + backup codes)", operationId: "mfaSetup",
        description: "Backup codes are shown once and stored only as bcrypt hashes. MFA is not active until `/mfa/verify`.",
        responses: {
          200: ok("Enrolment started", ref("MfaSetupResponse")),
          401: R401, 403: err("`PROTECTED_ACCOUNT`"), 409: err("`MFA_ALREADY_ENABLED`"),
        },
      },
    },
    "/api/v1/auth/mfa/verify": {
      post: {
        tags: ["MFA"], summary: "Confirm enrolment with the first code", operationId: "mfaVerify",
        description: "Enables MFA and resets trust on all devices.",
        requestBody: body(ref("MfaVerifyRequest")),
        responses: {
          200: ok("MFA enabled", success),
          400: err("`INVALID_MFA_CODE` or `MFA_NOT_INITIALIZED`"),
          401: R401, 409: err("`MFA_ALREADY_ENABLED`"),
        },
      },
    },
    "/api/v1/auth/mfa/disable": {
      post: {
        tags: ["MFA"], summary: "Disable MFA (password + code required)", operationId: "mfaDisable",
        requestBody: body(ref("MfaDisableRequest")),
        responses: {
          200: ok("MFA disabled", success),
          400: err("`MFA_NOT_ENABLED` or `VALIDATION_ERROR`"),
          401: err("`INVALID_CREDENTIALS` or `INVALID_MFA`"),
          403: err("`PROTECTED_ACCOUNT`"),
        },
      },
    },

    // ── Users ───────────────────────────────────────────────────
    "/api/v1/users": {
      get: {
        tags: ["Users"], summary: "List users", operationId: "listUsers", description: needs("read:user"),
        parameters: [
          query("page", { type: "integer", default: 1 }),
          query("limit", { type: "integer", default: 20, maximum: 100 }),
          query("search", str, "Matches email, first or last name"),
          query("status", { type: "string", enum: ["active", "inactive"] }),
        ],
        responses: {
          200: ok("Users", obj({ data: arr(ref("UserSummary")), pagination: ref("Pagination") })),
          400: R400, 401: R401, 403: R403,
        },
      },
    },
    "/api/v1/users/{id}": {
      get: {
        tags: ["Users"], summary: "Get a user", operationId: "getUser", description: needs("read:user"),
        parameters: [idParam],
        responses: { 200: ok("User", ref("UserDetail")), 401: R401, 403: R403, 404: R404 },
      },
      delete: {
        tags: ["Users"], summary: "Delete a user", operationId: "deleteUser", description: needs("delete:user"),
        parameters: [idParam],
        responses: {
          200: ok("Deleted", success), 400: err("`CANNOT_MODIFY_SELF`"), 401: R401,
          403: err("`FORBIDDEN` or `PROTECTED_ACCOUNT`"), 404: R404,
        },
      },
    },
    "/api/v1/users/{id}/deactivate": {
      post: {
        tags: ["Users"], summary: "Deactivate a user (revokes all sessions)", operationId: "deactivateUser",
        description: needs("update:user"), parameters: [idParam],
        responses: {
          200: ok("Deactivated", { allOf: [success, obj({ revokedSessions: int })] }),
          400: err("`CANNOT_MODIFY_SELF`"), 401: R401, 403: err("`FORBIDDEN` or `PROTECTED_ACCOUNT`"), 404: R404,
        },
      },
    },
    "/api/v1/users/{id}/activate": {
      post: {
        tags: ["Users"], summary: "Activate a user and clear any lockout", operationId: "activateUser",
        description: needs("update:user"), parameters: [idParam],
        responses: { 200: ok("Activated", success), 401: R401, 403: R403, 404: R404 },
      },
    },
    "/api/v1/users/{id}/reset-password": {
      post: {
        tags: ["Users"], summary: "Issue a temporary password", operationId: "resetPassword",
        description: `${needs("manage:user")}\n\nRevokes the user's sessions and sets \`mustChangePassword\`.`,
        parameters: [idParam],
        responses: {
          200: ok("Temporary password (shown once)", ref("PasswordResetResponse")),
          401: R401, 403: err("`FORBIDDEN` or `PROTECTED_ACCOUNT`"), 404: R404,
        },
      },
    },

    // ── Roles ───────────────────────────────────────────────────
    "/api/v1/roles": {
      get: {
        tags: ["Roles & Permissions"], summary: "List roles", operationId: "listRoles", description: needs("read:role"),
        responses: { 200: ok("Roles", arr(ref("Role"))), 401: R401, 403: R403 },
      },
      post: {
        tags: ["Roles & Permissions"], summary: "Create a role", operationId: "createRole",
        description: `${needs("create:role")}\n\n\`manage\` implies every action; resource \`*\` matches every resource.`,
        requestBody: body(ref("CreateRoleRequest"), {
          name: "support", description: "Read-only user support",
          permissions: [{ action: "read", resource: "user" }, { action: "read", resource: "audit" }],
        }),
        responses: { 201: ok("Created", ref("Role")), 400: R400, 401: R401, 403: R403, 409: err("`ROLE_EXISTS`") },
      },
    },
    "/api/v1/roles/{id}": {
      get: {
        tags: ["Roles & Permissions"], summary: "Get a role", operationId: "getRole", description: needs("read:role"),
        parameters: [idParam],
        responses: { 200: ok("Role", ref("Role")), 401: R401, 403: R403, 404: R404 },
      },
      put: {
        tags: ["Roles & Permissions"], summary: "Update a role (permissions are replaced)", operationId: "updateRole",
        description: `${needs("update:role")}\n\nSystem roles (admin, auditor, user) only accept description changes.`,
        parameters: [idParam],
        requestBody: body(ref("UpdateRoleRequest")),
        responses: {
          200: ok("Updated", ref("Role")), 400: R400, 401: R401,
          403: err("`FORBIDDEN` or `SYSTEM_ROLE`"), 404: R404, 409: err("`ROLE_NAME_TAKEN`"),
        },
      },
      delete: {
        tags: ["Roles & Permissions"], summary: "Delete a role", operationId: "deleteRole", description: needs("delete:role"),
        parameters: [idParam],
        responses: { 200: ok("Deleted", success), 401: R401, 403: err("`FORBIDDEN` or `SYSTEM_ROLE`"), 404: R404 },
      },
    },
    "/api/v1/roles/{id}/assign": {
      post: {
        tags: ["Roles & Permissions"], summary: "Assign a role to a user", operationId: "assignRole",
        description: needs("manage:user-role"), parameters: [idParam],
        requestBody: body(ref("AssignRoleRequest")),
        responses: {
          200: ok("Assigned", success), 400: R400, 401: R401,
          403: err("`FORBIDDEN` or `PROTECTED_ACCOUNT`"), 404: err("`ROLE_NOT_FOUND` or `USER_NOT_FOUND`"),
        },
      },
    },
    "/api/v1/roles/{id}/revoke": {
      post: {
        tags: ["Roles & Permissions"], summary: "Revoke a role from a user", operationId: "revokeRole",
        description: needs("manage:user-role"), parameters: [idParam],
        requestBody: body(ref("AssignRoleRequest")),
        responses: {
          200: ok("Revoked", success), 400: R400, 401: R401, 403: err("`FORBIDDEN` or `PROTECTED_ACCOUNT`"),
          404: err("`ROLE_NOT_FOUND`, `USER_NOT_FOUND` or `ROLE_NOT_ASSIGNED`"), 409: err("`LAST_ADMIN`"),
        },
      },
    },

    // ── Devices ─────────────────────────────────────────────────
    "/api/v1/devices": {
      get: {
        tags: ["Devices"], summary: "List your devices", operationId: "listDevices",
        responses: { 200: ok("Devices", obj({ devices: arr(ref("Device")) })), 401: R401 },
      },
    },
    "/api/v1/devices/current": {
      get: {
        tags: ["Devices"], summary: "Describe the calling device", operationId: "currentDevice",
        responses: { 200: ok("Current device", obj({ currentDevice: ref("CurrentDevice") })), 401: R401 },
      },
    },
    "/api/v1/devices/{id}/trust": {
      post: {
        tags: ["Devices"], summary: "Remember a device (skip the MFA code there)", operationId: "trustDevice", parameters: [idParam],
        description: "Requires MFA to be enabled **and** a current authenticator code or unused backup code. Trust lasts `TRUSTED_DEVICE_DAYS` (default 30) and is cleared when MFA is enabled or disabled and when the password changes.",
        requestBody: body(ref("TrustDeviceRequest")),
        responses: {
          200: ok("Trusted", obj({ success: bool, message: str, trustedUntil: date })),
          400: err("`MFA_NOT_ENABLED`, or `VALIDATION_ERROR` when no code is given"),
          401: err("`INVALID_MFA` (wrong or reused code) or missing token"),
          404: err("`DEVICE_NOT_FOUND`"),
          423: err("`ACCOUNT_LOCKED`"),
        },
      },
    },
    "/api/v1/devices/{id}/revoke": {
      post: {
        tags: ["Devices"], summary: "Remove trust from a device", operationId: "untrustDevice", parameters: [idParam],
        responses: { 200: ok("Trust revoked", success), 401: R401, 404: err("`DEVICE_NOT_FOUND`") },
      },
    },
    "/api/v1/devices/{id}": {
      delete: {
        tags: ["Devices"], summary: "Forget a device and sign out its sessions", operationId: "deleteDevice",
        parameters: [idParam],
        responses: {
          200: ok("Removed", { allOf: [success, obj({ revokedSessions: int })] }),
          401: R401, 404: err("`DEVICE_NOT_FOUND`"),
        },
      },
    },

    // ── Audit ───────────────────────────────────────────────────
    "/api/v1/audit": {
      get: {
        tags: ["Audit Trail"], summary: "Paginated audit log", operationId: "listAuditLogs", description: needs("read:audit"),
        parameters: [
          query("page", { type: "integer", default: 1 }),
          query("limit", { type: "integer", default: 50, maximum: 500 }),
          query("userId", uuid), query("event", { type: "string", example: "LOGIN_FAILED" }),
          query("action", { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE"] }),
          query("resource", { type: "string", example: "/auth/login" }), query("ipAddress", str),
          query("statusCode", int), query("startDate", date), query("endDate", date),
        ],
        responses: {
          200: ok("Audit rows", obj({ data: arr(ref("AuditLog")), pagination: ref("Pagination") })),
          400: R400, 401: R401, 403: R403,
        },
      },
    },
    "/api/v1/audit/events": {
      get: {
        tags: ["Audit Trail"], summary: "Search events (flattened, with suspicious-activity flag)", operationId: "searchAuditEvents",
        description: needs("read:audit"),
        parameters: [
          query("userId", uuid), query("email", str, "Partial, case-insensitive"), query("event", str),
          query("action", str), query("resource", str), query("ip", str), query("status", int),
          query("before", date), query("after", date),
          query("sensitive", { type: "string", enum: ["true", "false"] }, "Only logins, MFA, password and role changes"),
          query("limit", { type: "integer", default: 200, maximum: 1000 }),
        ],
        responses: {
          200: ok("Events", obj({ total: int, events: arr(ref("AuditEvent")) })),
          400: R400, 401: R401, 403: R403,
        },
      },
    },
    "/api/v1/audit/retention": {
      get: {
        tags: ["Audit Trail"], summary: "Audit statistics", operationId: "auditRetention", description: needs("read:audit"),
        responses: { 200: ok("Statistics", ref("RetentionStats")), 401: R401, 403: R403 },
      },
    },
    "/api/v1/audit/export": {
      post: {
        tags: ["Audit Trail"], summary: "Download up to 10,000 rows as CSV", operationId: "exportAuditLogs",
        description: `${needs("export:audit")}\n\nAccepts the same query filters as \`GET /audit\`. Cells are escaped against formula injection.`,
        parameters: [query("event", str), query("userId", uuid), query("startDate", date), query("endDate", date)],
        responses: {
          200: { description: "CSV file", content: { "text/csv": { schema: { type: "string", format: "binary" } } } },
          401: R401, 403: R403,
        },
      },
    },
    "/api/v1/audit/purge": {
      post: {
        tags: ["Audit Trail"], summary: "Delete audit rows older than N days", operationId: "purgeAuditLogs",
        description: `${needs("manage:audit")}\n\nDefaults to \`AUDIT_RETENTION_DAYS\`.`,
        requestBody: { required: false, content: json(ref("PurgeRequest")) },
        responses: {
          200: ok("Purged", obj({ success: bool, deleted: int, cutoff: date })),
          400: R400, 401: R401, 403: R403,
        },
      },
    },

    // ── OpenID Connect ──────────────────────────────────────────
    "/.well-known/openid-configuration": {
      get: {
        tags: ["OpenID Connect"], summary: "Discovery document (issuer root)", operationId: "oidcDiscovery", security: PUBLIC,
        responses: { 200: ok("Provider metadata", ref("OidcDiscovery")) },
      },
    },
    "/api/v1/openid/.well-known/openid-configuration": {
      get: {
        tags: ["OpenID Connect"], summary: "Discovery document (API path alias)", operationId: "oidcDiscoveryAlias", security: PUBLIC,
        responses: { 200: ok("Provider metadata", ref("OidcDiscovery")) },
      },
    },
    "/api/v1/openid/jwks": {
      get: {
        tags: ["OpenID Connect"], summary: "Public signing keys (JWKS)", operationId: "oidcJwks", security: PUBLIC,
        responses: { 200: ok("JSON Web Key Set", ref("Jwks")) },
      },
    },
    "/api/v1/openid/authorize": {
      get: {
        tags: ["OpenID Connect"], summary: "Authorization endpoint (browser redirect)", operationId: "oidcAuthorize", security: PUBLIC,
        description: "Validates the request and redirects to the consent page, where the user logs in and approves. Public clients must use PKCE (S256).",
        parameters: [
          query("response_type", { type: "string", enum: ["code"] }, undefined, true),
          query("client_id", { type: "string", example: "secureaccess-demo" }, undefined, true),
          query("redirect_uri", { type: "string", example: "http://localhost:4000/oauth/callback.html" }, undefined, true),
          query("scope", { type: "string", example: "openid profile email" }, "Must include openid"),
          query("state", str, "Opaque CSRF value echoed back"),
          query("nonce", str, "Echoed in the id_token"),
          query("code_challenge", str, "BASE64URL(SHA256(code_verifier))"),
          query("code_challenge_method", { type: "string", enum: ["S256"] }),
        ],
        responses: {
          302: { description: "Redirect to the consent page, or to redirect_uri with an `error`" },
          400: oauthErr("Unknown client or unregistered redirect_uri (never redirected)"),
        },
      },
    },
    "/api/v1/openid/consent": {
      get: {
        tags: ["OpenID Connect"], summary: "Details for the consent screen", operationId: "oidcConsentDetails", security: PUBLIC,
        parameters: [
          query("response_type", str, undefined, true), query("client_id", str, undefined, true),
          query("redirect_uri", str, undefined, true), query("scope", str),
          query("code_challenge", str), query("code_challenge_method", str),
        ],
        responses: { 200: ok("Client and requested scopes", ref("ConsentDetails")), 400: oauthErr("Invalid request") },
      },
      post: {
        tags: ["OpenID Connect"], summary: "Approve or deny (signed-in user)", operationId: "oidcConsent",
        description: "Returns the URL the browser must navigate to: `redirect_uri?code=…&state=…&iss=…` or `?error=access_denied`.",
        requestBody: body(ref("ConsentRequest")),
        responses: {
          200: ok("Next browser location", obj({ redirectTo: str })),
          400: oauthErr("Invalid request"), 401: R401,
        },
      },
    },
    "/api/v1/openid/token": {
      post: {
        tags: ["OpenID Connect"], summary: "Token endpoint", operationId: "oidcToken",
        security: [{ clientBasic: [] }, {}],
        description: "`authorization_code` (with PKCE `code_verifier`) or `refresh_token`. Codes are single-use and expire after 120 seconds; replaying one revokes the tokens it produced.",
        requestBody: {
          required: true,
          content: {
            "application/x-www-form-urlencoded": { schema: ref("TokenRequest") },
            "application/json": { schema: ref("TokenRequest") },
          },
        },
        responses: {
          200: ok("Tokens", ref("TokenResponse")),
          400: oauthErr("`invalid_request`, `invalid_grant` or `unsupported_grant_type`"),
          401: oauthErr("`invalid_client`"),
        },
      },
    },
    "/api/v1/openid/userinfo": {
      get: {
        tags: ["OpenID Connect"], summary: "Claims about the signed-in user", operationId: "oidcUserinfo",
        security: [{ oidcAccessToken: [] }],
        responses: {
          200: ok("Claims released by the granted scopes", ref("UserInfo")),
          401: oauthErr("`invalid_token`"), 403: oauthErr("`insufficient_scope`"),
        },
      },
    },
    "/api/v1/openid/revoke": {
      post: {
        tags: ["OpenID Connect"], summary: "Revoke an access or refresh token (RFC 7009)", operationId: "oidcRevoke",
        security: [{ clientBasic: [] }, {}],
        requestBody: {
          required: true,
          content: {
            "application/x-www-form-urlencoded": { schema: obj({ token: str, client_id: str, client_secret: str }, ["token"]) },
          },
        },
        responses: { 200: ok("Always 200, even for unknown tokens", success), 401: oauthErr("`invalid_client`") },
      },
    },

    // ── OIDC client registry ────────────────────────────────────
    "/api/v1/openid/clients": {
      get: {
        tags: ["OIDC Clients"], summary: "List registered clients", operationId: "listClients", description: needs("read:client"),
        responses: { 200: ok("Clients", obj({ clients: arr(ref("OAuthClient")) })), 401: R401, 403: R403 },
      },
      post: {
        tags: ["OIDC Clients"], summary: "Register a client", operationId: "createClient",
        description: `${needs("create:client")}\n\nConfidential clients receive a \`clientSecret\` exactly once. Redirect URIs may be absolute or a path such as \`/oauth/callback.html\`.`,
        requestBody: body(ref("CreateClientRequest")),
        responses: {
          201: ok("Created", { allOf: [ref("OAuthClient"), obj({ clientSecret: str, warning: str })] }),
          400: R400, 401: R401, 403: R403,
        },
      },
    },
    "/api/v1/openid/clients/{id}": {
      delete: {
        tags: ["OIDC Clients"], summary: "Delete a client (revokes its sessions)", operationId: "deleteClient",
        description: needs("delete:client"), parameters: [idParam],
        responses: { 200: ok("Deleted", success), 401: R401, 403: R403, 404: err("`CLIENT_NOT_FOUND`") },
      },
    },
  },
};
