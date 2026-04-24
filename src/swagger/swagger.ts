export const swaggerDefinition = {
  openapi: "3.0.3",
  info: {
    title: "SecureAccess — Enterprise Auth & RBAC API",
    version: "2.0.0",
    description: "Production-grade authentication system: JWT, MFA (TOTP), RBAC, device trust, audit trail, OpenID Connect.",
    contact: { name: "Raghul", email: "raghulraghul111@gmail.com" },
    license: { name: "MIT", url: "https://opensource.org/licenses/MIT" },
  },
  servers: [
    { url: "http://localhost:4000/api/v1", description: "Local Development" },
    { url: "https://api.secureaccess.ca/v1", description: "Production" },
  ],
  tags: [
    { name: "Authentication", description: "User registration, login, MFA, and profile management" },
    { name: "Users", description: "User management and administration" },
    { name: "Roles & Permissions", description: "Role-based access control (RBAC)" },
    { name: "Devices", description: "Device trust and management" },
    { name: "Audit Trail", description: "Security audit logging and compliance" },
    { name: "OpenID Connect", description: "OAuth 2.0 / OpenID Connect endpoints" },
  ],
  components: {
    securitySchemes: {
      bearerAuth: { 
        type: "http", 
        scheme: "bearer", 
        bearerFormat: "JWT",
        description: "JWT token obtained from /auth/login"
      },
    },
    schemas: {
      // ═══════════════════════════════════════════════════════════
      // ───────────────── COMMON SCHEMAS ─────────────────────────
      // ═══════════════════════════════════════════════════════════
      ErrorResponse: {
        type: "object",
        properties: {
          error: { type: "string", example: "INVALID_CREDENTIALS" },
          message: { type: "string", example: "Invalid email or password" },
          details: { type: "object" },
        },
      },
      PaginationInfo: {
        type: "object",
        properties: {
          page: { type: "integer", example: 1 },
          limit: { type: "integer", example: 20 },
          total: { type: "integer", example: 150 },
          totalPages: { type: "integer", example: 8 },
        },
      },
      
      // ═══════════════════════════════════════════════════════════
      // ───────────────── AUTH SCHEMAS ───────────────────────────
      // ═══════════════════════════════════════════════════════════
      RegisterRequest: {
        type: "object",
        required: ["email", "password", "firstName", "lastName"],
        properties: {
          email: { type: "string", format: "email", example: "user@example.com" },
          password: { 
            type: "string", 
            minLength: 12, 
            example: "SecureP@ssw0rd123",
            description: "Minimum 12 characters, must contain uppercase, lowercase, numbers, special chars"
          },
          firstName: { type: "string", example: "John" },
          lastName: { type: "string", example: "Doe" },
        },
      },
      RegisterResponse: {
        type: "object",
        properties: {
          message: { type: "string", example: "User registered successfully" },
          userId: { type: "string", format: "uuid" },
        },
      },
      LoginRequest: {
        type: "object",
        required: ["email", "password"],
        properties: {
          email: { type: "string", format: "email", example: "user@example.com" },
          password: { type: "string", example: "SecureP@ssw0rd123" },
          totp_code: { 
            type: "string", 
            example: "123456",
            description: "6-digit TOTP code (required if MFA is enabled and device not trusted)"
          },
        },
      },
      LoginResponse: {
        type: "object",
        properties: {
          token: { type: "string", example: "eyJhbGciOiJIUzI1NiIs..." },
          refreshToken: { type: "string" },
          user: {
            type: "object",
            properties: {
              id: { type: "string", format: "uuid" },
              email: { type: "string" },
              mfaEnabled: { type: "boolean" },
            },
          },
        },
      },
      MFASetupResponse: {
        type: "object",
        properties: {
          qrCode: { type: "string", description: "Base64-encoded QR code image" },
          secret: { type: "string", example: "JBSWY3DPEBLW64TMMQ" },
          backupCodes: { 
            type: "array",
            items: { type: "string" },
            example: ["ABC12345", "DEF67890"]
          },
          message: { type: "string" },
        },
      },
      MFAVerifyRequest: {
        type: "object",
        required: ["token"],
        properties: {
          token: { type: "string", pattern: "^\\d{6}$", example: "123456" },
        },
      },
      UserProfile: {
        type: "object",
        properties: {
          id: { type: "string", format: "uuid" },
          email: { type: "string" },
          firstName: { type: "string" },
          lastName: { type: "string" },
          mfaEnabled: { type: "boolean" },
          createdAt: { type: "string", format: "date-time" },
          devices: {
            type: "array",
            items: {
              type: "object",
              properties: {
                id: { type: "string" },
                deviceName: { type: "string" },
                ipAddress: { type: "string" },
                isTrusted: { type: "boolean" },
                lastUsedAt: { type: "string", format: "date-time" },
                firstUsedAt: { type: "string", format: "date-time" },
              },
            },
          },
        },
      },

      // ═══════════════════════════════════════════════════════════
      // ───────────────── USER SCHEMAS ───────────────────────────
      // ═══════════════════════════════════════════════════════════
      User: {
        type: "object",
        properties: {
          id: { type: "string", format: "uuid" },
          email: { type: "string", format: "email" },
          firstName: { type: "string" },
          lastName: { type: "string" },
          isActive: { type: "boolean" },
          mfaEnabled: { type: "boolean" },
          createdAt: { type: "string", format: "date-time" },
          roles: {
            type: "array",
            items: {
              type: "object",
              properties: {
                role: {
                  type: "object",
                  properties: {
                    id: { type: "string" },
                    name: { type: "string" },
                  },
                },
              },
            },
          },
        },
      },
      UserWithDevices: {
        type: "object",
        properties: {
          id: { type: "string", format: "uuid" },
          email: { type: "string" },
          firstName: { type: "string" },
          lastName: { type: "string" },
          isActive: { type: "boolean" },
          mfaEnabled: { type: "boolean" },
          createdAt: { type: "string", format: "date-time" },
          roles: { type: "array" },
          devices: {
            type: "array",
            items: {
              type: "object",
              properties: {
                id: { type: "string" },
                deviceName: { type: "string" },
                ipAddress: { type: "string" },
                isTrusted: { type: "boolean" },
                lastUsedAt: { type: "string", format: "date-time" },
              },
            },
          },
        },
      },
      PasswordResetResponse: {
        type: "object",
        properties: {
          success: { type: "boolean", example: true },
          temporaryPassword: { type: "string", example: "Temp@Pass123456" },
          warning: { type: "string", example: "Shown once only — send via secure channel" },
        },
      },

      // ═══════════════════════════════════════════════════════════
      // ───────────────── ROLE SCHEMAS ───────────────────────────
      // ═══════════════════════════════════════════════════════════
      Permission: {
        type: "object",
        properties: {
          id: { type: "string" },
          action: { type: "string", enum: ["create", "read", "update", "delete", "manage", "export"] },
          resource: { type: "string", example: "user" },
        },
      },
      CreateRoleRequest: {
        type: "object",
        required: ["name"],
        properties: {
          name: { type: "string", maxLength: 50, example: "Admin" },
          description: { type: "string", maxLength: 255, example: "Full system access" },
          permissions: {
            type: "array",
            items: {
              type: "object",
              required: ["action", "resource"],
              properties: {
                action: { type: "string", enum: ["create", "read", "update", "delete", "manage", "export"] },
                resource: { type: "string", example: "user" },
              },
            },
          },
        },
      },
      Role: {
        type: "object",
        properties: {
          id: { type: "string" },
          name: { type: "string" },
          description: { type: "string" },
          createdAt: { type: "string", format: "date-time" },
          permissions: { type: "array", items: { $ref: "#/components/schemas/Permission" } },
          users: {
            type: "array",
            items: {
              type: "object",
              properties: {
                user: { $ref: "#/components/schemas/User" },
              },
            },
          },
        },
      },
      AssignRoleRequest: {
        type: "object",
        required: ["userId"],
        properties: {
          userId: { type: "string", format: "uuid" },
        },
      },

      // ═══════════════════════════════════════════════════════════
      // ───────────────── DEVICE SCHEMAS ─────────────────────────
      // ═══════════════════════════════════════════════════════════
      Device: {
        type: "object",
        properties: {
          id: { type: "string" },
          userId: { type: "string" },
          deviceName: { type: "string", example: "My Laptop" },
          fingerprint: { type: "string" },
          userAgent: { type: "string" },
          ipAddress: { type: "string" },
          isTrusted: { type: "boolean" },
          firstUsedAt: { type: "string", format: "date-time" },
          lastUsedAt: { type: "string", format: "date-time" },
        },
      },
      CurrentDevice: {
        type: "object",
        properties: {
          fingerprint: { type: "string" },
          name: { type: "string" },
          ipAddress: { type: "string" },
          userAgent: { type: "string" },
          isTrusted: { type: "boolean" },
        },
      },

      // ═══════════════════════════════════════════════════════════
      // ───────────────── AUDIT SCHEMAS ──────────────────────────
      // ═══════════════════════════════════════════════════════════
      AuditLog: {
        type: "object",
        properties: {
          id: { type: "string" },
          timestamp: { type: "string", format: "date-time" },
          userId: { type: "string", format: "uuid" },
          action: { type: "string", example: "POST" },
          resource: { type: "string", example: "/login" },
          ipAddress: { type: "string" },
          metadata: {
            type: "object",
            properties: {
              requestId: { type: "string" },
              statusCode: { type: "integer" },
              durationMs: { type: "integer" },
              device: { type: "string" },
            },
          },
          user: {
            type: "object",
            properties: {
              id: { type: "string" },
              email: { type: "string" },
              firstName: { type: "string" },
              lastName: { type: "string" },
            },
          },
        },
      },
      AuditEvent: {
        type: "object",
        properties: {
          id: { type: "string" },
          timestamp: { type: "string", format: "date-time" },
          user: { type: "string", example: "John Doe (john@example.com)" },
          action: { type: "string", example: "POST" },
          resource: { type: "string", example: "/login" },
          ip: { type: "string" },
          device: { type: "string" },
          status: { type: "integer" },
          durationMs: { type: "integer" },
          requestId: { type: "string" },
          suspicious: { type: "string", nullable: true, example: "Off-hours external access" },
        },
      },
      RetentionStats: {
        type: "object",
        properties: {
          totalRecords: { type: "integer", example: 5000 },
          last30Days: { type: "integer", example: 250 },
          oldestRecord: { type: "string", format: "date-time" },
          retentionDays: { type: "integer", example: 365 },
          complianceNote: { type: "string" },
        },
      },
    },
  },
  security: [{ bearerAuth: [] }],
  paths: {
    // ═══════════════════════════════════════════════════════════
    // ────────────────── AUTHENTICATION ────────────────────────
    // ═══════════════════════════════════════════════════════════
    "/auth/register": {
      post: {
        tags: ["Authentication"],
        summary: "Register a new user",
        operationId: "registerUser",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/RegisterRequest" },
            },
          },
        },
        responses: {
          201: {
            description: "User registered successfully",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/RegisterResponse" },
              },
            },
          },
          400: {
            description: "Validation error or weak password",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
                example: {
                  error: "WEAK_PASSWORD",
                  details: {
                    password: ["Missing uppercase", "Missing special characters"],
                  },
                },
              },
            },
          },
          409: {
            description: "Email already registered",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
                example: {
                  error: "EMAIL_EXISTS",
                  message: "Email already registered",
                },
              },
            },
          },
        },
        security: [],
      },
    },
"/auth/login": {
  "post": {
    "tags": ["Authentication"],
    "summary": "Authenticate user and obtain JWT token",
    "operationId": "loginUser",
    "requestBody": {
      "required": true,
      "content": {
        "application/json": {
          "schema": {
            "oneOf": [
              {
                "$ref": "#/components/schemas/LoginRequest"
              },
              {
                "$ref": "#/components/schemas/LoginRequestWithMFA"
              }
            ]
          }
        }
      }
    },
    "responses": {
      "200": {
        "description": "Login successful",
        "content": {
          "application/json": {
            "schema": { "$ref": "#/components/schemas/LoginResponse" }
          }
        }
      },
      "206": {
        "description": "MFA required (if enabled and device not trusted)",
        "content": {
          "application/json": {
            "schema": {
              "type": "object",
              "properties": {
                "mfaRequired": { "type": "boolean", "example": true },
                "message": { "type": "string" }
              }
            }
          }
        }
      },
      "401": {
        "description": "Invalid credentials or MFA code",
        "content": {
          "application/json": {
            "schema": { "$ref": "#/components/schemas/ErrorResponse" }
          }
        }
      }
    },
    "security": []
  }
},
    "/auth/mfa/setup": {
      post: {
        tags: ["Authentication"],
        summary: "Initialize MFA (TOTP) setup",
        operationId: "setupMFA",
        description: "Generates QR code and backup codes. User must scan QR and call /mfa/verify to enable.",
        responses: {
          200: {
            description: "MFA setup initialized",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/MFASetupResponse" },
              },
            },
          },
          401: {
            description: "Unauthorized",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },
    "/auth/mfa/verify": {
      post: {
        tags: ["Authentication"],
        summary: "Verify and enable MFA",
        operationId: "verifyMFA",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/MFAVerifyRequest" },
            },
          },
        },
        responses: {
          200: {
            description: "MFA enabled successfully",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    success: { type: "boolean" },
                    message: { type: "string" },
                  },
                },
              },
            },
          },
          400: {
            description: "Invalid MFA code",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },
    "/auth/me": {
      get: {
        tags: ["Authentication"],
        summary: "Get current user profile",
        operationId: "getCurrentUser",
        responses: {
          200: {
            description: "Current user profile with devices",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/UserProfile" },
              },
            },
          },
          401: {
            description: "Unauthorized",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },

    // ═══════════════════════════════════════════════════════════
    // ─────────────────── USER MANAGEMENT ───────────────────────
    // ═══════════════════════════════════════════════════════════
    "/users": {
      get: {
        tags: ["Users"],
        summary: "List all users (paginated)",
        operationId: "listUsers",
        parameters: [
          {
            name: "page",
            in: "query",
            schema: { type: "integer", default: 1 },
          },
          {
            name: "limit",
            in: "query",
            schema: { type: "integer", default: 20, maximum: 100 },
          },
          {
            name: "search",
            in: "query",
            description: "Search by email, firstName, or lastName",
            schema: { type: "string" },
          },
        ],
        responses: {
          200: {
            description: "List of users",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    data: { type: "array", items: { $ref: "#/components/schemas/User" } },
                    pagination: { $ref: "#/components/schemas/PaginationInfo" },
                  },
                },
              },
            },
          },
          401: {
            description: "Unauthorized",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
          403: {
            description: "Insufficient permissions",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },
    "/users/{id}": {
      get: {
        tags: ["Users"],
        summary: "Get user details by ID",
        operationId: "getUser",
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            schema: { type: "string", format: "uuid" },
          },
        ],
        responses: {
          200: {
            description: "User details with roles and devices",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/UserWithDevices" },
              },
            },
          },
          404: {
            description: "User not found",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },
    "/users/{id}/activate": {
      post: {
        tags: ["Users"],
        summary: "Activate a deactivated user",
        operationId: "activateUser",
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            schema: { type: "string", format: "uuid" },
          },
        ],
        responses: {
          200: {
            description: "User activated",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    success: { type: "boolean" },
                    message: { type: "string" },
                  },
                },
              },
            },
          },
          403: {
            description: "Insufficient permissions",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },
    "/users/{id}/deactivate": {
      post: {
        tags: ["Users"],
        summary: "Deactivate a user account",
        operationId: "deactivateUser",
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            schema: { type: "string", format: "uuid" },
          },
        ],
        responses: {
          200: {
            description: "User deactivated",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    success: { type: "boolean" },
                    message: { type: "string" },
                  },
                },
              },
            },
          },
          403: {
            description: "Insufficient permissions",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },
    "/users/{id}/reset-password": {
      post: {
        tags: ["Users"],
        summary: "Reset user password (admin only)",
        operationId: "adminResetPassword",
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            schema: { type: "string", format: "uuid" },
          },
        ],
        responses: {
          200: {
            description: "Password reset. Temporary password returned.",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/PasswordResetResponse" },
              },
            },
          },
          403: {
            description: "Insufficient permissions",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },

    // ═══════════════════════════════════════════════════════════
    // ─────────────── ROLES & PERMISSIONS ───────────────────────
    // ═══════════════════════════════════════════════════════════
    "/roles": {
      get: {
        tags: ["Roles & Permissions"],
        summary: "List all roles",
        operationId: "listRoles",
        responses: {
          200: {
            description: "List of roles with permissions",
            content: {
              "application/json": {
                schema: {
                  type: "array",
                  items: { $ref: "#/components/schemas/Role" },
                },
              },
            },
          },
          401: {
            description: "Unauthorized",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
      post: {
        tags: ["Roles & Permissions"],
        summary: "Create a new role",
        operationId: "createRole",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/CreateRoleRequest" },
            },
          },
        },
        responses: {
          201: {
            description: "Role created successfully",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Role" },
              },
            },
          },
          409: {
            description: "Role name already exists",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },
    "/roles/{id}": {
      put: {
        tags: ["Roles & Permissions"],
        summary: "Update role and permissions",
        operationId: "updateRole",
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            schema: { type: "string" },
          },
        ],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  name: { type: "string" },
                  description: { type: "string" },
                  permissions: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        action: { type: "string", enum: ["create", "read", "update", "delete", "manage", "export"] },
                        resource: { type: "string" },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: "Role updated successfully",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Role" },
              },
            },
          },
          409: {
            description: "Role name already taken",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },
    "/roles/{id}/assign": {
      post: {
        tags: ["Roles & Permissions"],
        summary: "Assign a role to a user",
        operationId: "assignRole",
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            schema: { type: "string" },
          },
        ],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/AssignRoleRequest" },
            },
          },
        },
        responses: {
          200: {
            description: "Role assigned successfully",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    success: { type: "boolean" },
                    message: { type: "string" },
                  },
                },
              },
            },
          },
          404: {
            description: "Role or user not found",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },
    "/roles/{id}/revoke": {
      post: {
        tags: ["Roles & Permissions"],
        summary: "Revoke a role from a user",
        operationId: "revokeRole",
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            schema: { type: "string" },
          },
        ],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/AssignRoleRequest" },
            },
          },
        },
        responses: {
          200: {
            description: "Role revoked successfully",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    success: { type: "boolean" },
                    message: { type: "string" },
                  },
                },
              },
            },
          },
        },
      },
    },

    // ═══════════════════════════════════════════════════════════
    // ─────────────── DEVICE MANAGEMENT ─────────────────────────
    // ═══════════════════════════════════════════════════════════
    "/devices": {
      get: {
        tags: ["Devices"],
        summary: "List current user's devices",
        operationId: "listMyDevices",
        responses: {
          200: {
            description: "List of user devices",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    devices: { type: "array", items: { $ref: "#/components/schemas/Device" } },
                  },
                },
              },
            },
          },
          401: {
            description: "Unauthorized",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },
    "/devices/current": {
      get: {
        tags: ["Devices"],
        summary: "Get current device fingerprint and info",
        operationId: "getCurrentDevice",
        responses: {
          200: {
            description: "Current device information",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    currentDevice: { $ref: "#/components/schemas/CurrentDevice" },
                  },
                },
              },
            },
          },
          400: {
            description: "Device info unavailable",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },
    "/devices/{id}/trust": {
      post: {
        tags: ["Devices"],
        summary: "Trust a device (skip MFA on next login)",
        operationId: "trustDevice",
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            schema: { type: "string" },
          },
        ],
        responses: {
          200: {
            description: "Device trusted",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    success: { type: "boolean" },
                    message: { type: "string" },
                  },
                },
              },
            },
          },
          404: {
            description: "Device not found",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },
    "/devices/{id}/revoke": {
      post: {
        tags: ["Devices"],
        summary: "Revoke device trust (require MFA on next login)",
        operationId: "revokeDevice",
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            schema: { type: "string" },
          },
        ],
        responses: {
          200: {
            description: "Trust revoked",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    success: { type: "boolean" },
                    message: { type: "string" },
                  },
                },
              },
            },
          },
          404: {
            description: "Device not found",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },
    "/devices/{id}": {
      delete: {
        tags: ["Devices"],
        summary: "Delete device record",
        operationId: "deleteDevice",
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            schema: { type: "string" },
          },
        ],
        responses: {
          200: {
            description: "Device deleted",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    success: { type: "boolean" },
                    message: { type: "string" },
                  },
                },
              },
            },
          },
          404: {
            description: "Device not found",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },

    // ═══════════════════════════════════════════════════════════
    // ──────────────── AUDIT TRAIL & COMPLIANCE ──────────────────
    // ═══════════════════════════════════════════════════════════
    "/audit": {
      get: {
        tags: ["Audit Trail"],
        summary: "List audit logs (paginated)",
        operationId: "listAuditLogs",
        parameters: [
          {
            name: "page",
            in: "query",
            schema: { type: "integer", default: 1 },
          },
          {
            name: "limit",
            in: "query",
            schema: { type: "integer", default: 50, maximum: 500 },
          },
          {
            name: "userId",
            in: "query",
            schema: { type: "string" },
          },
          {
            name: "action",
            in: "query",
            schema: { type: "string", example: "POST" },
          },
          {
            name: "resource",
            in: "query",
            schema: { type: "string", example: "/login" },
          },
          {
            name: "ipAddress",
            in: "query",
            schema: { type: "string" },
          },
          {
            name: "startDate",
            in: "query",
            schema: { type: "string", format: "date-time" },
          },
          {
            name: "endDate",
            in: "query",
            schema: { type: "string", format: "date-time" },
          },
        ],
        responses: {
          200: {
            description: "Paginated audit logs",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    data: { type: "array", items: { $ref: "#/components/schemas/AuditLog" } },
                    pagination: { $ref: "#/components/schemas/PaginationInfo" },
                  },
                },
              },
            },
          },
          401: {
            description: "Unauthorized",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },
    "/audit/events": {
      get: {
        tags: ["Audit Trail"],
        summary: "Search audit events with advanced filters",
        operationId: "searchAuditEvents",
        parameters: [
          {
            name: "userId",
            in: "query",
            schema: { type: "string" },
          },
          {
            name: "email",
            in: "query",
            schema: { type: "string" },
          },
          {
            name: "action",
            in: "query",
            schema: { type: "string", example: "POST" },
          },
          {
            name: "resource",
            in: "query",
            schema: { type: "string" },
          },
          {
            name: "ip",
            in: "query",
            schema: { type: "string" },
          },
          {
            name: "status",
            in: "query",
            schema: { type: "integer" },
          },
          {
            name: "before",
            in: "query",
            schema: { type: "string", format: "date-time" },
          },
          {
            name: "after",
            in: "query",
            schema: { type: "string", format: "date-time" },
          },
          {
            name: "sensitive",
            in: "query",
            description: "Set to 'true' to filter for sensitive operations",
            schema: { type: "string", enum: ["true", "false"] },
          },
        ],
        responses: {
          200: {
            description: "Filtered audit events",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    total: { type: "integer" },
                    events: { type: "array", items: { $ref: "#/components/schemas/AuditEvent" } },
                  },
                },
              },
            },
          },
          401: {
            description: "Unauthorized",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },
    "/audit/retention": {
      get: {
        tags: ["Audit Trail"],
        summary: "Get audit log retention statistics",
        operationId: "getRetentionStats",
        responses: {
          200: {
            description: "Retention and compliance statistics",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/RetentionStats" },
              },
            },
          },
          401: {
            description: "Unauthorized",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },
    "/audit/export": {
      post: {
        tags: ["Audit Trail"],
        summary: "Export audit logs to CSV",
        operationId: "exportAuditLogs",
        description: "Exports up to 10,000 most recent audit logs in CSV format",
        responses: {
          200: {
            description: "CSV file download",
            content: {
              "text/csv": {
                schema: {
                  type: "string",
                  format: "binary",
                },
              },
            },
          },
          401: {
            description: "Unauthorized",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
          403: {
            description: "Insufficient permissions (requires export permission)",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
      },
    },

    // ═══════════════════════════════════════════════════════════
    // ─────────────── OPENID CONNECT ENDPOINTS ───────────────────
    // ═══════════════════════════════════════════════════════════
    "/.well-known/openid-configuration": {
      get: {
        tags: ["OpenID Connect"],
        summary: "OpenID Connect discovery endpoint",
        operationId: "discoveryEndpoint",
        description: "Returns OpenID Connect server metadata and endpoints",
        responses: {
          200: {
            description: "OpenID Connect configuration",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    issuer: { type: "string" },
                    authorization_endpoint: { type: "string" },
                    token_endpoint: { type: "string" },
                    jwks_uri: { type: "string" },
                    response_types_supported: { type: "array", items: { type: "string" } },
                    subject_types_supported: { type: "array", items: { type: "string" } },
                    id_token_signing_alg_values_supported: { type: "array", items: { type: "string" } },
                    scopes_supported: { type: "array", items: { type: "string" } },
                    claims_supported: { type: "array", items: { type: "string" } },
                  },
                },
              },
            },
          },
        },
        security: [],
      },
    },
    "/openid/jwks": {
      get: {
        tags: ["OpenID Connect"],
        summary: "JSON Web Key Set endpoint",
        operationId: "getJWKS",
        description: "Returns public keys for verifying JWTs issued by this server",
        responses: {
          200: {
            description: "JWKS",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    keys: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          kty: { type: "string" },
                          use: { type: "string" },
                          kid: { type: "string" },
                          n: { type: "string" },
                          e: { type: "string" },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        security: [],
      },
    },
    "/openid/authorize": {
      get: {
        tags: ["OpenID Connect"],
        summary: "OAuth 2.0 / OpenID Connect authorization endpoint",
        operationId: "authorizeEndpoint",
        parameters: [
          {
            name: "response_type",
            in: "query",
            required: true,
            schema: { type: "string", enum: ["code", "token", "id_token"] },
          },
          {
            name: "client_id",
            in: "query",
            required: true,
            schema: { type: "string" },
          },
          {
            name: "redirect_uri",
            in: "query",
            required: true,
            schema: { type: "string", format: "uri" },
          },
          {
            name: "scope",
            in: "query",
            schema: { type: "string", example: "openid profile email" },
          },
          {
            name: "state",
            in: "query",
            schema: { type: "string", description: "CSRF protection token" },
          },
          {
            name: "nonce",
            in: "query",
            schema: { type: "string", description: "Prevents token replay" },
          },
        ],
        responses: {
          302: {
            description: "Redirect to authorization or login",
          },
          400: {
            description: "Invalid request parameters",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
        security: [],
      },
    },
    "/openid/token": {
      post: {
        tags: ["OpenID Connect"],
        summary: "Token endpoint (exchange code for tokens)",
        operationId: "tokenEndpoint",
        requestBody: {
          required: true,
          content: {
            "application/x-www-form-urlencoded": {
              schema: {
                type: "object",
                required: ["grant_type", "code", "client_id", "redirect_uri"],
                properties: {
                  grant_type: { type: "string", enum: ["authorization_code", "refresh_token"] },
                  code: { type: "string", description: "Authorization code from /authorize" },
                  refresh_token: { type: "string", description: "Refresh token (for refresh_token grant)" },
                  client_id: { type: "string" },
                  client_secret: { type: "string", description: "Confidential clients only" },
                  redirect_uri: { type: "string", format: "uri" },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: "Tokens issued",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    access_token: { type: "string" },
                    token_type: { type: "string", example: "Bearer" },
                    expires_in: { type: "integer" },
                    id_token: { type: "string" },
                    refresh_token: { type: "string" },
                  },
                },
              },
            },
          },
          400: {
            description: "Invalid request or credentials",
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ErrorResponse" },
              },
            },
          },
        },
        security: [],
      },
    },
  },
};
