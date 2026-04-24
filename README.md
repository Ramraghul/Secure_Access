# SecureAccess v2 — Enterprise Authentication & RBAC API

## What This Project Does (Plain English)

**SecureAccess is a backend security system that handles everything related to user identity and access control.** Think of it as the "security guard" layer of any application.

Here's what it does in simple terms:

| Feature | What it means |
|---|---|
| **Registration & Login** | Users create accounts and log in with email + password |
| **JWT Tokens** | After login, users get a digital "pass" (token) they send with every request |
| **MFA (Two-Factor Auth)** | Optional second layer — user scans a QR code with Google Authenticator |
| **RBAC** | Roles like "admin" or "editor" control what each user is allowed to do |
| **Device Trust** | Remembers your devices so you don't need MFA code every single login |
| **Audit Trail** | Every action is logged — who did what, when, from where, on which device |
| **OpenID Connect** | Standard protocol so other apps can use SecureAccess for login (like "Login with Google" but your own) |

---

## Setup From Scratch (Step by Step)

### Prerequisites
- Node.js 18+
- PostgreSQL 14+
- yarn or npm

### Step 1 — Clone and install
```bash
git clone <your-repo>
cd secureaccess
npm install
```

### Step 2 — Configure environment
```bash
cp .env.example .env
# Edit .env — set DATABASE_URL and JWT_SECRET
```

### Step 3 — Set up the database
```bash
# Create the database
createdb secureaccess

# Run migrations (creates all tables)
npm run migrate

# Seed admin user
npm run seed
# → Creates admin@secureaccess.ca / Admin@SecureAccess123
```

### Step 4 — Start the server
```bash
npm run dev
# → http://localhost:4000
# → Swagger docs: http://localhost:4000/api-docs
```

---

## API Endpoints

### Auth
| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/auth/register` | Create new account |
| POST | `/api/v1/auth/login` | Login → get JWT token |
| POST | `/api/v1/auth/mfa/setup` | Get QR code for authenticator app |
| POST | `/api/v1/auth/mfa/verify` | Enable MFA after scanning QR |
| GET  | `/api/v1/auth/me` | Get your profile + devices |

### Users (Admin only)
| Method | Path | Description |
|---|---|---|
| GET  | `/api/v1/users` | List all users (paginated) |
| GET  | `/api/v1/users/:id` | Get single user |
| POST | `/api/v1/users/:id/deactivate` | Disable account |
| POST | `/api/v1/users/:id/reset-password` | Force password reset |

### Roles & Permissions
| Method | Path | Description |
|---|---|---|
| GET  | `/api/v1/roles` | List roles + their permissions |
| POST | `/api/v1/roles` | Create a new role |
| PUT  | `/api/v1/roles/:id` | Update role + permissions |
| POST | `/api/v1/roles/:id/assign` | Give a role to a user |
| POST | `/api/v1/roles/:id/revoke` | Remove role from user |

### Devices
| Method | Path | Description |
|---|---|---|
| GET  | `/api/v1/devices` | List your devices |
| GET  | `/api/v1/devices/current` | Info about current device |
| POST | `/api/v1/devices/:id/trust` | Trust a device (skip MFA) |
| POST | `/api/v1/devices/:id/revoke` | Untrust a device |
| DELETE | `/api/v1/devices/:id` | Delete device record |

### Audit (Admin only)
| Method | Path | Description |
|---|---|---|
| GET  | `/api/v1/audit` | Paginated audit logs |
| GET  | `/api/v1/audit/events` | Advanced search with filters |
| GET  | `/api/v1/audit/retention` | Compliance retention stats |
| POST | `/api/v1/audit/export` | Download audit log as CSV |

---

## Testing the API (Quick Start)

```bash
# 1. Register
curl -X POST http://localhost:4000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"you@test.com","password":"Test@Password123","firstName":"John","lastName":"Doe"}'

# 2. Login → copy the token
curl -X POST http://localhost:4000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"you@test.com","password":"Test@Password123"}'

# 3. Use the token
TOKEN="paste-token-here"

curl http://localhost:4000/api/v1/auth/me \
  -H "Authorization: Bearer $TOKEN"
```

---

## What Changed in v2

| Area | Old | New |
|---|---|---|
| TypeScript types | `(req as any)` everywhere | Proper `Express.Request` augmentation |
| Audit middleware | Only patched `res.send`, missed `res.json`/`res.end` | Patches all 3 response paths, double-fire guard |
| Audit middleware | Shallow 1-level masking | Deep recursive masking + circular ref safe |
| Audit middleware | `arguments` in arrow fn (broken) | Proper `.bind(res)` + typed params |
| Input validation | No validation at all | Zod schemas on every endpoint |
| Password generation | `Math.random()` (not secure) | `crypto.randomBytes()` |
| Backup codes | Stored as base64 (not hashed!) | Hashed with bcrypt |
| Device fingerprint | Only `userAgent\|ip` | SHA-256 of UA + IP + Accept-Language + Accept-Encoding |
| RBAC | 2 separate DB queries (N+1) | Single `Promise.all` — 2x fewer queries |
| Error handling | No global handler — crashes leak stack traces | `error.middleware.ts` catches everything |
| Config | `process.env` scattered everywhere | Centralised `src/config/index.ts` |
| Logging | `console.log` | Winston structured logger with daily rotating files |
| Schema | `backupCodesRaw` (wrong name, no index) | `backupCodesHashed` + proper indexes on all query paths |
