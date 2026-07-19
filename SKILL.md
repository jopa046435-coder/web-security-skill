---
name: web-security
description: Auto-secure web projects for vibe coders. Fixes auth, XSS, SQLi, CSRF, file uploads, env leaks, and security headers on Next.js, React, Express apps. Use when user says "secure my app", "security audit", "check security", "auth", "fix security", "env leak", "security headers", "protect API routes", "rate limit".
framework: tailwind
---

# Web Security for Vibe Coders

## Purpose
This skill automatically secures web projects as you build. When activated, it analyzes your code for security vulnerabilities and provides fixes in real-time. Designed for Next.js, React, Express, and modern full-stack frameworks.

## Trigger Keywords
`secure my app`, `security audit`, `is this safe`, `check security`, `fix security`, `auth`, `sanitize input`, `secure coding`, `env vars`, `api key leak`, `security headers`, `protect route`

---

## Core Rules

### 1. NEVER expose secrets to client
```
// BAD - goes to browser
const API_KEY = "sk-abc123"

// GOOD
const API_KEY = process.env.API_KEY  // server-only
const API_KEY = process.env.NEXT_PUBLIC_API_KEY  // only if intentionally public
```

### 2. Always validate & sanitize input
### 3. Always use parameterized queries (never string concatenation for SQL)
### 4. Every API route must authenticate
### 5. Never trust client-side validation alone
### 6. Security headers must be present on every response

---

## Authentication Patterns

### Next.js Auth (NextAuth.js v5)
```typescript
// middleware.ts - Protect routes
import { auth } from "@/auth"

export default auth((req) => {
  const isLoggedIn = !!req.auth
  const isAuthPage = req.nextUrl.pathname.startsWith("/login")
  const isApiRoute = req.nextUrl.pathname.startsWith("/api")

  if (!isLoggedIn && !isAuthPage) {
    return Response.redirect(new URL("/login", req.url))
  }

  if (isApiRoute && !isLoggedIn) {
    return Response.json({ error: "Unauthorized" }, { status: 401 })
  }
})

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
}
```

### API Route Protection
```typescript
// app/api/users/route.ts
import { auth } from "@/auth"

export async function GET(req: Request) {
  const session = await auth()
  if (!session?.user?.id) {
    return Response.json({ error: "Unauthorized" }, { status: 401 })
  }
  // Proceed with user-specific data
  const users = await db.user.findMany({
    where: { orgId: session.user.orgId }
  })
  return Response.json(users)
}
```

### Role-Based Access
```typescript
// Guard helper
export function requireRole(session: Session | null, ...roles: string[]) {
  if (!session?.user?.role) return false
  return roles.includes(session.user.role)
}

// Usage in API route
if (!requireRole(session, "admin", "moderator")) {
  return Response.json({ error: "Forbidden" }, { status: 403 })
}
```

---

## SQL Injection Prevention

### Prisma (parameterized by default)
```typescript
// GOOD - Prisma automatically parameterizes
const user = await prisma.user.findUnique({
  where: { email: inputEmail }
})

// GOOD - for raw queries, use parameterized
const users = await prisma.$queryRaw`
  SELECT * FROM "User" WHERE email = ${inputEmail}
`

// BAD - never do this
const users = await prisma.$queryRawUnsafe(
  `SELECT * FROM "User" WHERE email = '${inputEmail}'`
)
```

### Drizzle
```typescript
// GOOD - parameterized
const users = await db.select().from(usersTable).where(
  eq(usersTable.email, inputEmail)
)

// For raw SQL
const users = await db.execute(
  sql`SELECT * FROM users WHERE email = ${inputEmail}`
)
```

### Express + MySQL/Postgres
```javascript
// BAD
const query = `SELECT * FROM users WHERE id = ${req.params.id}`
db.query(query)

// GOOD - use parameterized queries
db.query("SELECT * FROM users WHERE id = ?", [req.params.id])

// GOOD - use ORM
const user = await User.findById(req.params.id)
```

---

## XSS Prevention

### React (auto-escapes by default)
```tsx
// SAFE - React auto-escapes
<div>{userComment}</div>

// DANGER - bypasses React's escaping
<div dangerouslySetInnerHTML={{ __html: userComment }} />

// SAFE with sanitization
import DOMPurify from "dompurify"
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />
```

### Server-side output
```typescript
// Never return unsanitized user input directly
// BAD
return res.json({ message: userInput })

// GOOD - validate and sanitize
import { z } from "zod"

const contactSchema = z.object({
  name: z.string().min(1).max(100).regex(/^[a-zA-Z\s'-]+$/),
  email: z.string().email().max(255),
  message: z.string().min(1).max(5000),
})

const result = contactSchema.safeParse(req.body)
if (!result.success) {
  return res.status(400).json({ error: "Invalid input" })
}
```

---

## File Upload Security

```typescript
// Next.js API route
import { writeFile } from "fs/promises"
import path from "path"

const ALLOWED_TYPES = ["image/jpeg", "image/png", "image/webp"]
const MAX_SIZE = 5 * 1024 * 1024 // 5MB
const UPLOAD_DIR = path.join(process.cwd(), "uploads")

export async function POST(req: Request) {
  const formData = await req.formData()
  const file = formData.get("file") as File

  // Validate type
  if (!file || !ALLOWED_TYPES.includes(file.type)) {
    return Response.json({ error: "Invalid file type" }, { status: 400 })
  }

  // Validate size
  if (file.size > MAX_SIZE) {
    return Response.json({ error: "File too large" }, { status: 400 })
  }

  // Generate safe filename
  const ext = path.extname(file.name)
  const safeName = `${crypto.randomUUID()}${ext}`
  const filePath = path.join(UPLOAD_DIR, safeName)

  // Prevent path traversal
  if (!filePath.startsWith(UPLOAD_DIR)) {
    return Response.json({ error: "Invalid path" }, { status: 400 })
  }

  const bytes = await file.arrayBuffer()
  await writeFile(filePath, Buffer.from(bytes))

  return Response.json({ url: `/uploads/${safeName}` })
}
```

---

## API Security

### Rate Limiting (Next.js)
```typescript
// lib/rate-limit.ts
import { LRUCache } from "lru-cache"

export function rateLimit(options: {
  interval: number
  uniqueTokenPerInterval: number
}) {
  const tokenCache = new LRUCache<string, number>({
    max: options.uniqueTokenPerInterval || 500,
    ttl: options.interval || 60000,
  })

  return {
    check: (limit: number, token: string) => {
      const tokenCount = (tokenCache.get(token) as number[]) || [0]
      if (tokenCount[0] === 0) tokenCache.set(token, [1])
      else tokenCount[0] += 1

      const currentUsage = tokenCount[0]
      const isRateLimited = currentUsage >= limit

      return { isRateLimited, currentUsage, limit }
    },
  }
}

// Usage
const limiter = rateLimit({ interval: 60000, uniqueTokenPerInterval: 500 })

export async function POST(req: Request) {
  const ip = req.headers.get("x-forwarded-for") || "unknown"
  const { isRateLimited } = limiter.check(5, ip) // 5 requests per minute

  if (isRateLimited) {
    return Response.json({ error: "Too many requests" }, { status: 429 })
  }
  // ...
}
```

### CORS (Next.js)
```typescript
// middleware.ts
export function middleware(req: Request) {
  const origin = req.headers.get("origin")
  const allowedOrigins = [process.env.NEXT_PUBLIC_APP_URL]

  if (origin && !allowedOrigins.includes(origin)) {
    return new Response("CORS error", { status: 403 })
  }

  const response = NextResponse.next()
  response.headers.set("Access-Control-Allow-Origin", origin || "")
  response.headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
  response.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization")
  response.headers.set("Access-Control-Allow-Credentials", "true")
  return response
}
```

---

## CSRF Protection

### Next.js (Server Actions)
```tsx
// Next.js server actions have built-in CSRF protection
// No extra setup needed when using server actions

// For API routes without server actions, use CSRF tokens
import { cookies } from "next/headers"
import { createHash, randomBytes } from "crypto"

export function generateCsrfToken() {
  const token = randomBytes(32).toString("hex")
  cookies().set("csrf_token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
  })
  return token
}

export function validateCsrfToken(token: string) {
  const stored = cookies().get("csrf_token")?.value
  return token === stored
}
```

---

## Security Headers (Next.js)

```typescript
// next.config.ts
import type { NextConfig } from "next"

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-XSS-Protection", value: "0" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          {
            key: "Strict-Transport-Security",
            value: "max-age=31536000; includeSubDomains",
          },
          {
            key: "Content-Security-Policy",
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-inline'",
              "style-src 'self' 'unsafe-inline'",
              "img-src 'self' data: blob: https:",
              "font-src 'self'",
              "connect-src 'self' https://api.yourapp.com",
            ].join("; "),
          },
          {
            key: "Permissions-Policy",
            value: "camera=(), microphone=(), geolocation=()",
          },
        ],
      },
    ]
  },
}

export default nextConfig
```

---

## Environment Variables & Secrets

### Rules
- **Never** commit `.env` files
- Use `.env.example` to document required vars
- Prefix client-safe vars with `NEXT_PUBLIC_` (Next.js)
- Use edge-compatible secrets in production

```gitignore
# .gitignore
.env
.env*.local
!.env.example
```

```
# .env.example (safe to commit)
DATABASE_URL=
NEXTAUTH_SECRET=  # generate: openssl rand -base64 32
NEXTAUTH_URL=http://localhost:3000
NEXT_PUBLIC_APP_URL=http://localhost:3000
```

### Checking for leaked secrets
```bash
# Before pushing, check for secrets
git diff --cached | grep -E "(sk-|api_key|password|secret|token)"
```

---

## Project Security Audit Checklist

When triggered with `security audit` or `secure my app`, run through this checklist:

### Frontend
- [ ] No API keys or secrets in client components
- [ ] `dangerouslySetInnerHTML` used with DOMPurify
- [ ] Forms have CSRF protection
- [ ] Inputs have validation (Zod/Yup)
- [ ] No sensitive data in localStorage (use httpOnly cookies)

### Backend
- [ ] All API routes authenticate (unless intentionally public)
- [ ] Database queries use parameterized statements / ORM
- [ ] File uploads validate type, size, and path
- [ ] Rate limiting on auth routes and public APIs
- [ ] SQL/noSQL injection safeguards in place
- [ ] User IDs from session, never from client params

### Infrastructure
- [ ] Security headers configured in next.config.ts / middleware
- [ ] CORS limited to specific origins
- [ ] `.env` is in `.gitignore`
- [ ] Dependencies audited (`npm audit`, `pnpm audit`)
- [ ] HTTPS enforced in production
- [ ] Auth secrets are strong (crypto.randomBytes for tokens)

### Auth
- [ ] Passwords hashed with bcrypt/argon2 (never plaintext)
- [ ] Sessions use httpOnly, secure, sameSite cookies
- [ ] Rate limiting on login/signup/reset endpoints
- [ ] 2FA available for sensitive actions
- [ ] Password reset tokens expire and are single-use

---

## Dependency Audit Commands

```bash
# JavaScript/TypeScript
npm audit
npm audit fix

# Python
pip-audit
pip install --upgrade -r requirements.txt

# General: check for known vulns
npx snyk test
```

---

## Common Beginner Mistakes & Fixes

| Mistake | Fix |
|---------|-----|
| `const API_KEY = "sk-..."` in frontend | Move to `.env`, use server-only code |
| Trusting `req.body` without validation | Use Zod schemas on every API route |
| Using `innerHTML` or `dangerouslySetInnerHTML` without sanitizer | Use DOMPurify or avoid entirely |
| String building SQL queries | Use ORM or parameterized queries |
| Checking auth only on frontend | Auth check on every API route server-side |
| `const user = await db.user.findFirst({ where: { id: req.query.id } })` | Use session user ID, not client-supplied |
| No rate limiting on login | Add rate limiter on all auth endpoints |
| Uploading files with original names | Generate random filenames |
| `.env` committed to git | Add to `.gitignore`, rotate exposed secrets |

---

## Quick Security Fix Prompts

When user says:
- **"auth"** -> Add NextAuth middleware + API route guards
- **"secure api"** -> Add validation (Zod), auth check, rate limiting
- **"fix upload"** -> Add file type/size/path validation
- **"headers"** -> Add security headers config
- **"secrets"** -> Check for exposed keys, add .gitignore
- **"audit"** -> Run full checklist and fix all issues found
