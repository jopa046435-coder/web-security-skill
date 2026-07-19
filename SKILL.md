---
name: web-security
description: Context-aware web security patterns. Auto-detects what feature you are building (login, API, upload, payment, search, admin, etc.) and injects the correct security code. Works with any AI coding tool: Cursor, Copilot, Windsurf, Claude, ChatGPT.
framework: tailwind
---

# Web Security Patterns (Auto-Apply Mode)

## How This Works

**Do NOT wait for the user to ask for security.** When you see them building any of the features below, proactively read their code, detect the feature type, and inject the matching security pattern directly into their files. Explain only what you changed and why.

## Auto-Detection Rules

| User is building | Trigger words | Security to inject |
|---|---|---|
| Login / Signup form | `login`, `signup`, `register`, `signin`, `auth form`, `bcrypt`, `nextauth`, `clerk` | #1 Auth Flow |
| API route / handler | `route.ts`, `api/`, `server action`, `trpc`, `endpoint`, `REST` | #2 API Route Guard |
| File upload | `upload`, `file input`, `multer`, `formData`, `supabase storage`, `s3 upload` | #3 File Upload |
| Database query | `prisma`, `drizzle`, `query`, `raw sql`, `execute`, `findMany`, `findUnique` | #4 Database Query |
| Payment / Checkout | `stripe`, `checkout`, `payment`, `subscription`, `billing`, `paypal`, `lemonsqueezy` | #5 Payment |
| User profile / settings | `profile`, `settings page`, `account`, `edit user`, `update user` | #6 User Data |
| Comment / UGC / text input | `comment`, `review`, `textarea`, `user post`, `chat message` | #7 User Content |
| Search | `search`, `searchbar`, `filter`, `query param` | #8 Search |
| Admin panel | `admin`, `dashboard`, `admin route`, `moderator` | #9 Admin |
| Webhook endpoint | `webhook`, `stripe webhook`, `postback` | #10 Webhook |
| Contact / Newsletter form | `contact form`, `newsletter`, `subscribe`, `email signup` | #11 Public Form |
| Password reset | `forgot password`, `reset password`, `reset token` | #12 Password Reset |
| Middleware file | `middleware.ts`, `middleware` | #13 Middleware |
| OAuth / Social login | `oauth`, `google login`, `github login`, `social` | #14 OAuth |
| `.env` or secrets | `.env`, `API_KEY`, `DATABASE_URL`, `secret` | #15 Secrets |
| Any new project | `new project`, `init`, `create app`, `npx create` | #16 Project Bootstrap |

---

## Security Patterns (Inject These)

### #1 Auth Flow

When detecting a login or signup form, check then inject:

```
DETECT: Read the auth code. Look for:
- Is password hashed with bcrypt/argon2? (not plaintext, not SHA/MD5)
- Is there rate limiting on the login endpoint?
- Is input validated before the auth call?
- Are cookies set with httpOnly, secure, sameSite?
- Is there account lockout after N failed attempts?

INJECT if missing:
```

```typescript
// lib/auth-utils.ts (create if not exists)
import { hash, compare } from "bcryptjs"

const SALT_ROUNDS = 12
const MAX_LOGIN_ATTEMPTS = 5
const LOCKOUT_MINUTES = 15

export async function hashPassword(password: string) {
  return hash(password, SALT_ROUNDS)
}

export async function verifyPassword(password: string, hashed: string) {
  return compare(password, hashed)
}

// Rate limit login attempts (lib/rate-limit.ts)
import { LRUCache } from "lru-cache"

const loginAttempts = new LRUCache<string, number>({
  max: 10000,
  ttl: 15 * 60 * 1000, // 15 min window
})

export function checkLoginRateLimit(ip: string): boolean {
  const attempts = loginAttempts.get(ip) || 0
  if (attempts >= MAX_LOGIN_ATTEMPTS) return false
  loginAttempts.set(ip, attempts + 1)
  return true
}
```

```typescript
// app/api/auth/login/route.ts
// In the POST handler, add:
import { z } from "zod"

const loginSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(8).max(128),
})

// Inside POST():
const parsed = loginSchema.safeParse(await req.json())
if (!parsed.success) {
  return Response.json({ error: "Invalid input" }, { status: 400 })
}

const ip = req.headers.get("x-forwarded-for") || "unknown"
if (!checkLoginRateLimit(ip)) {
  return Response.json({ error: "Too many attempts. Try again later." }, { status: 429 })
}

// Hash password for signup:
// const hashedPassword = await hashPassword(parsed.data.password)

// Verify for login:
// const isValid = await verifyPassword(parsed.data.password, user.password)
```

---

### #2 API Route Guard

When detecting any API route, check then inject:

```
DETECT: Read the route file. Look for:
- Is there an auth/session check at the top?
- Is input validated with Zod/Yup?
- Is the user ID from session, not request body/params?
- Is there rate limiting on POST/PUT/DELETE?

INJECT if missing:
```

```typescript
// app/api/[resource]/route.ts
import { auth } from "@/auth"
import { z } from "zod"

// Put this at the TOP of every authenticated API route:
async function guard(req: Request) {
  const session = await auth()
  if (!session?.user?.id) {
    return Response.json({ error: "Unauthorized" }, { status: 401 })
  }
  return session // returns session, not an error response
}

// Inside each handler:
export async function GET(req: Request) {
  const session = await guard(req)
  if (session instanceof Response) return session  // auth failed

  // NEVER do this (IDOR):
  // const { userId } = await req.json()
  // const data = await db.user.findUnique({ where: { id: userId } })

  // ALWAYS use session user ID:
  const data = await db.user.findUnique({
    where: { id: session.user.id }
  })
  return Response.json(data)
}
```

---

### #3 File Upload

When detecting file upload code, inject ALL of these:

```typescript
// lib/upload-safe.ts
import { writeFile } from "fs/promises"
import path from "path"

const ALLOWED_MIMES = {
  "image/jpeg": [".jpg", ".jpeg"],
  "image/png": [".png"],
  "image/webp": [".webp"],
  "image/gif": [".gif"],
  "application/pdf": [".pdf"],
} as const

const MAX_SIZE = 10 * 1024 * 1024 // 10MB
const UPLOAD_DIR = path.join(process.cwd(), "public/uploads")

export function validateUpload(file: File) {
  // 1. No file
  if (!file || file.size === 0) {
    return { ok: false, error: "No file provided" }
  }

  // 2. Size check
  if (file.size > MAX_SIZE) {
    return { ok: false, error: `File too large. Max ${MAX_SIZE / 1024 / 1024}MB` }
  }

  // 3. MIME check
  const allowed = ALLOWED_MIMES[file.type as keyof typeof ALLOWED_MIMES]
  if (!allowed) {
    return { ok: false, error: "Invalid file type" }
  }

  // 4. Extension matches MIME
  const ext = path.extname(file.name).toLowerCase()
  if (!allowed.includes(ext)) {
    return { ok: false, error: "File extension does not match type" }
  }

  return { ok: true, error: null }
}

export function safeFileName(originalName: string) {
  const ext = path.extname(originalName)
  const sanitized = originalName
    .replace(ext, "")
    .replace(/[^a-zA-Z0-9_-]/g, "_")
    .slice(0, 50)
  return `${sanitized}-${crypto.randomUUID().slice(0, 8)}${ext}`
}

export async function saveFile(file: File) {
  const name = safeFileName(file.name)
  const filePath = path.join(UPLOAD_DIR, name)

  // 5. Path traversal protection
  const resolved = path.resolve(filePath)
  const uploadResolved = path.resolve(UPLOAD_DIR)
  if (!resolved.startsWith(uploadResolved)) {
    throw new Error("Invalid file path")
  }

  const bytes = Buffer.from(await file.arrayBuffer())
  await writeFile(filePath, bytes)
  return { url: `/uploads/${name}`, path: filePath }
}
```

---

### #4 Database Query

When detecting any database query, scan for:

```
DETECT: Look for patterns like:
- $queryRawUnsafe(    ❌  DANGER
- "${...}" in SQL     ❌  DANGER
- String concatenation in SQL   ❌  DANGER
- $queryRaw\`  or  sql\`   ✅  OK (tagged template)
- ORM methods like findUnique, findFirst  ✅  OK

SCAN ONLY SAFE: If all queries use ORM or tagged templates, do nothing.
SCAN NOT SAFE: If raw string-concatenated SQL found, fix it.
```

Inject fix:
```typescript
// FIX: Replace string-built SQL with parameterized:

// BEFORE (unsafe)
const users = await db.$queryRawUnsafe(
  `SELECT * FROM User WHERE email = '${email}'`
)

// AFTER (safe)
const users = await db.$queryRaw`
  SELECT * FROM "User" WHERE email = ${email}
`

// OR use ORM
const users = await db.user.findUnique({ where: { email } })
```

---

### #5 Payment / Checkout

When detecting payment code:

```
DETECT: Read the checkout/payment file. Check:
- Is the price validated server-side? (never trust client price)
- Is the payment intent/idempotency key handled?
- Is the webhook signature verified?
- Are raw card details anywhere in logs/body? (they should never be)

INJECT if missing:
```

```typescript
// app/api/payment/create-checkout/route.ts
import { auth } from "@/auth"
import { z } from "zod"
import Stripe from "stripe"

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)

// 1. Never trust client-side price
const PRODUCT_PRICES: Record<string, number> = {
  "pro_monthly": 2900,
  "pro_yearly": 29000,
}

const checkoutSchema = z.object({
  productId: z.string().refine(id => id in PRODUCT_PRICES, "Invalid product"),
})

export async function POST(req: Request) {
  const session = await auth()
  if (!session?.user?.id) {
    return Response.json({ error: "Unauthorized" }, { status: 401 })
  }

  const parsed = checkoutSchema.safeParse(await req.json())
  if (!parsed.success) {
    return Response.json({ error: "Invalid request" }, { status: 400 })
  }

  // 2. Use server-side price, not client
  const amount = PRODUCT_PRICES[parsed.data.productId]

  const stripeSession = await stripe.checkout.sessions.create({
    mode: "subscription",
    customer_email: session.user.email!,
    metadata: { userId: session.user.id },
    line_items: [{ price: parsed.data.productId, quantity: 1 }],
    success_url: `${process.env.NEXT_PUBLIC_URL}/billing?success=true`,
    cancel_url: `${process.env.NEXT_PUBLIC_URL}/billing?canceled=true`,
  })

  return Response.json({ url: stripeSession.url })
}
```

```typescript
// app/api/webhooks/stripe/route.ts
import Stripe from "stripe"

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)

export async function POST(req: Request) {
  const body = await req.text()
  const sig = req.headers.get("stripe-signature")!

  // 3. Verify webhook signature
  let event: Stripe.Event
  try {
    event = stripe.webhooks.constructEvent(
      body, sig, process.env.STRIPE_WEBHOOK_SECRET!
    )
  } catch {
    return Response.json({ error: "Invalid signature" }, { status: 400 })
  }

  // Handle event...
}
```

---

### #6 User Profile / Settings

```typescript
// app/api/user/update/route.ts
export async function PUT(req: Request) {
  const session = await guard(req)
  if (session instanceof Response) return session

  const schema = z.object({
    name: z.string().min(1).max(100).regex(/^[\p{L}\s'-]+$/u),
    bio: z.string().max(500).optional(),
  })

  const parsed = schema.safeParse(await req.json())
  if (!parsed.success) {
    return Response.json({ error: "Invalid input" }, { status: 400 })
  }

  // CRITICAL: Use session.user.id, never accept userId from body
  const updated = await db.user.update({
    where: { id: session.user.id },
    data: parsed.data,
  })

  // Never return password, token, or sensitive fields
  const { password, ...safeUser } = updated
  return Response.json(safeUser)
}
```

---

### #7 User-Generated Content (Comments, Posts, Reviews)

```typescript
// app/api/comments/route.ts
import { auth } from "@/auth"
import { z } from "zod"

const commentSchema = z.object({
  postId: z.string().uuid(),
  content: z.string().min(1).max(2000),
})

export async function POST(req: Request) {
  const session = await auth()
  if (!session?.user?.id) {
    return Response.json({ error: "Unauthorized" }, { status: 401 })
  }

  const parsed = commentSchema.safeParse(await req.json())
  if (!parsed.success) {
    return Response.json({ error: "Invalid input" }, { status: 400 })
  }

  const comment = await db.comment.create({
    data: {
      postId: parsed.data.postId,
      authorId: session.user.id,
      content: parsed.data.content, // stored raw
    },
  })

  return Response.json(comment)
}
```

```tsx
// components/comment.tsx
// In the frontend, always sanitize before render:
import DOMPurify from "isomorphic-dompurify"

function CommentCard({ content }: { content: string }) {
  return (
    <p dangerouslySetInnerHTML={{
      __html: DOMPurify.sanitize(content, {
        ALLOWED_TAGS: ["b", "i", "em", "strong", "a", "br", "p"],
        ALLOWED_ATTR: ["href", "target", "rel"],
      })
    }} />
  )
}
```

---

### #8 Search

```typescript
// app/api/search/route.ts
// The search is a SQL injection and XSS risk vector
export async function GET(req: Request) {
  const { searchParams } = new URL(req.url)
  const q = searchParams.get("q")

  if (!q || q.length > 200) {
    return Response.json({ results: [] })
  }

  // SAFE: parameterized query
  const results = await db.$queryRaw`
    SELECT id, title, excerpt FROM posts
    WHERE published = true
    AND (title ILIKE ${`%${q}%`} OR excerpt ILIKE ${`%${q}%`})
    LIMIT 20
  `

  return Response.json({ results })
}
```

---

### #9 Admin Panel / Dashboard

```typescript
// middleware.ts admin guard or inline guard
import { auth } from "@/auth"

export async function requireAdmin() {
  const session = await auth()
  if (!session?.user || session.user.role !== "admin") {
    throw new Error("Forbidden")
  }
  return session
}

// app/api/admin/users/route.ts
export async function GET(req: Request) {
  await requireAdmin()
  // ... admin logic
}

// app/admin/layout.tsx
import { redirect } from "next/navigation"
import { auth } from "@/auth"

export default async function AdminLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const session = await auth()
  if (!session?.user || session.user.role !== "admin") {
    redirect("/login")
  }
  return <>{children}</>
}
```

---

### #10 Webhook Endpoint

```typescript
// app/api/webhooks/[service]/route.ts
import { createHmac, timingSafeEqual } from "crypto"

function verifyWebhookSignature(
  body: string,
  signature: string,
  secret: string
): boolean {
  const expected = createHmac("sha256", secret).update(body).digest("hex")
  const expectedBuffer = Buffer.from(expected)
  const signatureBuffer = Buffer.from(signature.replace("sha256=", ""))

  if (expectedBuffer.length !== signatureBuffer.length) return false
  return timingSafeEqual(expectedBuffer, signatureBuffer)
}

export async function POST(req: Request) {
  const body = await req.text()
  const sig = req.headers.get("x-webhook-signature") || ""

  if (!verifyWebhookSignature(body, sig, process.env.WEBHOOK_SECRET!)) {
    return Response.json({ error: "Invalid signature" }, { status: 400 })
  }

  const event = JSON.parse(body)

  // Idempotency: check if event already processed
  const existing = await db.event.findUnique({
    where: { eventId: event.id },
  })
  if (existing) {
    return Response.json({ status: "already processed" })
  }

  // Process and mark as done in a transaction
  await db.$transaction([
    db.order.update({ where: { id: event.orderId }, data: { ... } }),
    db.event.create({ data: { eventId: event.id } }),
  ])

  return Response.json({ status: "ok" })
}
```

---

### #11 Public Form (Contact, Newsletter)

```typescript
// 3 layers on every public form:
// 1. Zod validation server-side
// 2. Rate limiting (5/hour per IP)
// 3. CSRF token OR use server actions (Next.js)

const contactLimiter = rateLimit({ interval: 3600000, uniqueTokenPerInterval: 500 })

export async function POST(req: Request) {
  const ip = req.headers.get("x-forwarded-for") || "unknown"
  const { isRateLimited } = contactLimiter.check(5, ip)
  if (isRateLimited) {
    return Response.json({ error: "Rate limited" }, { status: 429 })
  }

  const schema = z.object({
    name: z.string().min(1).max(100),
    email: z.string().email().max(255),
    message: z.string().min(10).max(5000),
  })

  const parsed = schema.safeParse(await req.json())
  if (!parsed.success) {
    return Response.json({ error: "Invalid input" }, { status: 400 })
  }

  // Process...
}
```

---

### #12 Password Reset

```typescript
// Rules for password reset flow:
// 1. Token is single-use, stored hashed
// 2. Token expires in 15-60 minutes
// 3. Same response whether email exists or not (prevents enumeration)
// 4. Rate limit the request endpoint
// 5. Invalidate all sessions after password change

import { randomBytes, createHash } from "crypto"

export async function generateResetToken(userId: string) {
  const token = randomBytes(32).toString("hex")
  const hashedToken = createHash("sha256").update(token).digest("hex")
  const expires = new Date(Date.now() + 15 * 60 * 1000) // 15 min

  await db.passwordResetToken.create({
    data: { userId, token: hashedToken, expires },
  })

  return token // send this in email
}

// Always respond the same way
export async function requestPasswordReset(email: string) {
  const user = await db.user.findUnique({ where: { email } })
  if (user) {
    const token = await generateResetToken(user.id)
    // await sendResetEmail(email, token)
  }
  // Return same message regardless
  return { message: "If that email exists, we sent a reset link." }
}
```

---

### #13 Middleware

When detecting middleware.ts, ensure these are present:

```typescript
// middleware.ts - Complete secure middleware
import { NextResponse } from "next/server"
import type { NextRequest } from "next/server"

const securityHeaders = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-XSS-Protection": "0",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Content-Security-Policy": [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: https:",
    "font-src 'self'",
    "connect-src 'self'",
  ].join("; "),
}

export function middleware(req: NextRequest) {
  const res = NextResponse.next()

  // Apply security headers
  Object.entries(securityHeaders).forEach(([key, value]) => {
    res.headers.set(key, value)
  })

  return res
}

export const config = {
  matcher: "/((?!_next/static|_next/image|favicon.ico).*)",
}
```

---

### #14 OAuth / Social Login

```typescript
// When detecting OAuth setup, verify:
// 1. redirect_uri is validated (exact match only)
// 2. state parameter is used (prevents CSRF on OAuth callback)
// 3. PKCE is used for SPA / mobile (code_challenge + code_verifier)
// 4. Never expose client_secret on client side

// With NextAuth.js, these are handled. Verify config:
export const authConfig = {
  providers: [
    Google({
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    }),
  ],
  callbacks: {
    signIn: async ({ account, profile }) => {
      // Verify the email is verified by the provider
      if (account?.provider === "google") {
        return !!(profile as any).email_verified
      }
      return true
    },
  },
}
```

---

### #15 Environment Variables & Secrets

When detecting secrets exposure:

```
BEFORE PUSHING: Scan for patterns:
- const KEY = "sk-"           ❌
- const SECRET = "ghp_"       ❌
- .env file staged in git     ❌
- NEXT_PUBLIC_ prefixed for private keys  ❌

ACTIONS:
1. Move raw keys to .env (never committed)
2. Create .env.example (safe to commit)
3. For Next.js: only NEXT_PUBLIC_* vars are visible to client
4. Regenerate any exposed keys immediately
```

```gitignore
# Ensure .gitignore contains:
.env
.env*.local
```

```
# .env.example (safe to commit):
DATABASE_URL="postgresql://..."
NEXTAUTH_SECRET="openssl rand -base64 32"
NEXTAUTH_URL="http://localhost:3000"
NEXT_PUBLIC_APP_URL="http://localhost:3000"
STRIPE_SECRET_KEY="sk_live_..."
STRIPE_WEBHOOK_SECRET="whsec_..."
GOOGLE_CLIENT_ID="..."
GOOGLE_CLIENT_SECRET="..."
```

---

### #16 New Project Bootstrap

When detecting a fresh project, inject baseline security:

```bash
# 1. Create .gitignore with .env
# 2. Create .env.example
# 3. Generate NEXTAUTH_SECRET
openssl rand -base64 32

# 4. Run dependency audit
npm audit

# 5. Add security headers to next.config.ts (see #13)
# 6. Set session cookie config in Auth.js
```

```typescript
// auth.ts - Secure session config
export const authOptions: NextAuthConfig = {
  session: {
    strategy: "jwt",
    maxAge: 7 * 24 * 60 * 60, // 7 days
  },
  cookies: {
    sessionToken: {
      name: process.env.NODE_ENV === "production"
        ? "__Secure-next-auth.session-token"
        : "next-auth.session-token",
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: process.env.NODE_ENV === "production",
      },
    },
  },
}
```

---

## Audit Command

When user explicitly says `security audit` or `secure my app`:

### Step 1: Scan the project for the current framework
Check `package.json` for: next, react, express, remix, nuxt, svelte, etc.

### Step 2: Read key files
- `middleware.ts` or server entry
- `next.config.ts` / `next.config.js`
- Any files in `app/api/` or `pages/api/`
- Any file containing prisma or drizzle imports
- `.gitignore`
- Any `auth.ts` or `[...nextauth]` file

### Step 3: Report with severity
```
RED CIRCLE  CRITICAL - Fix immediately
YELLOW CIRCLE  WARNING - Fix before deploy
GREEN CIRCLE  OK - No issues
```

### Step 4: Apply all fixes automatically
After reporting, ask: "Apply all fixes?" and proceed to edit each file.
