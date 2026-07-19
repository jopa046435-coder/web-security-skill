# Web Security Patterns

**You build. This secures. Automatically.**

A comprehensive web security guide that works with any AI coding tool (Cursor, Copilot, Windsurf, Claude, ChatGPT, OpenCode). Drop the SKILL.md into your project and your AI assistant auto-detects what you're building and injects the right security patterns.

> Built for vibe coders using Next.js, React, Express, and modern full-stack frameworks.

## How It Works (Not a Reference. An Engine.)

| You build | AI detects | It injects |
|---|---|---|
| Login form | Sees `bcrypt`, `signup` | Adds rate limiting, Zod validation, session cookie hardening |
| API route | Sees `route.ts`, `handler` | Adds auth guard, input validation, IDOR prevention |
| File upload | Sees `formData`, `multer` | Adds type/size/path checks, safe filenames |
| DB query | Sees `$queryRawUnsafe` | Replaces with parameterized queries |
| Payment page | Sees `stripe`, `checkout` | Server-validates prices, verifies webhook sigs |
| Comments/UGC | Sees `textarea`, `comment` | Adds XSS sanitization, rate limiting |
| Admin panel | Sees `/admin`, `dashboard` | Adds role check, audit logging |

## 16 Auto-Apply Patterns

1. Auth Flow (login/signup)
2. API Route Guard
3. File Upload
4. Database Query
5. Payment/Checkout
6. User Profile/Settings
7. User Generated Content
8. Search
9. Admin/Dashboard
10. Webhook Endpoint
11. Public Forms
12. Password Reset
13. Middleware + Headers
14. OAuth/Social Login
15. Environment Secrets
16. New Project Bootstrap

## Quick Start

Drop `SKILL.md` into your project folder and tell your AI:

```
secure my app
security audit
check security for login form
fix file upload security
```

The AI reads the patterns and applies them to your codebase immediately.

## License

MIT
