# Web Security Patterns

**Your AI ships code. This makes sure it's safe.**

The only web security skill that works as a behavior modifier — auto-detects what feature you're building and injects security patterns BEFORE you ship. Works with Cursor, Copilot, Claude Code, Windsurf, and any AI coding tool.

---

## How It Works

```
You write code → Skill detects feature → Injects security → You ship safe
```

| You build | AI sees | It injects |
|---|---|---|
| Login form | `bcrypt`, `signup` | Rate limiting, Zod validation, session hardening |
| API route | `route.ts` | Auth guard, input validation, IDOR prevention |
| File upload | `formData`, `multer` | Type/size/path validation, safe filenames |
| DB query | `$queryRawUnsafe` | Parameterized query replacement |
| Payment | `stripe`, `checkout` | Server-side prices, webhook verification |
| Comments | `dangerouslySetInnerHTML` | DOMPurify sanitization |
| Admin panel | `/admin`, `dashboard` | Role guard, session check |

## 16 Auto-Apply Patterns

A) Auth Flow · B) API Route Guard · C) File Upload · D) Database Query · E) Payment · F) User Profile · G) User Content · H) Search · I) Admin · J) Webhook · K) Public Forms · L) Password Reset · M) Middleware · N) OAuth · O) Secrets · P) Bootstrap

## Quick Start

Drop `SKILL.md` in your project and start coding. The skill activates automatically.

```
secure my app          → Full security audit
fix login security     → Pattern A applied
check API routes       → Pattern B applied
scan for secrets       → Pattern O applied
```

## License

MIT
