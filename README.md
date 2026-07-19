# Web Security Skill for Vibe Coders

An OpenCode skill that automatically secures your web projects as you build. No security knowledge required -- just tell OpenCode to `secure my app` and it audits + fixes everything.

> Built for vibe coders using Next.js, React, Express, and modern full-stack frameworks. You build fast. This keeps it safe.

## Why This Exists

Vibe coders ship at incredible speed with AI -- but security is an afterthought. This skill brings security into your workflow automatically:

- **Catches leaked API keys** before they hit GitHub
- **Protects API routes** that you forgot to authenticate
- **Hardens file uploads** against common exploits
- **Adds security headers** in one config block
- **Prevents XSS, SQLi, CSRF** with copy-paste patterns

## Quick Start

1. Add `SKILL.md` to your OpenCode skills folder
2. In any web project, type: `secure my app`
3. The skill audits your codebase and gives you fixes

## Trigger Commands

| Command | What it does |
|---------|-------------|
| `secure my app` | Full project security audit |
| `security audit` | Run through checklist, report issues |
| `check security` | Quick scan for common mistakes |
| `auth` | Set up proper authentication |
| `fix upload` | Harden file upload handling |
| `headers` | Add security headers config |
| `secrets` | Check for leaked keys/tokens |

## What Gets Fixed

- Authentication & authorization gaps
- Environment variable leaks
- XSS (dangerouslySetInnerHTML etc.)
- SQL injection (raw query strings)
- File upload vulnerabilities
- Missing CSRF protection
- Missing rate limiting
- Missing security headers
- Unsafe dependency versions

## For Devs, Not Hackers

This is a **defensive** security skill. It teaches secure-by-default patterns for modern frameworks. No exploit scripts, no attack methodology -- just patterns that keep your users and data safe.

```
Build fast -> OpenCode checks security -> Ship safe
```

## License

MIT
