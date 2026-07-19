# Web Security Skill for OpenCode

A comprehensive, ready-to-use web security skill for [OpenCode](https://opencode.ai). Covers the complete web security testing methodology -- from recon to exploitation to secure coding.

## Features

- **OWASP Top 10** coverage (injection, broken auth, XSS, IDOR, SSRF, CSRF, etc.)
- **Practical exploit examples** with real curl/http commands
- **Bypass techniques** for WAF, filters, and common defenses
- **API security** testing (REST, GraphQL)
- **Secure coding patterns** with Python examples
- **10-step testing methodology** checklist
- **Tool reference** table

## Install

Copy `SKILL.md` to your OpenCode skills directory:

```
~/.config/opencode/skills/web-security/
```

Or drop it into any skill directory scanned by OpenCode.

## Usage

Once loaded, trigger with keywords like:

- `web security`, `XSS`, `SQL injection`, `CSRF`, `SSRF`, `IDOR`
- `LFI`, `XXE`, `SSTI`, `JWT`, `CORS`, `auth bypass`
- `secure coding`, `OWASP`, `threat model`

## Structure

| Section | Content |
|---------|---------|
| 1. Recon | Passive/active information gathering |
| 2. Auth | Authentication & authorization testing |
| 3. Injection | SQLi, XSS, SSTI, command injection |
| 4. Files | LFI, file upload, XXE |
| 5. CSRF/SSRF | Request forgery attacks |
| 6. Headers | CORS, CSP, security headers |
| 7. APIs | REST/GraphQL security testing |
| 8. Logic | Business logic flaws |
| 9. Methodology | Step-by-step testing process |
| 10. Defense | Secure coding patterns |

## License

MIT
