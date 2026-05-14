# Fleuris Vault
Secure Banking Platform
By Raghav Verma (rave271)

A Flask-based fintech demo that hardens a simple banking app with OWASP-style controls: password hashing, lockout, CSRF protection, access control, security headers, and audit logging.

## Features

- Customer dashboard, transfers, and statements
- Admin security center and file-based security log view
- Brute-force lockout and CSRF protection
- Parameterized queries to reduce SQL injection risk
- Security headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)

## Quick Start (Local)

```bash
cd student_folder/grp8/src
python3 app.py
```

Open: http://127.0.0.1:5001
Deployment Link: https://fleuris.onrender.com/

## Demo Accounts


- aryan / pass
- raghav / Admin@123 (admin)

## Admin Pages

- /security -> Security Center (DB-backed events)
- /security-log -> File-based log view (tail/refresh controls)
- /users -> Customer listing

## Notes

- The SQLite database is created locally as bank.db and is ignored by git.
- The file-based security log (security.log) is local and resets on redeploys.

## Render Deployment

See RENDER_DEPLOYMENT.md for settings and environment variables.
