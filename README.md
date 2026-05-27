# Fleuris Vault
Cloud-Hosted Operational Analytics Platform
By Raghav Verma (rave271)

A Flask-based fintech demo upgraded into a single-instance operational analytics platform: PostgreSQL, structured JSON logs, ELK-ready observability, and PySpark batch analytics.

## Features

- Customer dashboard, transfers, and statements
- Admin security center and structured JSON log view
- PySpark batch analytics for endpoints, logins, response times, and user activity
- Admin-only traffic generator to create realistic log volume
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


- alex / pass
- morgan / pass
- raghav / 123 (admin)

## Admin Pages

- /security -> Security Center (DB-backed events)
- /security-log -> JSON log view (tail/refresh controls)
- /analytics -> Admin analytics dashboard
- /traffic-generator -> Admin traffic generator
- /users -> Customer listing

## Notes

- PostgreSQL is required locally or on the EC2 host. Configure via DATABASE_URL.
- Structured logs are written to logs/app.json.log.

## Render Deployment

See RENDER_DEPLOYMENT.md for Render settings and AWS_DEPLOYMENT.md for EC2 setup.
