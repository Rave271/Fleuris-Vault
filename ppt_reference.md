# Fleuris Vault - PPT Reference Script

Use this as a slide-by-slide reference to generate a PowerPoint. Keep the look aligned with the app branding (dark background, red accent, gold highlights).

## Slide 1 - Title + Short Intro
Title: Fleuris Vault
Subtitle: Secure Banking Platform - upgraded from an unsafe banking reference
Short intro (2-3 lines):
- Flask-based digital banking demo with secure coding practices.
- Shows real defenses against common web vulnerabilities.
- Built for classroom evaluation and live security demo.

## Slide 2 - Project Explanation + Workflow
Title: Project Explanation and Workflow
Left side (project explanation):
- Supports login, dashboard, transfers, statements, admin review.
- Uses SQLite, Flask, Jinja templates, and audit logging.
- Security controls added across routes and forms.
Right side (workflow steps):
1. User logs in
2. Dashboard shows balance and transactions
3. Transfers validated and logged
4. Admin reviews users and security events
5. Security Demo Lab proves protections

## Slide 3 - Author
Title: Author
Use a short bio and responsibility list.
- Raghav Verma - Project lead, implementation, documentation, and security hardening

## Slide 4 - Vulnerability 1 of 6
Title: Security Misconfiguration (Missing Security Headers)
Author: Raghav Verma
Key points:
- Adds CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- Applied to every response using after_request
- Reduces clickjacking, MIME sniffing, and unsafe resource loading
Evidence callout:
- /security-demo shows header list

## Slide 5 - Vulnerability 2 of 6
Title: SQL Injection
Author: Raghav Verma
Key points:
- Parameterized queries with ? placeholders
- User input is treated as data, not SQL logic
- Example attack payload: ' OR '1'='1
Evidence callout:
- /security-demo SQL injection card

## Slide 6 - Vulnerability 3 of 6
Title: Brute Force Login Attempts
Author: Raghav Verma
Key points:
- Failed attempts counted per user
- Account locks after 5 failed attempts
- Lockout is temporary (10 minutes)
Evidence callout:
- Security log events: LOGIN_FAILED, LOGIN_LOCKED

## Slide 7 - Vulnerability 4 of 6
Title: CSRF on Money Transfers
Author: Raghav Verma
Key points:
- CSRF token generated per session
- Token stored in session and checked on submit
- Missing or invalid token blocks request
Evidence callout:
- /security-demo CSRF card

## Slide 8 - Vulnerability 5 of 6
Title: Weak Password Storage
Author: Raghav Verma
Key points:
- Passwords stored as hashes using Werkzeug
- Login uses check_password_hash
- Legacy plain password column is not used
Evidence callout:
- Security demo shows hash previews

## Slide 9 - Vulnerability 6 of 6
Title: Broken Access Control
Assigned member: Raghav Verma
Key points:
- Ownership checks on statements
- Role-based protection for admin routes
- Unauthorized access returns 403 and logs ACCESS_DENIED
Evidence callout:
- /statement/2 as Alice -> 403

## Slide 10 - Thank You
Title: Thank You
Subtitle: Questions?
Optional footer: Fleuris Vault - Secure Banking Platform
