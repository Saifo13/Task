# Attack Logbook — Detection Engineering Section

Target: OWASP Juice Shop local Docker lab  
Local URL: `http://localhost:3000`  
Evidence sources: Browser Developer Tools screenshots, exported HAR file, and Docker container logs.

## Attack 1: Reconnaissance and Route Probing

Date/Time: 24 June 2026, approximately 12:52-12:54 UTC  
Attack class: Scanning / reconnaissance  
MITRE ATT&CK ID: T1595 / T1595.003  
Endpoints observed:
- `/admin`
- `/ftp`
- `/api`
- `/rest`

Observed response:
- `/ftp` returned a directory listing.
- `/api` returned HTTP 500 and an "Unexpected path: /api" error page.
- `/rest` returned HTTP 500 and an "Unexpected path: /rest" error in Docker logs.
- `/ftp/suspicious_errors.yml` returned HTTP 403 and generated a file validation error.

Evidence:
- `evidence/screenshots/02-admin-route-probe.png`
- `evidence/screenshots/03-ftp-directory-listing.png`
- `evidence/screenshots/04-api-unexpected-path-error.png`
- `evidence/logs/docker-logs.txt`
- `evidence/logs/har-interesting-requests.csv`

Detection status: Detected / Partial  
Notes: The Docker logs confirm unexpected route access, but they do not provide clean structured access-log fields such as source IP, user ID, request method, and full request context. This is useful evidence but not enough for complete incident response by itself.

## Attack 2: Directory Listing and Restricted File Access

Date/Time: 24 June 2026, approximately 12:52-12:53 UTC  
Attack class: Directory exposure / restricted file probing  
MITRE ATT&CK ID: T1595.003  
Endpoints observed:
- `/ftp`
- `/ftp/acquisitions.md`
- `/ftp/announcement_encrypted.md`
- `/ftp/legal.md`
- `/ftp/suspicious_errors.yml`

Observed response:
- The `/ftp` endpoint exposed a visible directory listing.
- Several Markdown files returned HTTP 200.
- The `.yml` file returned HTTP 403 and triggered the Docker log message "Only .md and .pdf files are allowed!"

Evidence:
- `evidence/screenshots/03-ftp-directory-listing.png`
- `evidence/logs/docker-logs.txt`
- `evidence/logs/localhost.har`

Detection status: Detected  
Notes: In a Sohail-style platform, public listing of internal folders could expose internship documents, task files, client materials, or configuration references.

## Attack 3: Authentication Abuse / Repeated Failed Logins

Date/Time: 24 June 2026, approximately 12:55 UTC  
Attack class: Authentication abuse / password guessing  
MITRE ATT&CK ID: T1110 / T1110.001  
Endpoint:
- `POST /rest/user/login`

Observed response:
- Eight failed login attempts were recorded with HTTP 401 responses.
- The same target email pattern was used repeatedly with different passwords.

Evidence:
- `evidence/screenshots/05-failed-login-attempt-1.png`
- `evidence/screenshots/06-failed-login-attempt-2.png`
- `evidence/screenshots/07-failed-login-request-headers.png`
- `evidence/screenshots/08-failed-login-attempt-4.png`
- `evidence/screenshots/09-failed-login-attempt-5.png`
- `evidence/logs/har-interesting-requests.csv`

Detection status: Detected  
Notes: This attack is visible in request logs because repeated failed POST requests to the login endpoint create a clear pattern.

## Attack 4: SQL Injection Login Bypass

Date/Time: 24 June 2026, approximately 12:55 UTC  
Attack class: SQL Injection / authentication bypass  
MITRE ATT&CK ID: T1190  
Endpoint:
- `POST /rest/user/login`

Payload indicator:
- Email field contained SQL-like logic: `' OR 1=1--`

Observed response:
- The login request returned HTTP 200.
- The lab showed the admin account menu after the injection attempt.
- Docker logs recorded the "Login Admin" challenge as solved.

Evidence:
- `evidence/screenshots/10-sql-injection-login-payload.png`
- `evidence/screenshots/11-sqli-admin-session.png`
- `evidence/screenshots/16-whoami-admin-json.png`
- `evidence/logs/docker-logs.txt`
- `evidence/logs/har-interesting-requests.csv`

Detection status: Detected  
Notes: This is the highest-impact confirmed lab attack because a crafted login input led to an authenticated admin session in the training environment.

## Attack 5: Cross-Site Scripting Payload in Search

Date/Time: 24 June 2026, approximately 12:57 UTC  
Attack class: XSS / script injection  
MITRE ATT&CK ID: T1190  
Input point:
- Search field in the Juice Shop web interface

Payload indicators:
- `<script>alert(1)</script>`
- `<img src=x onerror=alert(1)>`

Observed response:
- The `<img>` payload triggered a browser alert with value `1`.
- The browser attempted to request `/x` after processing the injected image source.

Evidence:
- `evidence/screenshots/12-xss-script-search-payload.png`
- `evidence/screenshots/14-xss-img-onerror-alert.png`
- `evidence/screenshots/15-xss-request-x-network.png`

Detection status: Detected / Partial  
Notes: The evidence is clear in the browser, but the HAR export does not preserve all SPA hash-route search input as a normal backend request. For Sohail, XSS detection should include proxy logs, application input logs, and output-encoding tests.

## Attack 6: Broken Access Control / IDOR Visibility Gap

Date/Time: 24 June 2026  
Attack class: Broken access control / IDOR detection gap  
MITRE ATT&CK ID: T1190  
Observed indicator:
- `/rest/user/whoami` returned admin account information after the SQL injection login bypass.

Evidence:
- `evidence/screenshots/16-whoami-admin-json.png`
- `evidence/logs/localhost.har`

Detection status: Gap / Requires application-level logging  
Notes: No confirmed IDOR exploit was reproduced in the submitted evidence. However, this is still an important defensive gap. Basic web logs cannot reliably detect IDOR because the request may look normal unless the application logs `user_id`, `requested_resource_id`, `resource_owner_id`, role, and authorization decision.
