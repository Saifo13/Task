# Evidence Manifest

## Logs
- `evidence/logs/docker-logs.txt` — Docker container output showing route errors, unauthorized access, challenge completion, and file validation errors.
- `evidence/logs/localhost.har` — Browser Developer Tools HAR export from the Juice Shop lab.
- `evidence/logs/har-interesting-requests.csv` — Filtered list of relevant HAR requests.

## Screenshots
- `01-home-network-tab.png` — Juice Shop home page with Network tab.
- `02-admin-route-probe.png` — `/admin` route probe.
- `03-ftp-directory-listing.png` — `/ftp` directory listing.
- `04-api-unexpected-path-error.png` — `/api` 500 unexpected path error.
- `05-failed-login-attempt-1.png` to `09-failed-login-attempt-5.png` — repeated failed login evidence.
- `10-sql-injection-login-payload.png` — SQL injection style login payload.
- `11-sqli-admin-session.png` — admin session visible after injection.
- `12-xss-script-search-payload.png` — script payload in search.
- `14-xss-img-onerror-alert.png` — XSS alert popup.
- `15-xss-request-x-network.png` — network evidence from injected image source.
- `16-whoami-admin-json.png` — `/rest/user/whoami` JSON showing admin user after login bypass.
