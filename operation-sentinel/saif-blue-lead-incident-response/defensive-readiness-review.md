# Defensive Readiness Review

The Operation Sentinel lab shows that Sohail can detect several common web attack patterns if request-level logs are available. SQL injection, XSS, route probing, directory listing, and repeated failed login attempts create visible indicators in request URLs, request bodies, status codes, or application error logs.

The strongest detection coverage is for pattern-based attacks. SQL injection is visible through strings such as `' OR`, `1=1`, and SQL comment syntax. Authentication abuse is visible through repeated failed login requests. Reconnaissance is visible through unusual paths such as `/api`, `/rest`, `/admin`, and `/ftp`. XSS is partly visible through script-like payloads, although single-page application routes may not always appear clearly in backend logs.

The weakest area is broken access control and IDOR visibility. These attacks may look like normal requests unless the application logs authorization decisions. Basic Docker logs and browser traffic show endpoints and status codes, but they do not show whether the authenticated user should have been allowed to access a specific object. For Sohail, this is a major gap because the platform will involve student profiles, task submissions, feedback, evaluations, certificates, and eventually payments.

The single highest-priority gap is missing application-level authorization logging. Sohail should log user ID, role, requested resource ID, resource owner ID, endpoint, authorization result, and denial reason. Without these fields, the incident response playbook cannot reliably answer who accessed what, whether access was allowed, and whether student data was exposed.

Overall readiness is partial. The lab provides enough evidence to create practical detection rules and response procedures, but Sohail would need centralized logs, structured application events, alert thresholds, and a tested incident response process before launch.
