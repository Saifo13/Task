# Incident Response Playbook — Saif Blue Lead Section

Methodology: This playbook follows the incident response flow requested for Operation Sentinel: Prepare, Detect, Contain, Eradicate, Recover, and Lessons Learned. The goal is to convert detection findings into practical response steps for Sohail's future platform.

## Incident Type 1: Reconnaissance and Route Probing

Severity: Medium

Detection Source:
Reconnaissance rule triggered by multiple requests to `/admin`, `/api`, `/rest`, `/ftp`, or unexpected paths.

Triage:
- Confirm source IP, request time, requested paths, status codes, and user agent.
- Check whether the same source later attempted SQL injection, XSS, or login abuse.
- Review whether exposed routes revealed stack traces, directory listings, or sensitive files.

Containment:
- Rate-limit the source if probing is repeated.
- Block the source IP if the traffic is clearly malicious.
- Restrict exposed routes and remove unnecessary public endpoints.

Eradication:
- Disable unused routes.
- Remove public directory listings.
- Replace verbose error pages with generic error handling.
- Review server routing rules.

Recovery:
- Re-test the probed routes and confirm they no longer expose unnecessary information.
- Review logs for follow-up exploitation attempts.
- Update detection thresholds if too noisy or too weak.

Lessons Learned:
- Reconnaissance is often the first sign of later exploitation.
- Sohail should treat scanning as an early warning, not only as background noise.

## Incident Type 2: Directory Listing or Restricted File Access

Severity: Medium-High

Detection Source:
Directory listing or restricted file probing rule triggered by `/ftp`, backup-style files, or restricted extensions.

Triage:
- Identify which files were requested.
- Check whether files contained sensitive content, credentials, internal notes, or configuration references.
- Confirm whether access was allowed or blocked.

Containment:
- Disable public directory listing.
- Remove backup/configuration files from public folders.
- Temporarily restrict the affected directory.

Eradication:
- Move internal documents to private storage.
- Add web server rules that block backup, key, config, and database file extensions.
- Ensure error messages do not reveal internal file paths.

Recovery:
- Rotate any exposed secrets if sensitive files were downloaded.
- Restore safe folder permissions.
- Verify that only approved public files are reachable.

Lessons Learned:
- Public file exposure can create business risk even without direct system compromise.
- Sohail should review public storage and file permissions before launch.

## Incident Type 3: Authentication Abuse

Severity: High

Detection Source:
Repeated failed login rule triggered by multiple HTTP 401 responses from `POST /rest/user/login`.

Triage:
- Identify source IP, target account/email, number of attempts, and time window.
- Check whether any later login succeeded.
- Review whether password reset or MFA events occurred.

Containment:
- Temporarily rate-limit or block the source.
- Lock the targeted account if the volume is high or repeated.
- Alert the account owner or admin if a real user account is targeted.

Eradication:
- Enforce rate limits and account lockout thresholds.
- Add MFA for admin, mentor, and operations roles.
- Add breached-password checks and stronger password policy.

Recovery:
- Reset credentials if compromise is suspected.
- Revoke active sessions for the affected account.
- Confirm normal login activity has resumed.

Lessons Learned:
- Authentication logs must include username/email, source IP, success/failure, timestamp, and device information.
- Sohail should monitor login patterns before onboarding students and admins.

## Incident Type 4: SQL Injection Login Bypass

Severity: Critical

Detection Source:
SQL injection rule triggered by SQL-like input in the login form and followed by successful authentication.

Triage:
- Confirm the endpoint, payload, source IP, timestamp, and response code.
- Check whether the login bypass created an admin or privileged session.
- Review database activity after the event.
- Determine whether student records, evaluations, files, or payment data were accessed.

Containment:
- Immediately disable or restrict the affected login endpoint if exploitation is confirmed.
- Revoke the attacker's session and any related tokens.
- Temporarily force admin re-authentication.

Eradication:
- Replace unsafe SQL construction with parameterized queries.
- Add server-side input validation.
- Remove verbose database or stack-trace errors.
- Review all similar authentication and search queries.

Recovery:
- Test the patched login endpoint with safe negative tests.
- Review database integrity and restore modified records if needed.
- Re-enable the endpoint only after validation.

Lessons Learned:
- SQL injection is a direct path from input validation failure to account or data compromise.
- Sohail should make parameterized queries and secure coding review mandatory.

## Incident Type 5: Cross-Site Scripting Payload

Severity: Medium-High

Detection Source:
XSS rule triggered by `<script>`, `onerror=`, `alert(`, or encoded script-like input in a search/comment field.

Triage:
- Identify where the payload was submitted.
- Determine whether the payload was reflected or stored.
- Check whether any admin, mentor, or student viewed the affected page.
- Review whether session cookies or tokens may have been exposed.

Containment:
- Remove or neutralize the malicious input.
- Temporarily disable the affected field if the payload is stored.
- Invalidate sessions if session theft is suspected.

Eradication:
- Apply context-aware output encoding.
- Sanitize rich-text input if rich text is required.
- Add Content Security Policy where possible.
- Add XSS test cases to QA.

Recovery:
- Re-enable the affected feature after testing.
- Confirm the payload is rendered as text, not executed as code.
- Monitor for repeated XSS attempts.

Lessons Learned:
- Input validation alone is not enough; output encoding is needed.
- Sohail should review all user-generated content fields, especially evaluations and comments.

## Incident Type 6: Broken Access Control / IDOR

Severity: Critical

Detection Source:
Application authorization log showing user/resource ownership mismatch. Current lab evidence shows this as a visibility gap rather than a confirmed IDOR exploit.

Triage:
- Identify user ID, role, requested resource ID, resource owner, endpoint, and authorization result.
- Determine whether access was allowed or denied.
- Review whether submissions, evaluations, profiles, or files were exposed.

Containment:
- Disable the affected endpoint or account if unauthorized access is confirmed.
- Restrict access to the affected resource type.
- Rotate exposed file links if file access is involved.

Eradication:
- Enforce backend object-level authorization on every request.
- Add role, ownership, and assignment checks.
- Remove reliance on frontend button hiding.
- Add automated tests for horizontal and vertical access control.

Recovery:
- Review affected records and notify leadership if student data was exposed.
- Re-enable the endpoint after authorization tests pass.
- Add monitoring for denied access and owner mismatch events.

Lessons Learned:
- IDOR is hard to detect without proper application-level logs.
- Sohail's highest-priority logging improvement is authorization decision logging.
