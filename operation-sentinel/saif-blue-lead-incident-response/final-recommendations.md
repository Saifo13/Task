# Final Recommendations

1. Centralize application, authentication, file access, and admin dashboard logs.
2. Log timestamp, source IP, user ID, role, endpoint, method, status code, requested resource ID, authorization result, and denial reason.
3. Add detection alerts for SQL injection, XSS payloads, repeated failed logins, route probing, directory listing, and IDOR attempts.
4. Enforce backend authorization checks for every student, mentor, admin, file, and evaluation request.
5. Replace unsafe database query construction with parameterized queries.
6. Apply server-side validation to all input fields.
7. Apply context-aware output encoding for all user-controlled content.
8. Disable public directory listings and remove internal files from public folders.
9. Use rate limiting on login, search, upload, and sensitive API endpoints.
10. Test the incident response playbook with simulated incidents before Sohail's wider platform launch.
