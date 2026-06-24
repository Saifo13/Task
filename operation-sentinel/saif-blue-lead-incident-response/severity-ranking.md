# Severity Ranking

| Rank | Attack Class | Severity | Reason |
|---|---|---|---|
| 1 | SQL Injection Login Bypass | Critical | The lab evidence showed a SQL-like login payload returning HTTP 200 and an admin session. In Sohail, this could expose or modify student records, evaluations, and admin functions. |
| 2 | Broken Access Control / IDOR | Critical | Even though the lab evidence is a gap rather than a confirmed exploit, this is critical for Sohail because student submissions, evaluations, and files must never be accessible across users. |
| 3 | Authentication Abuse | High | Repeated failed logins could become account takeover if rate limiting, lockout, and MFA are weak. Admin and mentor accounts would be especially sensitive. |
| 4 | XSS Payload | Medium-High | XSS could affect dashboard users, steal sessions, or manipulate pages if stored or reflected in search, reviews, comments, or evaluations. |
| 5 | Directory Listing / Restricted File Access | Medium-High | Public file exposure could leak internal documents, configuration references, or student/client material. |
| 6 | Reconnaissance / Route Probing | Medium | Recon alone may not cause damage, but it reveals exposed routes and usually comes before exploitation. |
