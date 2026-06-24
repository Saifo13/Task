# Attack-to-Detection Mapping Table

| Attack Class | Data Source | Triggering Indicator | Detection Logic | MITRE ATT&CK ID | Detection Status |
|---|---|---|---|---|---|
| Reconnaissance / route probing | Docker logs, HAR, DevTools Network | Requests to `/admin`, `/api`, `/rest`, `/ftp`; 500 errors for unexpected paths | Alert when one source requests multiple uncommon paths or backend-style routes in a short time window | T1595 / T1595.003 | Detected / Partial |
| Directory listing / restricted file probing | HAR, Docker logs, screenshots | `/ftp` directory listing; requests for `.bak`, `.md`, `.yml`, or restricted files | Alert when public users request backup/config-like files or a directory listing endpoint | T1595.003 | Detected |
| Authentication abuse | HAR, DevTools Network | Repeated `POST /rest/user/login` requests returning HTTP 401 | Alert after 5 failed logins from same source or against same email within 5 minutes | T1110 / T1110.001 | Detected |
| SQL injection login bypass | HAR, DevTools Network, Docker logs | Login request contains SQL operators such as `' OR`, `1=1`, or `--`, followed by HTTP 200 | Alert when SQL-like payload appears in login/search/form parameters, especially followed by successful authentication | T1190 | Detected |
| XSS payload submission | Screenshots, DevTools Network | Search input contains `<script>`, `onerror=`, `alert(`, or encoded HTML/JS; browser alert triggered | Alert when script-like payload appears in a user-controlled input or causes a browser request such as `/x` from injected markup | T1190 | Detected / Partial |
| Broken access control / IDOR | Application authorization logs required | User requests resource not owned by them or receives data outside role scope | Alert when `user_id != resource_owner_id`, denied authorization repeats, or role does not match requested resource | T1190 | Gap: not visible enough in basic logs |
