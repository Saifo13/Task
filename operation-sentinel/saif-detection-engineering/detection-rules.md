# Detection Rules — Sigma-Style / Pseudo-SIEM

## Rule 1: Reconnaissance and Unexpected Route Access

```yaml
title: Juice Shop Reconnaissance and Unexpected Route Access
description: Detects probing of uncommon or backend-style routes.
logsource:
  category: web
detection:
  selection_paths:
    url|contains:
      - "/admin"
      - "/api"
      - "/rest"
      - "/ftp"
  selection_errors:
    status_code:
      - 403
      - 404
      - 500
  timeframe: 2m
  condition: selection_paths and count(source_ip) >= 4
fields:
  - timestamp
  - source_ip
  - method
  - url
  - status_code
level: medium
tags:
  - attack.T1595
```

## Rule 2: Directory Listing or Restricted File Probing

```yaml
title: Public Directory Listing or Restricted File Probing
description: Detects access to directory listing and backup/config-style files.
logsource:
  category: web
detection:
  selection:
    url|contains:
      - "/ftp"
      - ".bak"
      - ".yml"
      - ".kdbx"
      - "package.json"
      - "suspicious_errors"
  condition: selection
fields:
  - timestamp
  - source_ip
  - url
  - status_code
level: medium
tags:
  - attack.T1595.003
```

## Rule 3: Repeated Failed Login Attempts

```yaml
title: Repeated Failed Login Attempts
description: Detects possible password guessing or authentication abuse.
logsource:
  category: authentication
detection:
  selection:
    url|contains: "/rest/user/login"
    method: "POST"
    status_code: 401
  timeframe: 5m
  condition: count(source_ip) >= 5 or count(username) >= 5
fields:
  - timestamp
  - source_ip
  - username
  - url
  - status_code
level: high
tags:
  - attack.T1110
```

## Rule 4: SQL Injection Login Attempt

```yaml
title: SQL Injection Pattern in Login or Form Input
description: Detects SQL injection strings in user-controlled fields.
logsource:
  category: web
detection:
  selection:
    request_body|contains:
      - "' OR"
      - "1=1"
      - "--"
      - "UNION SELECT"
      - "DROP TABLE"
  condition: selection
fields:
  - timestamp
  - source_ip
  - method
  - url
  - request_body
  - status_code
level: high
tags:
  - attack.T1190
```

## Rule 5: XSS Payload Submitted

```yaml
title: Cross-Site Scripting Payload Submitted
description: Detects script-like input in search, review, profile, or comment fields.
logsource:
  category: web
detection:
  selection:
    request_body|contains:
      - "<script"
      - "onerror="
      - "javascript:"
      - "alert("
      - "%3Cscript"
      - "%3Cimg"
  condition: selection
fields:
  - timestamp
  - source_ip
  - user_id
  - url
  - request_body
level: medium
tags:
  - attack.T1190
```

## Rule 6: Possible IDOR or Broken Access Control Attempt

```yaml
title: Possible IDOR or Broken Access Control Attempt
description: Requires application-level authorization logging to detect ownership mismatch.
logsource:
  category: application
detection:
  selection:
    authorization_result: "denied"
    reason|contains:
      - "owner_mismatch"
      - "unauthorized_resource"
      - "invalid_resource_scope"
  condition: selection
fields:
  - timestamp
  - source_ip
  - user_id
  - role
  - requested_resource_id
  - resource_owner_id
  - authorization_result
  - reason
level: critical
tags:
  - attack.T1190
```

## Detection Gap Note

The IDOR rule cannot work with only basic Docker error logs. Sohail would need application-level authorization logs that record user identity, requested object, owner of that object, and whether access was allowed or denied.
