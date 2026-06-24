# Operation Sentinel — Sohail Platform Defensive Assessment

This package separates the work into the two required sections:

- `saif-detection-engineering/` — Detection Engineering section: attack logbook, detection rules, and attack-to-detection mapping.
- `saif-blue-lead-incident-response/` — Blue Lead section: incident response playbook, severity ranking, defensive readiness review, and final recommendations.

The target used for evidence was the local OWASP Juice Shop Docker lab at `http://localhost:3000`. The evidence folder contains the Docker logs, browser HAR export, and screenshots captured during the lab activity.

Scope note: All testing was performed against the local controlled lab. These steps are not intended for public systems.
