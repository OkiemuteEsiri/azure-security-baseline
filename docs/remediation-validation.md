# Remediation and Validation Playbook

## Identity
**Finding:** privileged identity lacks MFA or has standing Global Administrator access.

**Remediation:** require approved strong MFA; convert standing privilege to eligible/time-bound access where operationally feasible; document emergency-access exceptions.

**Validation evidence:** policy assignment, eligible-role configuration, successful control re-run, and approved exception record where applicable.

## Logging
**Finding:** activity logs are not exported or retention is below policy.

**Remediation:** export logs to the approved analytics/archive destination and align retention with governance requirements.

**Validation evidence:** destination configuration, recent ingested event, retention setting, and monitoring ownership.

## Network
**Finding:** SSH/RDP reachable from `0.0.0.0/0`.

**Remediation:** restrict the source, use private administration paths, or implement approved just-in-time management.

**Validation evidence:** revised rule set plus a re-run showing `AZ-NET-001` cleared.

## Storage
**Finding:** anonymous blob access or insecure transport permitted.

**Remediation:** disable public access unless formally required; enforce secure transfer.

**Validation evidence:** configuration state, anonymous-access denial test in an authorized environment, and baseline re-run.

## Key management
**Finding:** no key-rotation lifecycle.

**Remediation:** establish a rotation schedule appropriate to key use and application dependencies.

**Validation evidence:** rotation policy plus evidence of successful key-version lifecycle.

## Closure criteria
A finding is closed only when the configuration has changed, the control re-run no longer reports the condition, and required governance evidence is attached. Compensating controls must be explicitly recorded rather than silently treated as remediation.
