# Example Azure Security Baseline Assessment

> Synthetic demonstration only. No real tenant or organization is represented.

## Executive summary
The sample inventory produced multiple control gaps concentrated in privileged identity governance, activity-log assurance, management-plane exposure, storage configuration, and key lifecycle management.

## Priority findings

| ID | Severity | Area | Finding | Validation target |
|---|---|---|---|---|
| AZ-ID-001 | High | Identity | Privileged account lacks required MFA | Policy covers privileged identity |
| AZ-ID-002 | High | Identity | Standing Global Administrator assignment | Time-bound eligible assignment |
| AZ-LOG-001 | High | Logging | Activity logs not exported | Recent events visible at approved destination |
| AZ-NET-001 | High | Network | RDP exposed to Internet | Approved source/private path only |
| AZ-STOR-001 | High | Storage | Public blob access enabled | Anonymous access disabled |
| AZ-LOG-002 | Medium | Logging | Retention below baseline | Retention meets policy |
| AZ-STOR-002 | Medium | Storage | Secure transfer not required | HTTPS-only requirement enabled |
| AZ-KEY-001 | Medium | Key management | No rotation lifecycle | Rotation policy configured |

## Recommended sequence
1. Protect privileged identity paths.
2. Remove unnecessary public management exposure.
3. Restore durable security telemetry.
4. Correct storage exposure/transport controls.
5. Establish key lifecycle governance.
6. Re-run the baseline and retain evidence of cleared findings.

## Governance note
Risk acceptance should identify owner, justification, compensating control, expiry date, and review authority. Exceptions should not be represented as remediated findings.
