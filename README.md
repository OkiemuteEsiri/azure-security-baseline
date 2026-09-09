# Azure Security Baseline

A defensive cloud-security engineering project for evaluating Azure tenant and subscription posture from synthetic configuration data. The project converts common control expectations into repeatable checks, produces explainable findings, and demonstrates how cloud posture can be governed without touching production environments.

## Security problem
Azure estates can accumulate configuration drift across identity, logging, networking, storage, and key management. A useful baseline must do more than list controls: it should identify exceptions, assign consistent severity, explain business impact, and provide evidence for remediation validation.

## What this project demonstrates
- Azure security posture engineering
- Identity and privileged-access review
- Logging and monitoring assurance
- Storage and network exposure analysis
- Key-management and encryption checks
- Explainable risk scoring
- Synthetic-data-driven testing
- Remediation and revalidation workflow
- CI-backed unit testing

## Architecture

```text
Synthetic Azure inventory
        |
        v
src/baseline.py
  |-- identity checks
  |-- logging checks
  |-- network checks
  |-- storage checks
  |-- key-management checks
        |
        v
Normalized findings
        |
        +--> severity / control / evidence
        +--> remediation guidance
        +--> posture summary
```

## Implemented controls

| Domain | Example control | Risk addressed |
|---|---|---|
| Identity | MFA required for privileged identities | Account takeover / T1078 Valid Accounts |
| Identity | No standing Global Administrator access | Excessive privilege |
| Logging | Activity logs retained and exported | Insufficient forensic visibility |
| Network | No unrestricted management exposure | External attack surface |
| Storage | Public blob access disabled | Data exposure |
| Storage | Secure transfer required | Cleartext transport |
| Key management | Key rotation configured | Long-lived cryptographic material |

## Run

```bash
python -m src.baseline data/synthetic_azure.json
python -m unittest discover -s tests -v
```

## Example output

```text
HIGH     AZ-ID-001  Privileged identity does not require MFA
HIGH     AZ-NET-001 Management port exposed to 0.0.0.0/0
MEDIUM   AZ-LOG-001 Activity-log retention below policy
```

## Repository structure

```text
azure-security-baseline/
├── src/baseline.py
├── data/synthetic_azure.json
├── tests/test_baseline.py
├── docs/architecture.md
├── docs/remediation-validation.md
├── reports/example-assessment.md
└── .github/workflows/tests.yml
```

## Risk model
Findings are classified as Critical, High, Medium, or Low using control impact and exposure context. The project intentionally keeps the logic transparent rather than presenting a black-box score.

## MITRE ATT&CK context
Where relevant, identity findings map defensively to ATT&CK techniques such as **T1078 Valid Accounts** and cloud-account abuse concepts. ATT&CK mappings are used to explain detection and prevention value, not to provide exploitation procedures.

## Safety and scope
This repository uses synthetic tenant data only. It contains no credentials, tenant identifiers, production endpoints, exploit code, or instructions for bypassing Azure controls.

## Skills demonstrated
Cloud security engineering, Azure posture management, IAM review, Python, security control design, risk communication, testing, remediation validation, and CI/CD.

## Roadmap
- Add policy-as-code export
- Add control coverage metrics
- Add Azure resource graph adapter interface
- Add executive HTML/JSON reporting
- Add exception-expiry governance
