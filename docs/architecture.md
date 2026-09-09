# Architecture

## Objective
Provide an auditable, read-only security baseline pipeline that separates data collection from control evaluation. The current implementation consumes synthetic JSON, making the project safe to inspect and test without Azure credentials.

## Components

1. **Inventory input** — identities, subscription logging, network rules, storage accounts, and key vault metadata.
2. **Control engine** — deterministic checks in `src/baseline.py`.
3. **Finding model** — normalized control ID, severity, resource, evidence, remediation, and optional ATT&CK context.
4. **Summary layer** — severity counts suitable for downstream reporting.
5. **Validation layer** — unit tests exercise both positive findings and non-findings.

## Design principles
- Read-only analysis
- Explainable findings
- Stable control identifiers
- No dependency on secrets or live cloud access
- Evidence attached to each result
- Remediation guidance paired with validation expectations

## Production extension pattern
A real implementation should introduce a collector interface that obtains inventory through approved Azure APIs using least-privilege read permissions. Collector code should remain separate from the policy engine so the same tests can run against fixtures.

## Trust boundaries
The baseline engine treats input as untrusted configuration data. Future adapters should validate schema, bound collection scope, avoid logging sensitive values, and record collection timestamp/subscription scope for evidence quality.
