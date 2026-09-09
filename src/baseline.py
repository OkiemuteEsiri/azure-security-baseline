from __future__ import annotations

import json
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Finding:
    control_id: str
    severity: str
    resource: str
    title: str
    evidence: str
    remediation: str
    attack_mapping: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def evaluate_inventory(inventory: dict) -> list[Finding]:
    findings: list[Finding] = []

    for identity in inventory.get("identities", []):
        if identity.get("privileged") and not identity.get("mfa_required"):
            findings.append(Finding(
                "AZ-ID-001", "HIGH", identity["name"],
                "Privileged identity does not require MFA",
                "mfa_required=false",
                "Require phishing-resistant MFA for privileged identities and validate sign-in policy coverage.",
                "T1078 Valid Accounts",
            ))
        if identity.get("role") == "Global Administrator" and identity.get("assignment") == "permanent":
            findings.append(Finding(
                "AZ-ID-002", "HIGH", identity["name"],
                "Standing Global Administrator access",
                "assignment=permanent",
                "Replace standing privilege with eligible/time-bound privileged access and review break-glass exceptions.",
                "T1078 Valid Accounts",
            ))

    if "logging" in inventory:
        logging = inventory["logging"]
        if not logging.get("export_enabled", False):
            findings.append(Finding(
                "AZ-LOG-001", "HIGH", "subscription",
                "Activity logs are not exported",
                "export_enabled=false",
                "Export activity logs to a protected analytics/archive destination and validate ingestion.",
            ))
        if int(logging.get("retention_days", 0)) < 90:
            findings.append(Finding(
                "AZ-LOG-002", "MEDIUM", "subscription",
                "Activity-log retention below baseline",
                f"retention_days={logging.get('retention_days', 0)}",
                "Raise retention to the approved policy threshold and verify historical availability.",
            ))

    for rule in inventory.get("network_rules", []):
        if rule.get("source") == "0.0.0.0/0" and int(rule.get("port", 0)) in {22, 3389}:
            findings.append(Finding(
                "AZ-NET-001", "HIGH", rule["name"],
                "Management port exposed to the Internet",
                f"source={rule['source']} port={rule['port']}",
                "Restrict management access to approved administration paths, private connectivity, or just-in-time access.",
            ))

    for account in inventory.get("storage_accounts", []):
        if account.get("public_blob_access", False):
            findings.append(Finding(
                "AZ-STOR-001", "HIGH", account["name"],
                "Public blob access enabled",
                "public_blob_access=true",
                "Disable public blob access unless formally approved and validate anonymous access is denied.",
            ))
        if not account.get("secure_transfer_required", True):
            findings.append(Finding(
                "AZ-STOR-002", "MEDIUM", account["name"],
                "Secure transfer is not required",
                "secure_transfer_required=false",
                "Require secure transfer and validate clients use TLS-protected endpoints.",
            ))

    for vault in inventory.get("key_vaults", []):
        if int(vault.get("rotation_days", 0)) <= 0:
            findings.append(Finding(
                "AZ-KEY-001", "MEDIUM", vault["name"],
                "Key rotation policy is not configured",
                f"rotation_days={vault.get('rotation_days', 0)}",
                "Define an approved rotation lifecycle and validate new key versions are created as expected.",
            ))

    return findings


def summarize(findings: Iterable[Finding]) -> dict[str, int]:
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        summary[finding.severity] = summary.get(finding.severity, 0) + 1
    return summary


def main(path: str) -> int:
    inventory = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = evaluate_inventory(inventory)
    for item in findings:
        print(f"{item.severity:<8} {item.control_id:<10} {item.resource}: {item.title}")
    print(json.dumps(summarize(findings), indent=2))
    return 1 if any(f.severity == "CRITICAL" for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "data/synthetic_azure.json"))
