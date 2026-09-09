import unittest

from src.baseline import evaluate_inventory, summarize


class AzureBaselineTests(unittest.TestCase):
    def test_privileged_identity_without_mfa_is_high(self):
        inventory = {"identities": [{"name": "admin", "privileged": True, "mfa_required": False, "role": "Reader", "assignment": "eligible"}]}
        findings = evaluate_inventory(inventory)
        self.assertEqual(findings[0].control_id, "AZ-ID-001")
        self.assertEqual(findings[0].severity, "HIGH")

    def test_management_exposure_detected(self):
        inventory = {"network_rules": [{"name": "rdp", "source": "0.0.0.0/0", "port": 3389}]}
        ids = {f.control_id for f in evaluate_inventory(inventory)}
        self.assertIn("AZ-NET-001", ids)

    def test_https_public_rule_not_flagged_as_management(self):
        inventory = {"network_rules": [{"name": "https", "source": "0.0.0.0/0", "port": 443}]}
        self.assertEqual(evaluate_inventory(inventory), [])

    def test_storage_controls(self):
        inventory = {"storage_accounts": [{"name": "demo", "public_blob_access": True, "secure_transfer_required": False}]}
        ids = {f.control_id for f in evaluate_inventory(inventory)}
        self.assertEqual(ids, {"AZ-STOR-001", "AZ-STOR-002"})

    def test_summary_counts(self):
        inventory = {"logging": {"export_enabled": False, "retention_days": 1}}
        self.assertEqual(summarize(evaluate_inventory(inventory))["HIGH"], 1)
        self.assertEqual(summarize(evaluate_inventory(inventory))["MEDIUM"], 1)


if __name__ == "__main__":
    unittest.main()
