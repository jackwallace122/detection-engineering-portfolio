import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import cloudtrail_triage as ct  # noqa: E402

SAMPLE = ROOT / "tests" / "sample_logs"


class TestCloudTrailTriage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = ct.load_records([SAMPLE])
        cls.findings = ct.triage(cls.records)
        cls.rules = {f.rule for f in cls.findings}

    def test_detects_logging_tamper(self):
        self.assertIn("Logging/monitoring tampering", self.rules)

    def test_detects_root_usage(self):
        self.assertIn("Root account activity", self.rules)

    def test_detects_bruteforce(self):
        self.assertIn("Brute-force console logins", self.rules)

    def test_detects_admin_policy_attach(self):
        priv = [f for f in self.findings if f.rule == "IAM privilege change"]
        self.assertTrue(priv and priv[0].severity == "high")

    def test_open_ssh_is_critical(self):
        sg = [f for f in self.findings if f.rule == "Security group exposed to internet"]
        self.assertEqual(len(sg), 1, "internal-only SG rule should not be flagged")
        self.assertEqual(sg[0].severity, "critical")

    def test_benign_activity_not_flagged(self):
        self.assertFalse(any(f.event_name == "DescribeInstances" for f in self.findings))


if __name__ == "__main__":
    unittest.main()
