import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloudtrail_detector import analyze, detect, iter_events

class DetectorTests(unittest.TestCase):
    def test_console_login_without_mfa(self):
        e = {"eventName": "ConsoleLogin", "responseElements": {"ConsoleLogin": "Success"},
             "additionalEventData": {"MFAUsed": "No"}}
        self.assertEqual([a["rule_id"] for a in detect(e)], ["AWS-001"])

    def test_login_with_mfa(self):
        e = {"eventName": "ConsoleLogin", "responseElements": {"ConsoleLogin": "Success"},
             "additionalEventData": {"MFAUsed": "Yes"}}
        self.assertEqual(detect(e), [])

    def test_root_action(self):
        self.assertEqual(detect({"eventName": "ListBuckets", "userIdentity": {"type": "Root"}})[0]["rule_id"], "AWS-002")

    def test_public_ssh(self):
        e = {"eventName": "AuthorizeSecurityGroupIngress", "requestParameters": {"ipPermissions": {"items": [
            {"fromPort": 22, "toPort": 22, "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}
        ]}}}
        self.assertEqual(detect(e)[0]["rule_id"], "AWS-003")

    def test_private_ssh(self):
        e = {"eventName": "AuthorizeSecurityGroupIngress", "requestParameters": {"ipPermissions": {"items": [
            {"fromPort": 22, "toPort": 22, "ipRanges": {"items": [{"cidrIp": "10.0.0.0/8"}]}}
        ]}}}
        self.assertEqual(detect(e), [])

    def test_ipv6_public_rdp(self):
        e = {"eventName": "AuthorizeSecurityGroupIngress", "requestParameters": {"ipPermissions": {"items": [
            {"fromPort": 3389, "toPort": 3389, "ipv6Ranges": {"items": [{"cidrIpv6": "::/0"}]}}
        ]}}}
        self.assertEqual(detect(e)[0]["rule_id"], "AWS-003")

    def test_logging_change(self):
        self.assertEqual(detect({"eventName": "StopLogging"})[0]["rule_id"], "AWS-004")

    def test_s3_change(self):
        self.assertEqual(detect({"eventName": "PutBucketPolicy"})[0]["rule_id"], "AWS-005")

    def test_records(self):
        self.assertEqual(len(analyze({"Records": [{"eventName": "DeleteTrail"}, {"eventName": "ListBuckets"}]})), 1)

    def test_invalid_events(self):
        with self.assertRaises(ValueError):
            iter_events({"Records": ["not an event"]})

    def test_sample_data(self):
        path = Path(__file__).resolve().parents[1] / "examples" / "cloudtrail_sample.json"
        self.assertGreaterEqual(len(analyze(json.loads(path.read_text()))), 3)

if __name__ == "__main__":
    unittest.main()
