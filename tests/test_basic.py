import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detect import ThreatDetector, Event


class TestThreatDetector(unittest.TestCase):
    def setUp(self):
        self.detector = ThreatDetector(threshold=0.5)

    def test_no_events_no_alerts(self):
        alerts = self.detector.analyze_events([])
        self.assertEqual(len(alerts), 0)

    def test_low_risk_no_alert(self):
        events = [Event(user="alice", action="login", resource="web_app")]
        alerts = self.detector.analyze_events(events)
        self.assertEqual(len(alerts), 0)

    def test_high_risk_triggers_alert(self):
        events = [Event(user="bob", action="data_exfiltration", resource="customer_pii")]
        alerts = self.detector.analyze_events(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].user, "bob")
        self.assertGreaterEqual(alerts[0].score, self.detector.threshold)

    def test_multiple_users_separate_alerts(self):
        events = [
            Event(user="alice", action="login", resource="web_app"),
            Event(user="bob", action="data_exfiltration", resource="financial_db"),
        ]
        alerts = self.detector.analyze_events(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].user, "bob")

    def test_privilege_escalation_detected(self):
        events = [Event(user="mallory", action="privilege_escalation", resource="secrets_vault")]
        alerts = self.detector.analyze_events(events)
        self.assertEqual(len(alerts), 1)

    def test_generate_report(self):
        events = [Event(user="alice", action="data_exfiltration", resource="source_code")]
        report = self.detector.generate_report(events)
        self.assertEqual(report["total_events"], 1)
        self.assertEqual(report["unique_users"], 1)
        self.assertEqual(report["alerts_generated"], 1)

    def test_risk_score_bounds(self):
        events = [Event(user="test", action="data_exfiltration", resource="source_code")]
        alerts = self.detector.analyze_events(events)
        self.assertLessEqual(alerts[0].score, 1.0)
        self.assertGreaterEqual(alerts[0].score, 0.0)

    def test_multiple_events_same_user(self):
        events = [
            Event(user="bob", action="login", resource="web_app"),
            Event(user="bob", action="data_exfiltration", resource="source_code"),
        ]
        alerts = self.detector.analyze_events(events)
        self.assertEqual(len(alerts), 1)
        self.assertIn("data_exfiltration", alerts[0].reason)


if __name__ == "__main__":
    unittest.main()
