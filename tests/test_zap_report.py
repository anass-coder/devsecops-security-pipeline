import json
from pathlib import Path
import tempfile
import unittest

from security.scripts.check_zap import blocking_alerts, check, read_alerts


class ZapReportTests(unittest.TestCase):
    def test_medium_and_high_block(self):
        for risk in (2, 3):
            with self.subTest(risk=risk):
                alert = {"riskcode": str(risk), "pluginid": "123"}
                self.assertEqual(blocking_alerts([alert]), [alert])

    def test_informational_and_unrelated_low_do_not_block(self):
        alerts = [{"riskcode": str(risk), "pluginid": "123"} for risk in (0, 1)]
        self.assertEqual(blocking_alerts(alerts), [])

    def test_required_nosniff_regression_blocks(self):
        alert = {"riskcode": "1", "pluginid": "10021"}
        self.assertEqual(blocking_alerts([alert]), [alert])

    def test_report_validation_and_machine_readable_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "zap.json"
            summary = Path(directory) / "summary.json"
            data = {"site": [{"@name": "http://app:5000", "alerts": [
                {"riskcode": "1", "pluginid": "10021", "alert": "Missing nosniff"}
            ]}]}
            report.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(check(report, summary), 1)
            self.assertFalse(json.loads(summary.read_text())["passed"])
            data["site"][0]["alerts"] = []
            report.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(check(report, summary), 0)
            self.assertTrue(json.loads(summary.read_text())["passed"])
            for invalid in ({}, {"site": []}, {"site": [{"@name": "http://other", "alerts": []}]},
                            {"site": [{"@name": "http://app:5000", "alerts": [
                                {"riskcode": "4", "pluginid": "123"}]}]}):
                with self.subTest(invalid=invalid):
                    report.write_text(json.dumps(invalid), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        read_alerts(report)
