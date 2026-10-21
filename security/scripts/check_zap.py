"""Read ZAP baseline JSON and enforce the project's DAST policy."""

import argparse
from collections import Counter
import json
from pathlib import Path
from urllib.parse import urlsplit


TARGET = "http://app:5000"
NOSNIFF_PLUGIN = "10021"
RISK_NAMES = {0: "Informational", 1: "Low", 2: "Medium", 3: "High"}


def read_alerts(report_path, target=TARGET):
    data = json.loads(Path(report_path).read_text(encoding="utf-8"))
    sites = data.get("site")
    if not isinstance(sites, list) or not sites:
        raise ValueError("ZAP report has no scanned sites")
    expected = urlsplit(target)
    alerts = []
    matched_site = False
    for site in sites:
        actual = urlsplit(site["@name"])
        if (actual.scheme, actual.netloc) != (expected.scheme, expected.netloc):
            raise ValueError("ZAP report contains an unexpected target")
        matched_site = True
        for alert in site["alerts"]:
            risk = int(alert["riskcode"])
            if risk not in RISK_NAMES or not alert.get("pluginid"):
                raise ValueError("ZAP alert has an invalid risk or plugin ID")
            alerts.append(alert)
    if not matched_site:
        raise ValueError("Expected target was not scanned")
    return alerts


def blocking_alerts(alerts):
    # Treat the remediated Low-risk header as a required regression check too.
    return [alert for alert in alerts
            if int(alert["riskcode"]) >= 2 or str(alert["pluginid"]) == NOSNIFF_PLUGIN]


def check(report_path, summary_path):
    alerts = read_alerts(report_path)
    blocked = blocking_alerts(alerts)
    summary = {
        "target": TARGET,
        "scan_type": "baseline",
        "risk_counts": dict(Counter(RISK_NAMES[int(alert["riskcode"])] for alert in alerts)),
        "passed": not blocked,
        "blocking_alerts": [
            {"plugin_id": str(alert["pluginid"]), "name": alert["alert"],
             "risk": RISK_NAMES[int(alert["riskcode"])]} for alert in blocked
        ],
    }
    Path(summary_path).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 1 if blocked else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report")
    parser.add_argument("--summary", required=True)
    options = parser.parse_args()
    raise SystemExit(check(options.report, options.summary))
