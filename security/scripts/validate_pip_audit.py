"""Audit an isolated vulnerable Flask pin, then verify an upgraded pin is clean."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile


VULNERABLE_VERSION = "2.2.4"
REMEDIATED_VERSION = "3.1.3"
TARGET_ADVISORY = "CVE-2023-30861"


def validate(report_dir=None):
    if report_dir is not None:
        report_dir = Path(report_dir).resolve()
        report_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="pip-audit-validation-") as directory:
        root = Path(directory)
        requirements = root / "requirements.txt"

        def scan(version, expected_exit, label):
            requirements.write_text(f"Flask=={version}\n", encoding="utf-8")
            report = root / f"{label}.json"
            # Only this synthetic fixture skips dependency resolution. No
            # vulnerable distribution is installed or imported by this script.
            result = subprocess.run(
                [sys.executable, "-m", "pip_audit", "-r", str(requirements),
                 "--no-deps", "--disable-pip", "--strict",
                 "--vulnerability-service", "pypi", "--format", "json",
                 "--aliases", "on", "--desc", "on",
                 "--progress-spinner", "off", "--timeout", "30",
                 "--output", str(report)],
                check=False, timeout=180,
            )
            if result.returncode != expected_exit:
                raise RuntimeError(
                    f"Expected audit exit {expected_exit}, got {result.returncode}"
                )
            data = json.loads(report.read_text(encoding="utf-8"))
            dependencies = data["dependencies"]
            if (
                len(dependencies) != 1
                or dependencies[0]["name"].lower() != "flask"
                or dependencies[0].get("version") != version
                or "skip_reason" in dependencies[0]
            ):
                raise RuntimeError("The requested Flask pin was not fully audited")
            if report_dir is not None:
                (report_dir / f"pip-audit-validation-{label}.json").write_text(
                    json.dumps(data, indent=2) + "\n", encoding="utf-8"
                )
            return dependencies[0]["vulns"]

        vulnerabilities = scan(VULNERABLE_VERSION, 1, "before")
        finding = next(
            (item for item in vulnerabilities
             if TARGET_ADVISORY in {item["id"], *item.get("aliases", [])}),
            None,
        )
        if finding is None or not finding.get("fix_versions"):
            raise RuntimeError("Expected Flask advisory and fixed versions were not reported")
        print(
            f"PASS: Flask {VULNERABLE_VERSION}: {finding['id']} "
            f"({TARGET_ADVISORY}); fixes={','.join(finding['fix_versions'])}; exit=1",
            flush=True,
        )

        if scan(REMEDIATED_VERSION, 0, "after"):
            raise RuntimeError("Vulnerabilities remained in the upgraded test pin")
        print(
            f"PASS: upgraded test pin to Flask {REMEDIATED_VERSION}; "
            "no known vulnerabilities; exit=0",
            flush=True,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", help="Optionally retain before/after JSON reports")
    validate(parser.parse_args().report_dir)
