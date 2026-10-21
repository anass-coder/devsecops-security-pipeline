"""Verify the SQL rule detects an insecure example and accepts its remediation."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


RULES = Path(__file__).resolve().parents[1] / "semgrep.yml"

INSECURE = '''import sqlite3

def lookup(user_id):
    db = sqlite3.connect(":memory:")
    query = "SELECT username FROM users WHERE id = " + user_id
    return db.execute(query).fetchone()
'''

REMEDIATED = '''import sqlite3

def lookup(user_id):
    db = sqlite3.connect(":memory:")
    return db.execute(
        "SELECT username FROM users WHERE id = ?", (user_id,)
    ).fetchone()
'''


def validate(semgrep):
    executable = shutil.which(semgrep)
    if executable is None:
        raise FileNotFoundError(f"Semgrep executable not found: {semgrep}")
    semgrep = str(Path(executable).resolve())
    with tempfile.TemporaryDirectory(prefix="semgrep-validation-") as directory:
        root = Path(directory)
        source = root / "example.py"
        report = root / "semgrep.json"

        def scan(expected_exit):
            result = subprocess.run(
                [semgrep, "scan", "--config", str(RULES), "--strict", "--error",
                 "--metrics=off", "--disable-version-check",
                 "--no-rewrite-rule-ids", "--no-git-ignore", "--json",
                 "--output", str(report), str(source)],
                cwd=root, check=False,
            )
            if result.returncode != expected_exit:
                raise RuntimeError(
                    f"Expected scan exit {expected_exit}, got {result.returncode}"
                )
            data = json.loads(report.read_text(encoding="utf-8"))
            if data.get("errors"):
                raise RuntimeError("Semgrep reported analysis errors")
            if not data.get("paths", {}).get("scanned"):
                raise RuntimeError("Semgrep did not scan the example")
            return data["results"]

        # This source is only parsed by Semgrep; it is never executed.
        source.write_text(INSECURE, encoding="utf-8")
        findings = scan(1)
        matches = [
            finding for finding in findings
            if finding["check_id"] == "python-sql-query-concatenation"
        ]
        if len(matches) != 1:
            raise RuntimeError("Expected one SQL concatenation finding")
        finding = matches[0]
        if (
            Path(finding["path"]).name != "example.py"
            or finding["start"]["line"] != 6
            or finding["extra"]["severity"] not in {"ERROR", "HIGH"}
            or not finding["extra"]["message"]
        ):
            raise RuntimeError("Unexpected finding location, severity, or description")
        print(
            f"PASS: {finding['check_id']} detected at example.py:6; "
            f"severity={finding['extra']['severity']}; exit=1",
            flush=True,
        )

        source.write_text(REMEDIATED, encoding="utf-8")
        if scan(0):
            raise RuntimeError("Findings remained after parameterizing the query")
        print("PASS: parameterized query has no findings; exit=0", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semgrep", default="semgrep", help="Semgrep executable")
    validate(parser.parse_args().semgrep)
