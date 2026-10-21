"""Prove detection and remediation in a disposable Git repository."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def validate(gitleaks):
    with tempfile.TemporaryDirectory(prefix="gitleaks-validation-") as directory:
        root = Path(directory)
        repository = root / "repository"
        repository.mkdir()
        report = root / "report.json"
        # Isolate the demonstration from the user's global Git configuration.
        environment = os.environ.copy()
        environment["GIT_CONFIG_GLOBAL"] = os.devnull
        environment["GIT_CONFIG_NOSYSTEM"] = "1"

        def git(*arguments):
            subprocess.run(
                ["git", *arguments], cwd=repository, env=environment, check=True,
                stdout=subprocess.DEVNULL,
            )

        def scan(expected_exit):
            result = subprocess.run(
                [gitleaks, "git", ".", "--log-opts=--all", "--redact",
                 "--report-format=json", f"--report-path={report}"],
                cwd=repository, env=environment, check=False,
            )
            if result.returncode != expected_exit:
                raise RuntimeError(
                    f"Expected scan exit {expected_exit}, got {result.returncode}"
                )
            return json.loads(report.read_text(encoding="utf-8"))

        git("init", "--quiet")
        git("config", "user.name", "Gitleaks validation")
        git("config", "user.email", "validation@example.invalid")
        (repository / "README.md").write_text(
            "Controlled scanner validation.\n", encoding="utf-8"
        )
        # Synthetic GitHub PAT format, never issued by GitHub. Split the value
        # so the validation script itself does not contain a complete token.
        fake_secret = "ghp_" + "7mQ9zR2vX5nK8pL3sT6wY1bC4dF0hJ2kM9rV"
        (repository / "fake.env").write_text(
            f"GITHUB_TOKEN={fake_secret}\n", encoding="utf-8"
        )
        git("add", "README.md", "fake.env")
        git("commit", "--quiet", "-m", "Add controlled fake secret")
        findings = scan(1)
        if not any(
            item["RuleID"] == "github-pat" and item["File"] == "fake.env"
            for item in findings
        ):
            raise RuntimeError("The fake GitHub token was not reported")
        if fake_secret in report.read_text(encoding="utf-8"):
            raise RuntimeError("The report contains an unredacted token")
        print("PASS: fake secret detected; scanner returned exit 1", flush=True)
        finding = next(item for item in findings if item["RuleID"] == "github-pat")
        print(
            f"Finding: rule={finding['RuleID']} file={finding['File']} "
            f"line={finding['StartLine']} commit={finding['Commit'][:12]}",
            flush=True,
        )

        git("rm", "--quiet", "fake.env")
        scan(1)
        print("PASS: deleting the file still leaves the secret in history", flush=True)

        # Rewrite only the disposable repository's unpublished test commit.
        git("commit", "--quiet", "--amend", "--no-edit", "--allow-empty")
        if scan(0):
            raise RuntimeError("Findings remained after test-history remediation")
        print("PASS: fake secret removed from reachable history; exit 0", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gitleaks", default="gitleaks", help="Gitleaks executable")
    validate(parser.parse_args().gitleaks)
