"""Compare a controlled vulnerable image with the already-scanned final image."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid


TARGET_CVE = "CVE-2026-27205"


def validate(image, after_report, trivy, cache_dir):
    executable = shutil.which(trivy)
    if executable is None:
        raise FileNotFoundError(f"Trivy executable not found: {trivy}")
    executable = str(Path(executable).resolve())
    after_report = Path(after_report).resolve()
    after = json.loads(after_report.read_text(encoding="utf-8"))
    if after.get("ArtifactType") != "container_image" or after.get("ArtifactName") != image:
        raise RuntimeError("The after-report must describe the requested final image")

    def flask_results(report):
        results = [result for result in report.get("Results", [])
                   if result.get("Class") == "lang-pkgs"]
        packages = [package for result in results for package in result.get("Packages", [])
                    if package["Name"].lower() == "flask"]
        if not packages:
            raise RuntimeError("Flask package inventory missing; scan with --list-all-pkgs")
        findings = [finding for result in results
                    for finding in result.get("Vulnerabilities", [])
                    if finding["PkgName"].lower() == "flask"
                    and finding["VulnerabilityID"] == TARGET_CVE]
        return packages, findings

    _, after_findings = flask_results(after)
    if after_findings:
        raise RuntimeError(f"{TARGET_CVE} remains in the final image")

    before_report = after_report.with_name("trivy-validation-before.json")
    temporary_image = f"devsecops-trivy-validation:{uuid.uuid4().hex}"
    built = False
    try:
        with tempfile.TemporaryDirectory(prefix="trivy-validation-") as directory:
            dockerfile = Path(directory) / "Dockerfile"
            # OS packages remain unchanged. Restore the installer only inside
            # this disposable image, then install the vulnerable Flask wheel.
            dockerfile.write_text(
                f"FROM {image}\n"
                "RUN python -m ensurepip\n"
                'RUN python -m pip install --no-cache-dir --no-deps "Flask==3.0.3"\n',
                encoding="utf-8",
            )
            subprocess.run(
                ["docker", "build", "-t", temporary_image, directory], check=True
            )
            built = True
        command = [
            executable, "image", "--image-src", "docker", "--scanners", "vuln",
            "--pkg-types", "os,library", "--list-all-pkgs", "--skip-db-update",
            "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", "--exit-code", "0",
            "--format", "json", "--output", str(before_report), "--timeout", "10m",
        ]
        if cache_dir:
            command.extend(["--cache-dir", str(Path(cache_dir).resolve())])
        command.append(temporary_image)
        subprocess.run(command, check=True)
        before = json.loads(before_report.read_text(encoding="utf-8"))
        _, before_findings = flask_results(before)
        if not any(finding["InstalledVersion"] == "3.0.3"
                   and finding.get("FixedVersion") for finding in before_findings):
            raise RuntimeError("The vulnerable Flask package was not detected with a fix")
        print(f"PASS: Flask 3.0.3 image contains {TARGET_CVE}", flush=True)
        print(f"PASS: final image no longer contains Flask finding {TARGET_CVE}", flush=True)
    finally:
        if built:
            subprocess.run(["docker", "image", "rm", temporary_image], check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="Final, locally built image tag")
    parser.add_argument("--after-report", required=True, help="Full final-image JSON report")
    parser.add_argument("--trivy", default="trivy", help="Trivy executable")
    parser.add_argument("--cache-dir", help="Same vulnerability DB cache as the final scan")
    options = parser.parse_args()
    validate(options.image, options.after_report, options.trivy, options.cache_dir)
