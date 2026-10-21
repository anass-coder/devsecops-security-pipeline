# DevSecOps security pipeline

A deliberately vulnerable Flask/SQLite application for learning CI and security
scanning. The application weaknesses are intentional training examples.

## CI pipeline

The workflow in `.github/workflows/security.yml` currently runs on pushes:

1. Check out full Git history and install checksum-verified Gitleaks 8.30.1.
2. Validate fake-secret detection and remediation in a temporary Git repository.
3. Scan the project's fetched Git history and upload a redacted JSON report.
4. In a separate SAST job, install Semgrep, validate SQL-injection detection and
   remediation, then scan `app/` and upload `reports/semgrep.json`.
5. In a separate SCA job, validate pip-audit against vulnerable/fixed test pins,
   audit application dependencies, and upload JSON dependency reports.
6. If all three scanner jobs succeed, install Flask, run unit tests, and build
   Docker. Dependency vulnerabilities block the build. SAST records the training
   app's intentional findings without blocking; scanner errors and failed
   validation still fail the SAST job.
7. Test the built container, scan that same image with Trivy, validate a controlled
   container dependency remediation, and upload JSON reports. HIGH or CRITICAL
   container vulnerabilities fail the job; all severities remain in the report.
8. Start isolated application containers, wait for `/health`, and run ZAP baseline
   scans with explicit API requests. Verify a controlled missing-header finding
   disappears after remediation, save JSON/HTML reports, and enforce the DAST
   policy against the final application.

See [Phase 5: secret scanning](security/SECRET_SCANNING.md) for commands, report
fields, validation details, exclusions, and remediation guidance.

See [Phase 6: SAST](security/SAST.md) for the Semgrep rules, local commands,
JSON field descriptions, severity mapping, and detection/remediation demonstration.

See [Phase 7: dependency scanning](security/DEPENDENCY_SCANNING.md) for pip-audit
usage, package/advisory/fix fields, the controlled upgrade demonstration, and
dependency-report artifacts.

See [Phase 8: container scanning](security/CONTAINER_SCANNING.md) for Trivy report
fields, the Debian/Alpine comparison, container remediation, and severity policy.

See [Phase 9: DAST](security/DAST.md) for ZAP coverage, HTTP-header remediation,
report fields, risk levels, local commands, and artifact locations.

## Run locally

```powershell
docker build -t devsecops-security-app:local .
docker run --rm -p 127.0.0.1:5000:5000 devsecops-security-app:local
```

Open http://localhost:5000/health to check the application.

## Run application tests

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r app/requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```
