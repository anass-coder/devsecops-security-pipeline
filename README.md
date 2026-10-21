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
5. If both scanner jobs succeed, install Flask, run unit tests, and build Docker.
   SAST records the training app's intentional findings without blocking; scanner
   errors and failed validation still fail the SAST job.

See [Phase 5: secret scanning](security/SECRET_SCANNING.md) for commands, report
fields, validation details, exclusions, and remediation guidance.

See [Phase 6: SAST](security/SAST.md) for the Semgrep rules, local commands,
JSON field descriptions, severity mapping, and detection/remediation demonstration.

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
