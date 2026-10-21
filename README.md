# DevSecOps security pipeline

A deliberately vulnerable Flask/SQLite application for learning CI and security
scanning. The application weaknesses are intentional training examples.

## CI pipeline

The workflow in `.github/workflows/security.yml` runs on pushes and pull requests:

1. Check out full Git history and install checksum-verified Gitleaks 8.30.1.
2. Validate fake-secret detection and remediation in a temporary Git repository.
3. Scan the project's fetched Git history and upload a redacted JSON report.
4. If secret scanning passes, install Flask, run unit tests, and build Docker.

See [Phase 5: secret scanning](security/SECRET_SCANNING.md) for commands, report
fields, validation details, exclusions, and remediation guidance.

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
