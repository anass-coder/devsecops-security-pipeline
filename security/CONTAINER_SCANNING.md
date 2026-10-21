# Phase 8: container vulnerability scanning with Trivy

## Why scan the container after pip-audit?

pip-audit checks application Python requirements and their resolved dependencies.
The image also includes an operating system, C libraries, shell utilities,
cryptography/compression libraries, Python, and packaging tools such as pip.
These components can have vulnerabilities absent from `app/requirements.txt`.
Trivy inventories the built image and matches detected package versions against
its vulnerability database. It does not need to run the application.

This integration scans OS and language packages using the `vuln` scanner. It does
not enable Trivy's separate secret, configuration, or license scanners. A passing
vulnerability scan does not verify application logic or container hardening.

## Implementation and files

| File | Change | Purpose |
| --- | --- | --- |
| `.github/workflows/security.yml` | Modified | Scan the exact locally built image, test in-container compatibility, verify a controlled remediation, enforce severity policy, and upload reports |
| `Dockerfile` | Modified | Use a tested Alpine base, update zlib, install dependencies with pip 26.2.2, then remove pip and its bundled libraries from runtime; retain an overridable `PYTHON_BASE` |
| `.gitignore` | Modified | Ignore an optional local `.trivycache/`; generated reports are already ignored |
| `README.md` | Modified | Explain the container scanning stage and link this guide |
| `security/scripts/validate_trivy.py` | Created | Build and scan a disposable Flask downgrade and compare it with the final image |
| `security/CONTAINER_SCANNING.md` | Created | Document fields, severity, commands, remediation, and verification |

The action is pinned to commit `ed142fd0673e97e23eac54620cfb913e5ce36c25`
(`v0.36.0`) and explicitly installs Trivy `v0.76.1`.

## Pipeline and failure policy

The existing `build-and-test` job remains dependent on Gitleaks, Semgrep, and
pip-audit. It now:

1. Runs application unit tests.
2. Builds `devsecops-security-app:${{ github.sha }}` with `--pull`.
3. Runs tests inside that image to check the chosen Linux/Python dependencies.
4. Scans the same tag from the local Docker engine and writes `reports/trivy.json`.
5. Checks a controlled vulnerable image against the final image's scan.
6. Applies the HIGH/CRITICAL policy to the saved final-image report.
7. Always attempts to upload `reports/trivy*.json` as `trivy-report` for seven days.

Build and scan run in the same job because Docker images are local to a runner.
No registry push or registry credentials are required. Restricting the image
source to Docker avoids accidentally scanning an unrelated remote image.

The initial scan records **all severities**, including vulnerabilities without a
published fix. Its `exit-code: '0'` permits generating the full report. Actual
scanner/setup/database failures still fail the scan. The separate policy step:

```sh
trivy convert --scanners vuln --format table --severity HIGH,CRITICAL --exit-code 1 reports/trivy.json
```

fails when HIGH or CRITICAL findings exist, even if unfixed. LOW, MEDIUM, and
UNKNOWN findings remain visible but do not currently block. No blanket CVE
ignores or `continue-on-error` are used. The policy reads the already-generated
report, so it does not rescan against a different database. Artifacts are
attempted even after a policy failure. If an earlier step fails before a report
exists, inspect that step's logs.

## JSON structure and finding fields

Top-level fields include `SchemaVersion`, `ArtifactName`, `ArtifactType`,
`Metadata`, and `Results`. `Metadata.OS` identifies the detected distribution;
`Metadata.ImageID` identifies the scanned image. Each result groups a target and
package ecosystem: `Class: os-pkgs` for OS packages and `Class: lang-pkgs` for
language packages. `Type` can be `alpine`, `debian`, or `python-pkg`.

| JSON field | Meaning |
| --- | --- |
| `Results[].Target` | Image/OS target or language-package target |
| `Results[].Vulnerabilities[].VulnerabilityID` | CVE or other advisory ID |
| `Results[].Vulnerabilities[].PkgName` | Affected package |
| `Results[].Vulnerabilities[].InstalledVersion` | Detected package version |
| `Results[].Vulnerabilities[].FixedVersion` | Published fix version, if available |
| `Results[].Vulnerabilities[].Severity` | UNKNOWN, LOW, MEDIUM, HIGH, or CRITICAL |
| `Results[].Vulnerabilities[].Title` / `Description` | Finding explanation |
| `Results[].Vulnerabilities[].PrimaryURL` | Advisory reference |
| `Results[].Vulnerabilities[].SeveritySource` / `CVSS` | Rating source and available CVSS details |
| `Results[].Packages` | Package inventory retained by `list-all-pkgs` |

Missing `FixedVersion` means the selected data source does not list a fix. A
missing or empty `Vulnerabilities` array means no findings for that target, not
that no packages were scanned. Counts are package/advisory pairs: one CVE may
affect several packages, so finding count is not necessarily distinct CVE count.

Trivy uses advisory severity information, often prioritizing distribution-vendor
ratings for OS packages. Vendor backports can fix an issue without adopting the
upstream version number. Do not compare version strings or assume NVD's rating
must match the distribution's rating. UNKNOWN means no severity was assigned by
the selected data source. Severity and actual application exploitability are
different questions.

Inspect findings in PowerShell:

```powershell
$scan = Get-Content reports/trivy.json -Raw | ConvertFrom-Json
$scan.Results | ForEach-Object {
    $target = $_.Target
    $_.Vulnerabilities | ForEach-Object {
        [PSCustomObject]@{
            Target = $target
            CVE = $_.VulnerabilityID
            Package = $_.PkgName
            Installed = $_.InstalledVersion
            Fixed = $_.FixedVersion
            Severity = $_.Severity
        }
    }
} | Format-Table -Wrap
```

## Base image comparison and remediation

The initial fresh Debian `python:3.12-slim` image contained HIGH OS findings even
though application dependencies passed pip-audit. An Alpine comparison was built
with the same application requirements and scanned against the same database.
All seven unit tests passed inside the comparison image before choosing Alpine.

Changing the base changes the package inventory, distribution versions, and
vendor advisories. It can remove affected components or supply patched ones; it
does not prove that one Linux distribution is always safer than another.
Alpine uses musl instead of glibc, so the workflow tests image compatibility.

The comparison also exposed pip 25.0.1 and Alpine zlib 1.3.2-r0 vulnerabilities.
The Dockerfile uses pip 26.2.2 for installation and updates zlib to the repository's
patched release. A subsequent scan found vulnerable libraries bundled inside the
new pip wheel, so pip and those bundled libraries are removed after installing
the application. These are real image components that pip-audit's application
requirements scan did not cover. The application runs without pip installed.
`apk` is used only for Alpine-based builds; other base-image comparisons skip
that package update.

For a different base, rebuild with the `PYTHON_BASE` build argument, scan under a
separate tag/report, and run tests. For example:

```powershell
docker build --pull --build-arg PYTHON_BASE=python:3.12-slim -t devsecops-security-app:debian .
```

The default image tag and package repositories can change; repeat the audit after
rebuilding. An existing image is not modified when the Dockerfile changes.

## Controlled container remediation check

`validate_trivy.py` reads the final report and verifies the requested image and
Flask inventory are present. It creates a unique disposable image derived from
that final image, restores pip with `ensurepip`, and installs `Flask==3.0.3` with
`--no-deps`.

It scans this image with the cached database from the final scan
(`--skip-db-update`) and requires Flask finding `CVE-2026-27205` with a fixed
version. It confirms that finding is absent from the final image containing
patched Flask. OS packages remain the same; the disposable image also contains
the restored installer, whose incidental findings are retained in its report.
The vulnerable image is never run, pushed, or deployed, and its tag is removed
in cleanup. Application dependencies and source files are unchanged by the test.

The before-report is retained as `reports/trivy-validation-before.json`.
Its expected vulnerability does not fail the final-image policy: that policy
reads only `reports/trivy.json`. Unrelated OS findings do not invalidate the
specific remediation check and remain subject to the separate severity policy.

## Local verification results

Verified on 2026-10-21 with Trivy 0.76.1 and the same downloaded vulnerability DB:

| Image/report | Total package/advisory findings | HIGH | CRITICAL |
| --- | --- | --- | --- |
| Original Debian slim (`trivy-debian-baseline.json`) | 170 | 44 | 0 |
| Initial Alpine comparison (`trivy-alpine-comparison.json`) | 7 | 0 | 0 |
| Patched zlib and pip upgrade, installer retained (`trivy-installer-baseline.json`) | 6 | 4 | 0 |
| Final Alpine runtime, installer removed (`trivy.json`) | 0 | 0 | 0 |

The installer upgrade changed the detected inventory and introduced bundled
library findings; simply installing the newest pip was not sufficient. Removing
that build tool from runtime removed those installed components without CVE
suppression. The final report inventories 38 OS packages and seven Python
packages. The comparison results describe these image versions and database,
not a general security ranking of distributions.

Representative remediation evidence retained in the local reports:

| Component | Installed in earlier image | Finding | Severity | Reported fix / action |
| --- | --- | --- | --- | --- |
| zlib | 1.3.2-r0 | CVE-2026-85091 | MEDIUM | Updated to 1.3.2-r1 |
| pip | 25.0.1 | CVE-2025-8869 | MEDIUM | Reported fix 25.3; runtime pip ultimately removed |
| setuptools bundled with pip | 70.3.0 | CVE-2025-47273 | HIGH | Reported fix 78.1.1; bundled build-tool component removed |
| urllib3 bundled with pip | 2.7.0 | CVE-2026-97687 | HIGH | Reported fix 2.8.0; bundled build-tool component removed |

The controlled image produced Flask CVE-2026-27205 with Flask 3.0.3; it was absent
from the final Flask 3.1.3 image. The temporary validation tag was removed.
The final HIGH/CRITICAL policy returned exit 0. All seven unit tests passed
inside the final image, and a temporary container passed real HTTP `/health`
and SQLite `/users/1` checks before being stopped.

The three comparison/installer-baseline reports above are local historical
evidence, ignored by Git. CI normally generates `trivy.json` and
`trivy-validation-before.json` and uploads them as `trivy-report`. The latter
intentionally contains findings and is not the input to the final-image gate.
The artifact lasts seven days. A hosted GitHub Actions run has not yet been
verified; these changes have not been committed or pushed.

## Run locally

With Docker running and Trivy 0.76.1 on PATH, from the repository root:

```powershell
docker build --pull -t devsecops-security-app:local .
New-Item -ItemType Directory -Force reports | Out-Null
trivy image --image-src docker --scanners vuln --pkg-types os,library --list-all-pkgs --format json --output reports/trivy.json --cache-dir .trivycache --timeout 10m devsecops-security-app:local
python security/scripts/validate_trivy.py --image devsecops-security-app:local --after-report reports/trivy.json --cache-dir .trivycache
trivy convert --scanners vuln --format table --severity HIGH,CRITICAL --exit-code 1 reports/trivy.json
```

The first scan needs network access for the vulnerability database. The validation
build also needs package-index access for its controlled Flask wheel. If Trivy is
not on PATH, pass its executable path with `--trivy` to the validation script.

## References

- [Trivy Action](https://github.com/aquasecurity/trivy-action/tree/v0.36.0)
- [Vulnerability scanning and severity](https://trivy.dev/docs/latest/scanner/vulnerability/)
- [JSON reporting](https://trivy.dev/docs/latest/configuration/reporting/)
- [Report conversion and exit policy](https://trivy.dev/docs/latest/references/configuration/cli/trivy_convert/)
