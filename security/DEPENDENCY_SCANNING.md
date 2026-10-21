# Phase 7: dependency scanning with pip-audit

## What SCA checks

Software composition analysis (SCA) compares third-party package names and
versions against published vulnerability advisories. Here, pip-audit 2.10.1
audits `app/requirements.txt` and its resolved transitive dependencies using
PyPI's vulnerability service. It does not analyze Flask route source code,
discover unknown vulnerabilities, or prove an advisory is exploitable in this
application. Gitleaks and Semgrep address different security categories.

The scanner is pinned in `security/requirements-sca.txt`, separate from the
application dependencies, and is not added to the application Docker image.
An online advisory service and package resolution are required. Results can
change when new advisories or dependency releases appear.

## Files changed or created

| File | Change | Purpose |
| --- | --- | --- |
| `.github/workflows/security.yml` | Modified | Add SCA installation, controlled validation, application audit, artifacts, and build dependency |
| `.gitignore` | Modified | Ignore the optional `.venv-sca/` environment; existing `reports/` ignore covers JSON output |
| `README.md` | Modified | Describe SCA and link this guide |
| `app/requirements.txt` | Modified | Upgrade Flask 3.0.3 to 3.1.3 to remediate CVE-2026-27205 found by the real audit |
| `security/requirements-sca.txt` | Created | Pin pip-audit independently of runtime/SAST dependencies |
| `security/scripts/validate_pip_audit.py` | Created | Verify a vulnerable Flask pin is detected and an upgraded pin is clean |
| `security/DEPENDENCY_SCANNING.md` | Created | Explain SCA commands, JSON findings, remediation, and CI policy |

Generated reports are ignored by Git and uploaded as CI artifacts. The controlled
test requirements live in a temporary directory; the demonstration does not
downgrade or modify `app/requirements.txt` or install the vulnerable test package.
Separately, the real application audit found a known vulnerability in its
existing Flask pin, so the runtime requirement was upgraded as described below.

## Actual application finding and remediation

The initial audit of `Flask==3.0.3` reported `PYSEC-2026-2151`, with aliases
`CVE-2026-27205` and `GHSA-68rp-wp8r-4726`, and fixed version `3.1.3`. The advisory
concerns session access that fails to set `Vary: Cookie` in certain cases.
Its applicability depends on session usage and caching; a vulnerable package
version is not itself proof this app exposes the vulnerable behavior.

The service returned two entries for this same advisory with different
descriptions. These represent one distinct CVE, not two separate vulnerabilities.
The unmodified local report is retained as
`reports/pip-audit-application-before.json`. Reports are not deduplicated or
suppressed by the scanner integration.

`app/requirements.txt` now pins `Flask==3.1.3`. The repeated application audit
completed with exit 0: seven resolved dependencies, zero vulnerabilities, and
zero skipped dependencies. All seven application unit tests passed with the
upgraded Flask version installed in an isolated temporary environment.

Local verification on 2026-10-21:

| Check | Result |
| --- | --- |
| Controlled Flask 2.2.4 audit | Target advisory detected; exit 1 |
| Controlled upgrade to Flask 3.1.3 | No known vulnerabilities; exit 0 |
| Original application Flask 3.0.3 audit | CVE-2026-27205 detected; exit 1 |
| Upgraded full application dependency audit | Seven dependencies, zero findings; exit 0 |
| Application unit tests after upgrade | Seven tests passed |
| Python syntax and workflow YAML/dependencies/artifact checks | Passed |

A new Docker image has not been built as part of this phase. Rebuild before
running the upgraded container; an existing image still contains its old
dependencies. A hosted GitHub Actions run has not yet been verified.

## Controlled detection and upgrade

The validation script writes a temporary requirements file with `Flask==2.2.4`.
It audits this exact package using `--no-deps --disable-pip`. These options are
used only for the single-package demonstration, avoiding dependency resolution
and installation of the deliberately vulnerable version.

The script requires:

1. Exit code 1 for the vulnerable pin.
2. A JSON dependency named `flask` with version `2.2.4`, not a skipped dependency.
3. A finding identified by `CVE-2023-30861`, either as its main ID or an alias.
4. At least one published fixed version in that finding.
5. Exit code 0 and no vulnerabilities after replacing the test pin with
   `Flask==3.1.3`.

The targeted advisory concerns possible disclosure of permanent session cookies
with particular caching-proxy and session configurations. Its fixes include
Flask 2.2.5 and 2.3.2. The demonstration upgrades to 3.1.3 rather than claiming
that the advisory's first fixed release is necessarily free of all other issues.
The source advisory is linked below.

Expected validation messages include:

```text
PASS: Flask 2.2.4: <advisory ID> (CVE-2023-30861); fixes=<versions>; exit=1
PASS: upgraded test pin to Flask 3.1.3; no known vulnerabilities; exit=0
```

With `--report-dir reports`, the script retains before/after JSON evidence.
Temporary requirements are cleaned up automatically. A missing advisory,
unexpected exit status, skipped package, service error, or newly vulnerable
remediated pin fails validation rather than silently passing.

## Audit the application

The production CI audit uses dependency resolution, unlike the controlled test:

```sh
python -m pip_audit -r app/requirements.txt --strict \
  --vulnerability-service pypi --format json \
  --aliases on --desc on --progress-spinner off \
  --output reports/pip-audit.json
```

This audits Flask and the dependencies selected by the resolver, not every
package installed in the scanner's environment. It does not audit the separate
Gitleaks/Semgrep/pip-audit tooling or operating-system packages in a container.
The project's transitive dependencies are not fully locked; the JSON report
records the exact versions selected during that run. A scan of freshly resolved
requirements does not prove an older deployed image has those same versions.

There are no advisory ignores and no automatic `--fix` in CI. Review fixes,
update dependency pins deliberately, rerun application tests, and audit again.
An empty `fix_versions` list means no fix is currently provided by that advisory,
not that the vulnerable package should be ignored.

## JSON fields

The report is a JSON object with `dependencies` and `fixes` lists. A dependency
without findings still appears with `vulns: []`. An empty `fixes` list is expected
when automatic fixing was not requested; available remediation versions are in
each vulnerability's `fix_versions`.

| JSON field | Meaning |
| --- | --- |
| `dependencies[].name` | Audited package name |
| `dependencies[].version` | Audited package version |
| `dependencies[].vulns[].id` | Primary advisory ID, often a GHSA or PYSEC identifier |
| `dependencies[].vulns[].aliases` | Related identifiers, including CVEs when available |
| `dependencies[].vulns[].fix_versions` | Versions reported as fixing that advisory |
| `dependencies[].vulns[].description` | Advisory description |
| `dependencies[].skip_reason` | Reason a package could not be audited, if applicable |

The pinned pip-audit JSON format does not provide a standardized severity/CVSS
field. Do not infer severity from whether an ID starts with CVE, GHSA, or PYSEC;
consult the linked advisory if severity is needed.

To inspect findings in PowerShell:

```powershell
$audit = Get-Content reports/pip-audit-validation-before.json -Raw | ConvertFrom-Json
$audit.dependencies | ForEach-Object {
    $dependency = $_
    $_.vulns | ForEach-Object {
        [PSCustomObject]@{
            Package = $dependency.name
            Version = $dependency.version
            Advisory = $_.id
            Aliases = $_.aliases -join ', '
            FixedVersions = $_.fix_versions -join ', '
        }
    }
} | Format-Table -Wrap
```

Replace the filename with `reports/pip-audit.json` to inspect actual application
findings rather than the intentionally vulnerable test package.

## Run locally

From the repository root, in PowerShell:

```powershell
python -m venv .venv-sca
.\.venv-sca\Scripts\python.exe -m pip install -r security/requirements-sca.txt
.\.venv-sca\Scripts\python.exe security/scripts/validate_pip_audit.py --report-dir reports
New-Item -ItemType Directory -Force reports | Out-Null
.\.venv-sca\Scripts\python.exe -m pip_audit -r app/requirements.txt --strict --vulnerability-service pypi --format json --aliases on --desc on --progress-spinner off --output reports/pip-audit.json
```

On Linux/macOS, use a virtual environment's `python` with the same requirements,
validation script, and audit command.

## CI behavior and artifacts

`SCA (pip-audit)` runs alongside Gitleaks and Semgrep under the existing push
trigger. `Build and test` depends on all three jobs. For the real audit, pip-audit
returns 0 when no known vulnerabilities are found and 1 when findings exist.
Findings fail the job and prevent the build job from running. Network/resolution
errors also fail the job; `--strict` rejects incomplete dependency collection.
No `continue-on-error` or shell error suppression is used.

The validation step intentionally expects a failing scan of the vulnerable test
pin and a clean scan after its upgrade. These expected scanner outcomes make the
validation step pass; they do not bypass the separate application audit.

An `always()` upload step saves these files as `pip-audit-report` for seven days:

- `pip-audit.json`: real application dependency audit.
- `pip-audit-validation-before.json`: controlled vulnerable pin.
- `pip-audit-validation-after.json`: controlled upgraded pin.

The locally preserved `pip-audit-application-before.json` is historical evidence
from implementation and is not recreated by each CI run. The clean CI runner
uploads only the three reports produced by its own run.

Download the artifact through Actions -> Security CI -> the run -> Artifacts.
If an earlier step fails, some reports may not exist; inspect the failed step's
logs. Local results do not verify a hosted GitHub Actions run.

## References

- [pip-audit documentation](https://github.com/pypa/pip-audit/tree/v2.10.1)
- [Flask advisory CVE-2023-30861](https://github.com/pallets/flask/security/advisories/GHSA-m2qf-hxjv-5gpq)
- [Flask advisory CVE-2026-27205](https://github.com/pallets/flask/security/advisories/GHSA-68rp-wp8r-4726)
- [pip-audit JSON formatter](https://github.com/pypa/pip-audit/blob/v2.10.1/pip_audit/_format/json.py)
