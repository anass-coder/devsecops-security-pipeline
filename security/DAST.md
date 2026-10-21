# Phase 9: dynamic application security testing with OWASP ZAP

## What is being tested?

DAST sends HTTP requests to a running application and examines its responses.
Semgrep instead reads source code, and Trivy inventories image components.
This phase uses the official ZAP stable image, pinned by digest in the workflow:

```text
ghcr.io/zaproxy/zaproxy@sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6
```

The locally tested image reports ZAP version 2.17.0. Pinning the digest also pins
its bundled add-ons rather than changing scanner behavior on every image pull.

## Why a baseline scan?

The baseline runs a short spider and passive response checks. It is a bounded
first DAST stage for this small API. It does not run an active attack scan, prove
SQL injection is absent, test every payload, or establish authenticated coverage.
A full scan would add active attack payloads and typically take longer.

JSON endpoint listings are not reliable crawler navigation. `zap_hooks.py`
therefore sends these six requests through ZAP before spidering:

| Method | Path / case | Expected status |
| --- | --- | --- |
| GET | `/` | 200 |
| GET | `/health` | 200 |
| GET | `/users/1` | 200 |
| GET | `/users/99999` | 404 |
| POST | `/login`, nonexistent test user and invalid password | 401 |
| POST | `/login`, empty JSON object | 400 |

These are application requests, not fuzzing payloads. Successful authenticated
sessions are not configured. The hook saves `coverage.json`, and the runner
requires confirmation of all six requests. The spider may request additional
paths, including `/robots.txt` and `/sitemap.xml`.

## CI execution

The DAST steps run in the existing build job after container scanning, using the
same commit-tagged application image. `run_zap.py`:

1. Creates a unique internal Docker network.
2. Starts a controlled application container with the `nosniff` response header
   removed in memory. The production image and source are not modified by this
   control, and there is no production environment-variable bypass.
3. Checks `http://127.0.0.1:5000/health` from inside the app container until it
   returns HTTP 200 and `{"status":"ok"}`, with a 60-second readiness deadline.
4. Starts ZAP on the same network, targeting `http://app:5000/`. Here `app` is
   a Docker network alias; ZAP's own localhost would refer to the scanner itself.
5. Runs a one-minute baseline spider with bounded startup/passive-scan waiting,
   seeds the API requests, and generates JSON/HTML reports and logs.
6. Requires missing-header alert 10021 in the controlled before-report.
7. Stops those containers, starts the normal final application, waits for health,
   and repeats the scan. Alert 10021 must now be absent.
8. Removes the owned temporary containers and network in cleanup.

No host port is published for the app or ZAP API. Internal networking works on
Linux CI and Docker Desktop without relying on host-network behavior. The ZAP
image must be available before creating the isolated network; Docker pulls the
image through the host engine if necessary. ZAP's `-silent` setting disables
startup update checks for this pinned, isolated run.

The custom seed hook is used with `--autooff`, selecting the packaged baseline
script's supported hook flow. Logs are saved per phase so scanner errors remain
reviewable. The workflow bounds the entire DAST scan step to 15 minutes.

## Findings and remediation

### Controlled finding: missing anti-MIME-sniffing header

- ZAP plugin: **10021**, X-Content-Type-Options Header Missing.
- Risk: **Low**, risk code **1**.
- Observation: HTTP responses lack `X-Content-Type-Options: nosniff`.
- Remediation: `app.after_request` adds the header to successful responses and
  Flask-generated error responses.

The controlled container registers a final response callback that strips only
this header. It is the same application and routes, so the comparison exercises
the real ZAP detector against HTTP, rather than using fabricated scanner JSON.
The final container uses the default entrypoint and retains the remediation.

### Finding discovered during validation: missing CSP

The first scan of the application with `nosniff` added still reported plugin
**10038**, Content Security Policy Header Not Set, risk **Medium** (code **2**).
An example was the HTML 404 response for `/robots.txt`. The initial DAST gate
returned exit 1, demonstrating that a real Medium alert blocks the pipeline.

The application now sets this policy on its responses:

```http
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'
```

This restrictive CSP fits the current JSON API and simple error pages. If a
browser UI is added later, review its required resources and form behavior when
updating the policy. The unit tests cover security headers on success and errors.

## ZAP risk levels and JSON fields

| `riskcode` | Risk |
| --- | --- |
| `0` | Informational |
| `1` | Low |
| `2` | Medium |
| `3` | High |

ZAP does not use Trivy's CRITICAL level. `confidence` describes certainty, not
impact. For example, `riskdesc: "Medium (High)"` means Medium risk with High
confidence. Packaged scan statuses such as WARN and FAIL are policy labels,
not separate vulnerability severities.

The JSON report contains a top-level `site` list. Each site includes `@name`
and `alerts`. Important alert fields are:

| Field | Meaning |
| --- | --- |
| `pluginid` | Detection rule ID, for example `10021` |
| `alert` / `name` | Finding name |
| `riskcode`, `riskdesc` | Risk level and readable description |
| `confidence` | Confidence level |
| `desc` | Finding explanation, often HTML text |
| `solution` | Remediation guidance |
| `instances[].uri` | Affected URL |
| `instances[].method` | HTTP method |
| `instances[].evidence` | Observed evidence, if provided |
| `count` | Number of observed instances for the alert type |

Risk summaries count alert types, not every affected URL. An empty alert list
is accepted only in a report with the expected scanned site; missing reports,
unexpected targets, and invalid risk values fail report validation.

## DAST gate and artifacts

`check_zap.py` reads the **final** JSON report and writes `summary.json`.
It returns exit 1 for Medium or High alerts, or a regression of required plugin
10021 even though that finding is Low risk. Other Low/Informational alerts are
retained and reported without blocking. The expected controlled before-report
is not used as the final gate input.

The baseline command uses `-I` to let ordinary WARN results reach the separate
risk-based JSON gate. Scanner failures still return nonzero and fail the runner.
No alerts are hidden using IGNORE rules or blanket exclusions.

The `zap-report` Actions artifact is retained for seven days and contains:

- `before/zap.json`, `before/zap.html`: controlled missing-header scan.
- `final/zap.json`, `final/zap.html`: normal remediated application scan.
- `before/coverage.json`, `final/coverage.json`: seeded request/status evidence.
- Per-phase `scan.log` and `app.log`: scanner and application diagnostics.
- `summary.json`: machine-readable final policy decision.

The upload uses `always()` so findings and logs remain available after a failed
gate or scan. Some files may not exist if the failure occurred before report
generation. The local `reports/zap-initial/` directory preserves the first scan
and failing CSP gate as historical evidence; it is not generated on every CI run.

## Files changed or created in Phase 9

| File | Change | Purpose |
| --- | --- | --- |
| `.github/workflows/security.yml` | Modified | Add pinned ZAP execution, JSON gate, and artifact upload |
| `app/app.py` | Modified | Add nosniff and CSP response headers |
| `tests/test_app.py` | Modified | Check headers on successful and error responses |
| `tests/test_zap_report.py` | Created | Test gate decisions, regression detection, and invalid-report rejection |
| `security/scripts/run_zap.py` | Created | Manage isolated app/scanner lifecycle, readiness, before/after scans, and cleanup |
| `security/scripts/zap_hooks.py` | Created | Seed API coverage and verify HTTP statuses through ZAP |
| `security/scripts/check_zap.py` | Created | Interpret JSON alerts and emit the machine-readable gate result |
| `security/DAST.md` | Created | Document coverage, findings, remediation, reports, and policy |
| `README.md` | Modified | Link and describe the DAST stage |

This table describes the additions and edits for Phase 9; the previous pipeline
stages remain in place.

## Local verification results

Verified on 2026-10-21 using ZAP 2.17.0:

| Check | Result |
| --- | --- |
| Controlled missing `nosniff` header | Alert 10021 detected over HTTP |
| Initial application without CSP | Alert 10038 detected; JSON gate returned exit 1 |
| Remediated final application | Alerts 10021 and 10038 absent |
| Final DAST gate | Exit 0; no Medium or High alerts |
| Remaining final alert | 10036, server version disclosure, Low risk |
| Explicit request coverage | All six requests confirmed in each final comparison scan |
| Application and DAST-policy tests | All 12 passed inside the final image |
| Python syntax, workflow order, artifact/failure checks | Passed |
| Temporary containers and network | Removed; cleanup verified |

The remaining Low alert identifies the development server's `Server` header.
It remains in the report under the stated Low-risk policy. This phase does not
replace Flask's development server with a production HTTP deployment.

The local final report and summary are under `reports/zap/final/` and
`reports/zap/summary.json`. A hosted Actions run has not yet been verified.

## Run locally

With Docker running, from the repository root:

```powershell
docker build --pull -t devsecops-security-app:local .
python security/scripts/run_zap.py --image devsecops-security-app:local --zap-image ghcr.io/zaproxy/zaproxy@sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6 --report-dir reports/zap
python security/scripts/check_zap.py reports/zap/final/zap.json --summary reports/zap/summary.json
```

The scripts use Python's standard library; Flask and ZAP run in their containers.
Open `reports/zap/final/zap.html` for a readable report or inspect `zap.json` and
`summary.json` for automation. Reports remain ignored by Git through `reports/`.

## References

- [ZAP baseline scan](https://www.zaproxy.org/docs/docker/baseline-scan/)
- [ZAP full scan](https://www.zaproxy.org/docs/docker/full-scan/)
- [Missing nosniff alert 10021](https://www.zaproxy.org/docs/alerts/10021/)
- [Missing CSP alert 10038](https://www.zaproxy.org/docs/alerts/10038/)
