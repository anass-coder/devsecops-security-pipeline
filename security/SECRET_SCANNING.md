# Phase 5: secret scanning with Gitleaks

## What secret scanning checks

Secret scanning looks for accidentally committed credentials, such as API tokens,
cloud keys, passwords, and private keys. Gitleaks uses built-in patterns and, for
some rules, entropy checks. It does not authenticate to providers to prove a
credential is valid. A synthetic token can therefore exercise the real detector.

This project uses Gitleaks 8.30.1 with its default rules. The workflow downloads
the Linux release and checks its SHA-256 before executing it. This CLI integration
does not need a Gitleaks Action license or provider credentials.

Gitleaks does not replace application tests or scanners for SQL injection,
dependency vulnerabilities, or plaintext password storage. A passing scan does
not mean every hardcoded password was detected or that this training app is safe.

## Step 1: fetch history

The workflow checkout uses `fetch-depth: 0`. The scan runs:

```sh
gitleaks git . --log-opts="--all" --redact \
  --report-format=json --report-path=gitleaks-report.json
```

`git` mode examines commit patches. `--all` scans history reachable from all
locally available Git refs; it cannot inspect unfetched remote refs, other
repositories, or reflog-only/unreachable commits. Uncommitted files are not part
of this scan. For a separate working-directory check, run:

```sh
gitleaks dir . --redact
```

## Step 2: validate detection with a controlled fake secret

Install the matching binary from the official release, put it on PATH, then run:

```sh
python security/scripts/validate_gitleaks.py
```

You can also specify the executable explicitly in PowerShell:

```powershell
python security/scripts/validate_gitleaks.py --gitleaks 'C:\path\to\gitleaks.exe'
```

The script:

1. Creates a temporary Git repository with an isolated Git configuration.
2. Constructs a synthetic GitHub personal-access-token-shaped string and commits
   it in `fake.env`. This value was never issued by GitHub.
3. Runs the same history scan used by CI. It requires exit code 1 and a
   `github-pat` finding for `fake.env`, and verifies the JSON report is redacted.
4. Deletes the file and confirms the original committed secret is still detected.
5. Amends only the disposable repository's unpublished commit to remove the fake
   secret from reachable history, then requires an empty report and exit code 0.
6. Removes the temporary repository and report automatically.

Expected output includes:

```text
PASS: fake secret detected; scanner returned exit 1
Finding: rule=github-pat file=fake.env line=1 commit=<temporary commit>
PASS: deleting the file still leaves the secret in history
PASS: fake secret removed from reachable history; exit 0
```

The full token is constructed only inside the temporary repository, so the test
does not plant a token in this project's files or Git history. No scanner
exclusion is needed. The validation step passes when the scanner fails and then
passes as expected; a broken detector, unexpected error, or failed remediation
causes the validation step itself to fail.

## Step 3: scan the actual repository and read findings

The real scan runs after validation. Findings return exit code 1, which fails the
`Secret scanning (Gitleaks)` job. Other nonzero errors also fail the job; there is
no `continue-on-error`. `Build and test` depends on this job and is skipped when
secret scanning fails. Enforce the check in branch protection if merges must be
blocked; a failed workflow alone does not configure that policy.

The workflow writes its report outside the checkout in `RUNNER_TEMP`, and always
attempts to upload the redacted report as the `gitleaks-report` artifact, including
when the scan finds a secret. Artifacts expire after seven days. An installation
failure may occur before any report exists; inspect the failed step's logs.

JSON findings include:

| Field | Meaning |
| --- | --- |
| `RuleID` | Detection rule, such as `github-pat` |
| `File` | File containing the finding |
| `StartLine` / `EndLine` | Location in the scanned change |
| `Commit` | Commit introducing the matched content |
| `Fingerprint` | Identifier for tracking the finding |
| `Secret` / `Match` | Sensitive content redacted by `--redact` |

## Step 4: handle exclusions and remediation

No project-specific exclusions or baseline are configured. The default rules
found no secrets in the locally available project history during validation.
The controlled test uses a built-in rule rather than a custom always-matching
rule. Do not exclude entire application, test, or security directories to obtain
a green build.

For a confirmed false positive, review the exact finding and use a narrowly
scoped rule/path allowlist in `.gitleaks.toml`, preserving default rules with
`[extend]` and `useDefault = true`. Alternatively, Gitleaks supports exact finding
fingerprints in `.gitleaksignore`. Document the reason and rerun the validation;
never allowlist a real leaked credential.

Secrets in history remain retrievable after a normal deletion commit. For an
actual leak, revoke or rotate the credential first, remove it from current files,
and use environment variables or an appropriate secret store. Coordinate any
history cleanup with collaborators and rescan all available refs. Rewriting
history does not revoke a credential or remove copies from clones or forks.

## Step 5: verify on GitHub

After committing and pushing these changes, open the repository's Actions tab,
select `Security CI`, and inspect `Secret scanning (Gitleaks)` followed by
`Build and test`. Download `gitleaks-report` from the run's artifacts. A clean JSON
report is `[]`. Local validation does not prove that a hosted Actions run passed.

## References

- [Gitleaks documentation](https://github.com/gitleaks/gitleaks/tree/v8.30.1)
- [Pinned release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1)
- [Default detection rules](https://github.com/gitleaks/gitleaks/blob/v8.30.1/config/gitleaks.toml)
