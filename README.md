# Detection Engineering Portfolio

Detection rules and security automation built with a **detection-as-code** workflow: every rule is version-controlled, mapped to MITRE ATT&CK, linted automatically, and backed by tests.

![Validate detections](https://github.com/YOUR-USERNAME/detection-engineering-portfolio/actions/workflows/validate.yml/badge.svg)

## What's here

| Area | Contents |
|------|----------|
| `detections/` | [Sigma](https://github.com/SigmaHQ/sigma) rules for Windows endpoints, AWS, and network (DNS) telemetry |
| `scripts/cloudtrail_triage.py` | Offline AWS CloudTrail triage tool for incident response |
| `scripts/validate_rules.py` | Linter that enforces rule quality standards in CI |
| `tests/` | Unit tests and a simulated attack scenario in CloudTrail format |
| `.github/workflows/` | GitHub Actions pipeline that validates every commit |

## MITRE ATT&CK coverage

| Tactic | Technique | Detection |
|--------|-----------|-----------|
| Execution | T1059.001 PowerShell | Encoded PowerShell command line |
| Defense Evasion | T1027 Obfuscated Files | Encoded PowerShell command line |
| Persistence | T1053.005 Scheduled Task | Task created from user-writable path |
| Defense Evasion | T1562.008 Disable Cloud Logs | CloudTrail stopped/deleted/modified |
| Defense Evasion | T1562.007 Modify Cloud Firewall | Security group opened to 0.0.0.0/0 (triage tool) |
| Initial Access | T1078.004 Cloud Accounts | AWS root console login |
| Credential Access | T1110 Brute Force | Failed console login bursts (triage tool) |
| Persistence | T1098 Account Manipulation | IAM admin policy attachment (triage tool) |
| Command & Control | T1071.004 DNS | Possible DNS tunneling via long subdomains |

## CloudTrail triage tool

Analyzes exported CloudTrail logs (`.json` or `.json.gz`) with no AWS credentials needed, which makes it useful when responding to an incident from logs pulled out of S3.

```bash
python scripts/cloudtrail_triage.py tests/sample_logs/
python scripts/cloudtrail_triage.py /path/to/logs --min-severity high
python scripts/cloudtrail_triage.py /path/to/logs --json > findings.json
```

Running it against the included attack scenario reconstructs the full intrusion: a brute-force burst from one IP, a successful root login without MFA from that same IP, CloudTrail logging disabled, admin rights granted to a service account, and SSH opened to the internet.

```
[CRITICAL] Logging/monitoring tampering  (T1562.008)
    time: 2026-09-20T14:12:00Z  event: StopLogging  ip: 203.0.113.50
[CRITICAL] Security group exposed to internet  (T1562.007)
    sg-0abc123def456 opened tcp/22 to 0.0.0.0/0 (sensitive ports: 22)
[HIGH    ] Brute-force console logins  (T1110)
    6 failed logins from 203.0.113.50 targeting: ...user/admin
...
Total: 9 findings (2 critical, 6 high, 1 medium)
```

## Using the Sigma rules

Sigma is a vendor-neutral format, so the same rule can be converted to any SIEM with [sigma-cli](https://github.com/SigmaHQ/sigma-cli):

```bash
pip install sigma-cli
sigma plugin install splunk
sigma convert -t splunk -p sysmon detections/windows/
```

## Detection-as-code workflow

1. Write or update a rule in `detections/`
2. Test it against real or simulated telemetry (see lab setup below)
3. Push. GitHub Actions lints every rule and runs the test suite
4. Merge only when the pipeline passes

## Quick start

```bash
git clone https://github.com/YOUR-USERNAME/detection-engineering-portfolio.git
cd detection-engineering-portfolio
pip install -r requirements.txt
python scripts/validate_rules.py detections/
python -m unittest discover -s tests -v
```

## Lab setup

<!-- Describe your homelab here: e.g. Windows VM with Sysmon, Splunk/Elastic, Atomic Red Team for attack simulation, AWS free-tier account with CloudTrail enabled. -->

## Roadmap

- [ ] Add Azure / Entra ID sign-in detections
- [ ] Validate Windows rules against Atomic Red Team simulations
- [ ] Add threat-intel IOC enrichment script
- [ ] Publish write-ups for each detection

## About

<!-- 2–3 sentences: your background in networking and security, what you're focused on, and a link to LinkedIn. -->
