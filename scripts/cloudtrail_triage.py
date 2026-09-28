#!/usr/bin/env python3
"""
cloudtrail_triage.py - Flag high-risk activity in AWS CloudTrail logs.

Runs fully offline against exported CloudTrail files (.json or .json.gz), so it
works for incident response on logs pulled from S3 without any AWS credentials.

Checks:
  - Root account usage
  - CloudTrail / GuardDuty / VPC Flow Log tampering
  - Console logins without MFA
  - IAM privilege escalation (policy attachment, new access keys)
  - Security groups opened to the internet (0.0.0.0/0 or ::/0)
  - Bursts of failed console logins from a single IP

Usage:
    python scripts/cloudtrail_triage.py tests/sample_logs/
    python scripts/cloudtrail_triage.py logs/ --min-severity high
    python scripts/cloudtrail_triage.py logs/ --json > findings.json
"""
import argparse
import gzip
import json
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

LOGGING_TAMPER_EVENTS = {
    "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
    "DeleteFlowLogs", "DeleteDetector", "DisableSecurityHub",
}
PRIV_ESC_EVENTS = {
    "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
    "PutUserPolicy", "PutRolePolicy", "CreateAccessKey",
    "CreateLoginProfile", "UpdateAssumeRolePolicy",
}
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
SENSITIVE_PORTS = {22, 3389, 1433, 3306, 5432, 6379, 9200, 27017}
FAILED_LOGIN_THRESHOLD = 5


@dataclass
class Finding:
    severity: str
    rule: str
    event_time: str
    event_name: str
    actor: str
    source_ip: str
    detail: str
    mitre: str


# ---------- loading ----------

def iter_files(paths):
    for p in map(Path, paths):
        if p.is_dir():
            yield from sorted(f for f in p.rglob("*") if f.name.endswith((".json", ".json.gz")))
        elif p.exists():
            yield p
        else:
            print(f"warning: {p} not found", file=sys.stderr)


def load_records(paths):
    records = []
    for f in iter_files(paths):
        opener = gzip.open if f.name.endswith(".gz") else open
        try:
            with opener(f, "rt", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"warning: could not parse {f}: {exc}", file=sys.stderr)
            continue
        records.extend(data.get("Records", []) if isinstance(data, dict) else data)
    return records


# ---------- helpers ----------

def get_actor(rec):
    ui = rec.get("userIdentity") or {}
    return ui.get("arn") or ui.get("userName") or ui.get("type", "unknown")


def finding(rec, severity, rule, detail, mitre):
    return Finding(
        severity=severity,
        rule=rule,
        event_time=rec.get("eventTime", ""),
        event_name=rec.get("eventName", ""),
        actor=get_actor(rec),
        source_ip=rec.get("sourceIPAddress", ""),
        detail=detail,
        mitre=mitre,
    )


# ---------- per-event checks ----------

def check_root_usage(rec):
    ui = rec.get("userIdentity") or {}
    if ui.get("type") == "Root" and not ui.get("invokedBy"):
        return finding(rec, "high", "Root account activity",
                       "Root credentials were used directly.", "T1078.004")


def check_logging_tamper(rec):
    if rec.get("eventName") in LOGGING_TAMPER_EVENTS:
        return finding(rec, "critical", "Logging/monitoring tampering",
                       f"{rec['eventName']} may blind security monitoring.", "T1562.008")


def check_console_no_mfa(rec):
    if rec.get("eventName") != "ConsoleLogin":
        return None
    success = (rec.get("responseElements") or {}).get("ConsoleLogin") == "Success"
    mfa = (rec.get("additionalEventData") or {}).get("MFAUsed")
    if success and mfa == "No":
        return finding(rec, "medium", "Console login without MFA",
                       "Successful console sign-in with no MFA.", "T1078")


def check_priv_esc(rec):
    if rec.get("eventName") not in PRIV_ESC_EVENTS or rec.get("errorCode"):
        return None
    params = json.dumps(rec.get("requestParameters") or {})
    admin = "AdministratorAccess" in params or '"Action": "*"' in params
    return finding(rec, "high" if admin else "medium", "IAM privilege change",
                   ("Admin-level permissions granted. " if admin else "") + params[:200],
                   "T1098")


def check_open_security_group(rec):
    if rec.get("eventName") != "AuthorizeSecurityGroupIngress" or rec.get("errorCode"):
        return None
    params = rec.get("requestParameters") or {}
    perms = (params.get("ipPermissions") or {}).get("items", [])
    for perm in perms:
        cidrs = [r.get("cidrIp") for r in (perm.get("ipRanges") or {}).get("items", [])]
        cidrs += [r.get("cidrIpv6") for r in (perm.get("ipv6Ranges") or {}).get("items", [])]
        open_cidrs = OPEN_CIDRS.intersection(cidrs)
        if not open_cidrs:
            continue
        proto = str(perm.get("ipProtocol"))
        lo, hi = perm.get("fromPort", 0), perm.get("toPort", 65535)
        all_traffic = proto == "-1"
        exposed = sorted(p for p in SENSITIVE_PORTS if lo <= p <= hi)
        severity = "critical" if (all_traffic or exposed) else "medium"
        ports = "ALL" if all_traffic else f"{lo}-{hi}" if lo != hi else str(lo)
        detail = (f"{params.get('groupId', 'unknown SG')} opened {proto}/{ports} "
                  f"to {', '.join(sorted(open_cidrs))}")
        if exposed:
            detail += f" (sensitive ports: {', '.join(map(str, exposed))})"
        return finding(rec, severity, "Security group exposed to internet", detail, "T1562.007")


PER_EVENT_CHECKS = [
    check_root_usage,
    check_logging_tamper,
    check_console_no_mfa,
    check_priv_esc,
    check_open_security_group,
]


# ---------- aggregate checks ----------

def check_failed_login_burst(records, threshold=FAILED_LOGIN_THRESHOLD):
    by_ip = defaultdict(list)
    for rec in records:
        if (rec.get("eventName") == "ConsoleLogin"
                and (rec.get("responseElements") or {}).get("ConsoleLogin") == "Failure"):
            by_ip[rec.get("sourceIPAddress", "unknown")].append(rec)
    findings = []
    for ip, recs in by_ip.items():
        if len(recs) >= threshold:
            users = sorted({get_actor(r) for r in recs})
            last = max(recs, key=lambda r: r.get("eventTime", ""))
            findings.append(finding(
                last, "high", "Brute-force console logins",
                f"{len(recs)} failed logins from {ip} targeting: {', '.join(users)}",
                "T1110"))
    return findings


# ---------- main ----------

def triage(records):
    findings = [f for rec in records for check in PER_EVENT_CHECKS if (f := check(rec))]
    findings += check_failed_login_burst(records)
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.event_time))
    return findings


def print_table(findings):
    if not findings:
        print("No findings.")
        return
    for f in findings:
        print(f"[{f.severity.upper():8}] {f.rule}  ({f.mitre})")
        print(f"    time: {f.event_time}  event: {f.event_name}  ip: {f.source_ip}")
        print(f"    actor: {f.actor}")
        print(f"    {f.detail}\n")
    counts = defaultdict(int)
    for f in findings:
        counts[f.severity] += 1
    summary = ", ".join(f"{counts[s]} {s}" for s in sorted(counts, key=lambda s: -SEVERITY_ORDER[s]))
    print(f"Total: {len(findings)} findings ({summary})")


def main():
    parser = argparse.ArgumentParser(description="Triage AWS CloudTrail logs for high-risk activity.")
    parser.add_argument("paths", nargs="+", help="CloudTrail files or directories")
    parser.add_argument("--min-severity", choices=SEVERITY_ORDER, default="low")
    parser.add_argument("--json", action="store_true", help="output findings as JSON")
    args = parser.parse_args()

    records = load_records(args.paths)
    findings = [f for f in triage(records)
                if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[args.min_severity]]

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print(f"Analyzed {len(records)} events.\n")
        print_table(findings)


if __name__ == "__main__":
    main()
