#!/usr/bin/env python3
"""
validate_rules.py - Lint Sigma detection rules before they are merged.

Checks every .yml file under the given directory for:
  - required fields and a valid UUID id (unique across the repo)
  - an allowed status and level
  - at least one MITRE ATT&CK technique tag (attack.tXXXX)
  - a detection block that contains a condition

Usage:
    python scripts/validate_rules.py detections/
Exit code is non-zero if any rule fails, so it can gate CI.
"""
import sys
import uuid
from pathlib import Path

import yaml

REQUIRED_FIELDS = ["title", "id", "status", "description", "author", "date",
                   "tags", "logsource", "detection", "level"]
VALID_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}


def validate(path: Path, seen_ids: dict) -> list[str]:
    errors = []
    try:
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"invalid YAML: {exc}"]
    if not isinstance(rule, dict):
        return ["file does not contain a YAML mapping"]

    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"missing required field '{field}'")

    rule_id = str(rule.get("id", ""))
    try:
        uuid.UUID(rule_id)
    except ValueError:
        errors.append(f"id '{rule_id}' is not a valid UUID")
    if rule_id in seen_ids:
        errors.append(f"duplicate id (also used in {seen_ids[rule_id]})")
    seen_ids[rule_id] = path

    if rule.get("status") not in VALID_STATUS:
        errors.append(f"status must be one of {sorted(VALID_STATUS)}")
    if rule.get("level") not in VALID_LEVELS:
        errors.append(f"level must be one of {sorted(VALID_LEVELS)}")

    tags = rule.get("tags") or []
    if not any(str(t).startswith("attack.t") for t in tags):
        errors.append("needs at least one ATT&CK technique tag (e.g. attack.t1059.001)")

    detection = rule.get("detection") or {}
    if "condition" not in detection:
        errors.append("detection block has no 'condition'")

    return errors


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "detections")
    files = sorted(root.rglob("*.yml")) + sorted(root.rglob("*.yaml"))
    if not files:
        print(f"No rules found under {root}")
        return 1

    seen_ids: dict = {}
    failed = 0
    for path in files:
        errors = validate(path, seen_ids)
        if errors:
            failed += 1
            print(f"FAIL {path}")
            for err in errors:
                print(f"     - {err}")
        else:
            print(f"PASS {path}")

    print(f"\n{len(files) - failed}/{len(files)} rules passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
