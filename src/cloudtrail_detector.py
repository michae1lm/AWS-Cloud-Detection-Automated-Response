"""Offline CloudTrail event detector with non-destructive response recommendations."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from typing import Any

def iter_events(document: Any) -> list[dict[str, Any]]:
    if isinstance(document, dict):
        raw = document.get("Records", [document])
    elif isinstance(document, list):
        raw = document
    else:
        raise ValueError("Expected a JSON event, array, or Records document")
    if not isinstance(raw, list) or any(not isinstance(e, dict) for e in raw):
        raise ValueError("All events must be JSON objects")
    return raw

def _public_ingress(event: dict[str, Any]) -> bool:
    params = event.get("requestParameters") or {}
    groups = (params.get("ipPermissions") or {}).get("items") or []
    for group in groups:
        if not isinstance(group, dict):
            continue
        start, end = group.get("fromPort"), group.get("toPort")
        if not (isinstance(start, int) and isinstance(end, int)):
            continue
        if not any(start <= p <= end for p in (22, 3389)):
            continue
        ipv4 = (group.get("ipRanges") or {}).get("items") or []
        ipv6 = (group.get("ipv6Ranges") or {}).get("items") or []
        if any(x.get("cidrIp") == "0.0.0.0/0" for x in ipv4 if isinstance(x, dict)):
            return True
        if any(x.get("cidrIpv6") == "::/0" for x in ipv6 if isinstance(x, dict)):
            return True
    return False

def detect(event: dict[str, Any]) -> list[dict[str, str]]:
    name = event.get("eventName", "")
    user = event.get("userIdentity") or {}
    alerts: list[dict[str, str]] = []
    def add(rule: str, severity: str, reason: str, response: str) -> None:
        alerts.append({
            "rule_id": rule, "severity": severity, "reason": reason,
            "recommended_response": response,
            "event_name": str(name),
            "event_time": str(event.get("eventTime", "unknown")),
            "source_ip": str(event.get("sourceIPAddress", "unknown")),
        })
    if name == "ConsoleLogin":
        success = (event.get("responseElements") or {}).get("ConsoleLogin") == "Success"
        no_mfa = (event.get("additionalEventData") or {}).get("MFAUsed") == "No"
        if success and no_mfa:
            add("AWS-001", "high", "Successful console login without MFA",
                "Validate account owner and MFA policy; review sign-in activity")
    if user.get("type") == "Root" and name not in {"ConsoleLogin", "AssumeRole"}:
        add("AWS-002", "high", "Root identity made an AWS API call",
            "Validate expected use; inspect related CloudTrail events")
    if name == "AuthorizeSecurityGroupIngress" and _public_ingress(event):
        add("AWS-003", "high", "Public SSH/RDP access added to a security group",
            "Review ingress change and restrict exposure after approval")
    if name in {"StopLogging", "DeleteTrail", "UpdateTrail"}:
        add("AWS-004", "high", "CloudTrail logging configuration changed",
            "Validate change approval and confirm logging coverage")
    if name in {"PutBucketPolicy", "DeleteBucketPolicy", "PutPublicAccessBlock"}:
        add("AWS-005", "medium", "S3 bucket access configuration changed",
            "Review bucket permissions for unintended exposure")
    return alerts

def analyze(document: Any) -> list[dict[str, str]]:
    return [alert for event in iter_events(document) for alert in detect(event)]

def main() -> int:
    parser = argparse.ArgumentParser(description="Review selected CloudTrail events offline")
    parser.add_argument("events", type=Path, help="Local JSON CloudTrail events file")
    args = parser.parse_args()
    try:
        document = json.loads(args.events.read_text(encoding="utf-8"))
        print(json.dumps({"alerts": analyze(document)}, indent=2))
        return 0
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
