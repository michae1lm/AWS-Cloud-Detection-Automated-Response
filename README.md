# AWS CloudTrail Detection & Response-Planning Lab

A **local, offline proof of concept** for parsing CloudTrail-format JSON, identifying selected potentially risky changes, and producing **non-destructive response recommendations**. This starter lab demonstrates rule-based cloud threat detection and automated tests.

> **Current scope:** This repository does **not** deploy AWS resources or perform live containment. All sample events are synthetic. "Automated response" means generating a response recommendation, not changing infrastructure.

## Detection rules

| Rule | Event pattern | Severity |
| --- | --- | --- |
| AWS-001 | Successful console sign-in with MFAUsed=No | High |
| AWS-002 | Root principal executing an API operation | High |
| AWS-003 | Public SSH (22) / RDP (3389) security group ingress | High |
| AWS-004 | CloudTrail StopLogging, DeleteTrail, UpdateTrail | High |
| AWS-005 | S3 bucket policy or public-access config change | Medium |

These are triage signals, not confirmed compromises. Each alert identifies a source IP, event time, rule, severity, and recommended review step.

## Quick start

Requirements: Python 3.9+; no AWS account, credentials, paid cloud services, or third-party packages.

```bash
python src/cloudtrail_detector.py examples/cloudtrail_sample.json
python -m unittest discover -s tests -v
```

The first command prints JSON alerts. The second runs tests; the GitHub Actions workflow runs the same suite on push and pull request.

## Architecture

```text
Synthetic CloudTrail JSON -> parser -> detection rules -> JSON alert + safe response plan
                                             |
                                     Python unittest / CI
```

## Limitations

- Educational offline prototype, not a SIEM, GuardDuty replacement, or live AWS deployment.
- Schema coverage is intentionally narrow; CloudTrail fields differ across services and event types.
- Does not ingest events in real time, estimate production false-positive rates, or execute containment.
- S3 policy change is only a review signal; the detector cannot determine if a bucket is publicly accessible.
- No credentials, AWS account IDs, private operational logs, or other secrets.

## Responsible future enhancements

1. Test with permitted, sanitized CloudTrail data and record false positives.
2. Add EventBridge + Lambda integration under least-privilege IAM; document deployment and teardown.
3. Measure detection outcomes before claiming effectiveness.
4. Require explicit human approval for any future remediation.

This code is a **reproducible starter implementation**, not evidence that AWS infrastructure has been deployed.