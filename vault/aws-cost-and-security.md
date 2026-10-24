---
tags: [aws, security, cost]
---

# AWS: Cost and Security

S3 is the **only** AWS service. All compute runs locally.

## Bucket

- One private bucket in us-east-1, S3 Standard (cheapest at <1 GB; IA and
  Intelligent-Tiering add minimums and fees).
- Block Public Access at account and bucket level; ACLs disabled (bucket owner enforced).
- Default SSE-S3 encryption (free). No SSE-KMS (per-request cost).
- Bucket policy denies requests without TLS (`aws:SecureTransport = false`).
- Versioning on, with lifecycle rules: expire noncurrent versions, remove expired delete
  markers, abort incomplete multipart uploads after 1 day.

## Access

- Pipeline uses a dedicated `cti` profile: Get/Put/List on this bucket only, explicit
  Deny on `DeleteObject`. boto3 default credential chain; no keys in code or repo.
- Bucket setup is a one-time admin step, separate from `cti`, never run as root.
- Account ID and bucket name are not committed; they come from local config.

## Cost guardrails

- AWS Budgets alert at $5/month (actual + forecast), created **before** the bucket.
  Budget alerts are free.
- Cost Anomaly Detection (free).
- No CloudTrail data events.

Used by [[ingest-once-snapshot]]. Data handling: [[data-sources]].
