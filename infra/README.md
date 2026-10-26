# AWS setup (one-time, admin)

The pipeline's only cloud footprint is one private S3 bucket. These steps run once,
with an **admin IAM user's profile (never the root user)**. The pipeline itself then
runs as a separate, least-privilege `cti` user. Design notes:
[`vault/aws-cost-and-security.md`](../vault/aws-cost-and-security.md).

No account ID, bucket name, or credential is committed. Set them in your shell
(`envsubst` fills the templates; on macOS it comes from `brew install gettext`):

```bash
export BUCKET=cti-snapshots-<random-suffix>    # globally unique
export ACCT=$(aws sts get-caller-identity --query Account --output text)
export EMAIL=you@example.com
```

## 1. Cost guardrail first

A $5/month budget alerting on actual (80%) and forecast (100%) spend. The first two
budgets per account are free. Cost Anomaly Detection is on by default in new accounts
(`aws ce get-anomaly-monitors` to check).

```bash
aws budgets create-budget --account-id "$ACCT" \
  --budget '{"BudgetName":"cti-project-5usd","BudgetLimit":{"Amount":"5","Unit":"USD"},"TimeUnit":"MONTHLY","BudgetType":"COST"}' \
  --notifications-with-subscribers "[
    {\"Notification\":{\"NotificationType\":\"ACTUAL\",\"ComparisonOperator\":\"GREATER_THAN\",\"Threshold\":80,\"ThresholdType\":\"PERCENTAGE\"},\"Subscribers\":[{\"SubscriptionType\":\"EMAIL\",\"Address\":\"$EMAIL\"}]},
    {\"Notification\":{\"NotificationType\":\"FORECASTED\",\"ComparisonOperator\":\"GREATER_THAN\",\"Threshold\":100,\"ThresholdType\":\"PERCENTAGE\"},\"Subscribers\":[{\"SubscriptionType\":\"EMAIL\",\"Address\":\"$EMAIL\"}]}
  ]"
```

## 2. Bucket

```bash
aws s3api create-bucket --bucket "$BUCKET" --region us-east-1 --object-ownership BucketOwnerEnforced
aws s3api put-public-access-block --bucket "$BUCKET" \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3control put-public-access-block --account-id "$ACCT" \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-encryption --bucket "$BUCKET" \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
aws s3api put-bucket-versioning --bucket "$BUCKET" --versioning-configuration Status=Enabled
aws s3api put-bucket-policy --bucket "$BUCKET" --policy "$(envsubst < infra/bucket-policy.json)"
aws s3api put-bucket-lifecycle-configuration --bucket "$BUCKET" --lifecycle-configuration file://infra/lifecycle.json
```

Account-level Block Public Access applies to **every** bucket in the account; check
that none is meant to be public before setting it.

## 3. The `cti` user

```bash
aws iam create-user --user-name cti
aws iam put-user-policy --user-name cti --policy-name cti-snapshot-bucket \
  --policy-document "$(envsubst < infra/cti-user-policy.json)"
aws iam create-access-key --user-name cti   # store with `aws configure --profile cti`
aws configure set region us-east-1 --profile cti   # avoids cross-region redirects
```

Then in `.env`: `CTI_S3_BUCKET=$BUCKET` and `CTI_AWS_PROFILE=cti`.

The access key is long-lived. Once the upload is done, deactivate it
(`aws iam update-access-key --user-name cti --access-key-id <id> --status Inactive`)
and reactivate it only when needed.

## Verify

```bash
aws s3api list-objects-v2 --bucket "$BUCKET" --profile cti          # allowed
aws s3api delete-object --bucket "$BUCKET" --key x --profile cti     # AccessDenied
aws s3api get-bucket-policy --bucket "$BUCKET" --profile cti         # AccessDenied
aws s3api list-objects-v2 --bucket "$BUCKET" --profile cti \
  --endpoint-url http://s3.us-east-1.amazonaws.com                     # AccessDenied (no TLS)
```

Overwrites: a `PutObject` without `If-None-Match` is denied by IAM (except manifests),
and one with it is refused by S3 with 412 if the key exists.

## Files

| File | What it grants or sets |
|---|---|
| `cti-user-policy.json` | `ListBucket` on the bucket; `GetObject`/`PutObject` on its objects; explicit Deny on object and bucket deletes, and on any `PutObject` without `If-None-Match` except `*/manifest.json` (write-once enforced by IAM, not just code) |
| `bucket-policy.json` | Denies any request not made over TLS |
| `lifecycle.json` | Expires noncurrent versions after 30 days, removes expired delete markers, aborts incomplete multipart uploads after 1 day |
