# terraform/

Main infrastructure stack for coffer-vault on ECS Fargate.

Spec: PRD 0009 — VPC + private subnets + NAT + ECR + ECS Fargate +
ALB (HTTP + gRPC target groups) + IAM + Secrets Manager (empty shells)
+ CloudWatch logs.

State lives in S3 (`coffer-tf-state-<account-id>`) with a DynamoDB
lock table (`coffer-tf-lock`). Both are provisioned by
`./bootstrap/`; run that once per AWS account before initializing
this stack.

## Apply (first time)

```bash
cd terraform/bootstrap
terraform init
terraform apply
# Note the state_bucket output.

cd ..
terraform init \
  -backend-config="bucket=coffer-tf-state-<account-id>"
terraform apply
```

After apply, populate Secrets Manager and roll the service:

```bash
aws secretsmanager put-secret-value \
  --secret-id coffer/database-url \
  --secret-string "$DATABASE_URL" \
  --region us-west-1
aws secretsmanager put-secret-value \
  --secret-id coffer/grant-pubkey-pem \
  --secret-string "$COFFER_GRANT_PUBKEY_PEM" \
  --region us-west-1
aws ecs update-service \
  --cluster coffer --service coffer-vault \
  --force-new-deployment --region us-west-1
```

Full operator runbook: [../docs/runbook/deployment.md](../docs/runbook/deployment.md).

## Destroy

```bash
terraform destroy
```

The ECR repo has a lifecycle policy capping at 10 images; if destroy
fails on the repo, delete all images first.

## Layout

| File | Contents |
|---|---|
| `versions.tf` | TF + provider version pins |
| `backend.tf` | S3 backend config |
| `variables.tf` | Region, image tag, task sizing |
| `main.tf` | All resources |
| `outputs.tf` | ALB DNS, ECR URL, role ARNs, secret ARNs |
| `bootstrap/` | One-time chicken-and-egg setup (state backend + GH OIDC) |
