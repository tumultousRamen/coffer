# Runbook: Deploy to ECS Fargate

End-to-end procedure for shipping `cmd/vault` to AWS ECS Fargate behind an ALB, with infrastructure managed by Terraform and CI/CD by GitHub Actions. Spec: [PRD 0009](https://github.com/tumultousRamen/coffer/issues/16).

Follow §1 + §2 + §3 once per AWS account. Steady-state deploys after that are just `git push` to `main`.

Acceptance: `curl http://<alb-dns>/healthz` returns 200; `bash scripts/sanity-test.sh --host http://<alb-dns>` passes all 7 REST lifecycle steps.

## 1. Prerequisites

- AWS CLI v2 + a profile with admin (or at least `iam:CreateRole`, `s3:*`, `dynamodb:*`, `ec2:*`, `ecs:*`, `ecr:*`, `elasticloadbalancing:*`, `secretsmanager:*`, `logs:*`, `kms:*`)
- Terraform ≥ 1.7 (`terraform version`)
- Docker (for `make docker-build` verification only; the real build happens in GH Actions)
- The KMS key from the [foundation runbook](foundation.md) exists (alias `coffer-dev-master`)
- This repo cloned locally; you've run `make sanity-test` successfully against `make run`

## 2. One-time bootstrap (state backend + GH OIDC)

```bash
cd terraform/bootstrap
terraform init
terraform apply
```

Apply prints:

- `state_bucket` — e.g. `coffer-tf-state-123456789012`. Pass to `terraform init` in §3.
- `deploy_role_arn` — paste into the repo's **Variables** (not Secrets!) as `COFFER_DEPLOY_ROLE_ARN`.
- `test_role_arn` — paste into the repo's **Variables** as `COFFER_TEST_ROLE_ARN`.

Set repo variables:

```
gh variable set COFFER_DEPLOY_ROLE_ARN --body "<deploy_role_arn>"
gh variable set COFFER_TEST_ROLE_ARN   --body "<test_role_arn>"
```

If you want integration tests to run in CI, also set:

```
gh secret set DATABASE_URL_TEST --body "<your test Supabase pooler DSN>"
```

The bootstrap stack uses local state — its `terraform.tfstate` lives in `terraform/bootstrap/`. Commit it (the resources are not sensitive) or `.gitignore` it (re-apply is cheap). PRD says either is fine.

## 3. First main-stack apply

```bash
cd terraform
terraform init -backend-config="bucket=$(cd bootstrap && terraform output -raw state_bucket)"
terraform apply
```

`terraform apply` takes ~5–8 min (NAT gateway is the long pole). At the end you'll see:

```
alb_dns_name = "coffer-alb-xxxxxxxxxx.us-west-1.elb.amazonaws.com"
ecr_repository_url = "...dkr.ecr.us-west-1.amazonaws.com/coffer-vault"
...
```

The ECS service comes up but the task will crash-loop until you populate secrets (§4) — that's expected.

## 4. Populate secrets

The Terraform stack creates empty Secrets Manager entries. Populate them with the real values once:

```bash
# Re-use the values you've been running locally via .env.local.
set -a; source ../.env.local; set +a

aws secretsmanager put-secret-value \
  --secret-id coffer/database-url \
  --secret-string "$DATABASE_URL" \
  --region us-west-1

aws secretsmanager put-secret-value \
  --secret-id coffer/grant-pubkey-pem \
  --secret-string "$COFFER_GRANT_PUBKEY_PEM" \
  --region us-west-1
```

The task def maps `coffer/database-url` → env var `COFFER_PG_URL` inside the container; the binary keeps reading `COFFER_PG_URL` unchanged.

## 4a. Push the first image (chicken-and-egg fix)

After §3 the ECS service exists but ECR is empty — tasks crash-loop on `ImagePullBackOff`. Trigger `deploy.yml` once manually to push the first image:

```bash
# Option A — from the GH CLI:
gh workflow run deploy.yml --ref main

# Option B — from the GH UI:
#   Actions → deploy → Run workflow → main
```

Or push manually if you'd rather not wait for a CI run:

```bash
ECR=$(terraform output -raw ecr_repository_url)
aws ecr get-login-password --region us-west-1 \
  | docker login --username AWS --password-stdin "$ECR"
docker build -t "$ECR:latest" .
docker push "$ECR:latest"
```

Then force a fresh task so it picks up both the image and the now-populated secrets:

```bash
aws ecs update-service \
  --cluster coffer --service coffer-vault \
  --force-new-deployment --region us-west-1

aws ecs wait services-stable \
  --cluster coffer --services coffer-vault \
  --region us-west-1
```

Verify:

```bash
ALB_DNS=$(terraform output -raw alb_dns_name)
curl -i "http://$ALB_DNS/healthz"
# Expect: HTTP/1.1 200 OK
```

## 5. Push to main → automated deploy

Every push to `main` from here on triggers `.github/workflows/deploy.yml`:

1. Assume `coffer-github-deploy` via OIDC (no long-lived AWS keys in GH)
2. Build the Docker image; push to ECR tagged both `:<sha>` and `:latest`
3. `aws ecs update-service --force-new-deployment`
4. `aws ecs wait services-stable` (5-min timeout)

Watch a deploy in flight:

```bash
gh run watch
```

If the new task fails health checks, `services-stable` times out and the workflow fails — old task keeps serving traffic. Roll back by reverting the merge (or re-deploying a previous good SHA).

## 6. Sanity-test the deployed target

```bash
ALB_DNS=$(cd terraform && terraform output -raw alb_dns_name)
export COFFER_TEST_AWS_KEY_ID=...
export COFFER_TEST_AWS_SECRET=...
export COFFER_TEST_AWS_REGION=us-west-1
bash scripts/sanity-test.sh --host "http://$ALB_DNS"
```

Expect 7/7 PASS lines. Same script, same checks, identical output to `make sanity-test` against localhost — that's the point.

Phase C (gRPC) against deployed:

```bash
TOKEN=$(make mint-grant USER=demo IDS=<credential-id>)
grpcurl -plaintext -H "authorization: Bearer $TOKEN" \
  "$ALB_DNS:80" coffer.v1.Vault/GetCredentials
```

(The PRD notes ALB-with-gRPC over HTTP-only is known fragile. If `grpcurl` against the ALB DNS fails, the REST path on the same DNS still works — gRPC-on-HTTPS is the natural follow-up PRD.)

## 7. Destroy

When you're done with the trial deployment:

```bash
cd terraform
terraform destroy
# Optional — only if you also want to remove the state backend + IAM roles:
cd bootstrap
terraform destroy
```

ECR repos with images won't destroy cleanly. Either delete the images first or temporarily flip `force_delete = true` on `aws_ecr_repository.vault` and re-apply.

## 8. Cost reference

At idle (one task, no traffic): ~$60/mo all-in.

| Component | ~$/mo |
|---|---|
| ALB | 20 |
| NAT gateway | 32 |
| Fargate task (0.25 vCPU + 512 MB) | 9 |
| Secrets Manager (2 secrets) | 1 |
| CloudWatch Logs (7-day retention) | 1–5 |
| ECR storage | <1 |

`terraform destroy` brings all of this to zero.

## Troubleshooting

- **Task crash-loops on first apply.** Secrets aren't populated yet. Run §4.
- **ALB returns 503.** Tasks aren't passing target group health checks yet — wait ~90s after the rollout, or `aws ecs describe-services --cluster coffer --services coffer-vault` to see why.
- **`terraform init` fails on the backend bucket.** You skipped §2, or you're in a different AWS account than bootstrap was run in.
- **GH Actions deploy fails on `configure-aws-credentials`.** `COFFER_DEPLOY_ROLE_ARN` isn't set as a repo variable, or the OIDC trust policy doesn't match the actual repo/ref (recheck `var.github_repo` in bootstrap).
- **Image push fails: "no basic auth credentials".** The `aws-actions/amazon-ecr-login` step failed; check the role has `ecr:GetAuthorizationToken`.
- **gRPC over ALB returns weird status codes.** Known limitation per PRD §Out of Scope — gRPC over HTTPS is the production answer. REST against the same ALB DNS works regardless.
