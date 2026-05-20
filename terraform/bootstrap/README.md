# terraform/bootstrap

One-time bootstrap for the coffer Terraform deployment. Provisions the
S3 + DynamoDB backend the main stack uses, plus the GitHub OIDC trust
relationships GH Actions needs to assume IAM roles without long-lived
AWS keys.

Use **once per AWS account**. The state file stays local
(`terraform.tfstate` in this directory) — the S3 backend doesn't
exist yet, so we can't store state in it. Losing the file just means a
re-apply: the resources are easily recreatable.

## What this creates

| Resource | Purpose |
|---|---|
| `coffer-tf-state-<account-id>` (S3) | Backend for `terraform/main.tf` state |
| `coffer-tf-lock` (DynamoDB) | State lock for the main stack |
| `token.actions.githubusercontent.com` OIDC provider | Federated trust root |
| `coffer-github-deploy` role | GH Actions deploy.yml — push image + roll ECS, locked to refs/heads/main |
| `coffer-github-test` role | GH Actions test.yml — integration tests, any ref on the repo |

## Apply

```bash
cd terraform/bootstrap
terraform init
terraform apply
```

Outputs include the deploy / test role ARNs and the S3 bucket name.
Copy these into `../backend.tf` (or pass them as `-backend-config=...`
on the main stack's `terraform init`).

## Destroy

Only do this if you're tearing down the entire deployment. The S3
bucket will fail to destroy if it still has state objects; empty it
first or pass `force_destroy = true` and re-apply.

```bash
terraform destroy
```
