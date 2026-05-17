# Runbook: Foundation (PRD #1)

Decisions, costs, and recovery for the foundational external substrate the vault runs on. Smoke-test artifacts are throwaway by design; this runbook records what is **kept**.

## Decisions

| Item | Value | Notes |
|---|---|---|
| AWS account | `coffer-dev` | Personal account, root used only once for setup |
| AWS region (primary) | `us-west-1` | Matches Supabase region; chosen for California latency |
| Supabase project region | `us-west-1` (N. California) | Matches `aws-1-us-west-1.pooler.supabase.com` |
| KMS key alias | `alias/coffer-dev-master` | Symmetric, single-region, customer-managed |
| KMS key ARN | `arn:aws:kms:<region>:<acct>:key/<uuid>` | Fill in after Phase A9 |
| IAM model | AWS IAM Identity Center (SSO) | No long-lived access keys on dev laptops |
| IdC permission set | `CofferDevPower` | `PowerUserAccess` + inline KMS least-privilege policy |
| AWS CLI profile | `coffer-dev` | `aws configure sso` writes `[sso-session coffer]` + `[profile coffer-dev]` to `~/.aws/config` |
| Supabase tier | Pro ($25/mo) | Includes pooler + 8 GB; $10/mo compute credits cover Micro |
| Postgres connection | Transaction pooler, port **6543** | Direct (5432) reserved for future session-mode needs |
| Dev-laptop secret store | `.env.local` (gitignored) for DSN; AWS SSO token cache (`~/.aws/sso/cache/`) for AWS creds | No long-lived AWS keys on disk |
| Cost ceiling | $10/mo AWS budget alert at 80% | KMS at smoke-test scale is sub-cent/month |

## Smoke-test acceptance

A green `make smoke` proves: AWS SSO → KMS Encrypt → Postgres pooler insert → Postgres select → KMS Decrypt → plaintext match.

Negative check: `make smoke-negative` drops the table, runs smoke, expects `PG: insert (does table credentials_smoketest exist?): ERROR: relation "credentials_smoketest" does not exist`. Then recreates the table. Proves the insert path is genuinely exercised.

## Known gotchas

1. **IAM propagation lag.** Fresh IdC permission-set assignments take 5–10 min before KMS calls succeed. `AccessDenied` immediately after setup is usually patience, not policy.
2. **Supabase pooler port semantics (post Feb 28 2025).** Port `6543` is transaction-mode ONLY; session mode lives on `5432` at the pooler hostname. Mixing them up gives misleading errors.
3. **DSN password special characters.** Use alphanumeric DB passwords. `@` `:` `/` etc. must be `%`-encoded in URL form — easier to rotate the password than encode it.
4. **KMS IAM `Resource` field.** Must be the key ARN. `*` defeats least-privilege; alias strings are not valid in IAM `Resource`.
5. **Default KMS key policy delegates to IAM.** The "Enable IAM User Permissions" statement is what allows IAM policies to grant access. Don't remove it unless you intend the strict dual-grant model.
6. **AWS SSO token TTL.** Default 8h. Re-run `aws sso login --profile coffer-dev` when expired. Short-lived KMS creds are refreshed automatically while SSO token is valid.
7. **Region drift.** KMS key, Supabase project, and AWS profile default region should all match — otherwise every KMS call from the vault crosses regions.
8. **pgx prepared-statement cache + transaction pooler.** pgx v5's default `QueryExecModeCacheStatement` collides with pgbouncer transaction mode (`SQLSTATE 42P05: prepared statement already exists`). Fix: build the driver via `pgx.ParseConfig` + `stdlib.OpenDB` with `DefaultQueryExecMode = pgx.QueryExecModeExec`. Done in `cmd/smoketest/main.go`; remember when writing the real Postgres adapter in PRD 0003.

## Recovery

- **Lost AWS SSO access:** sign into IdC user via the AWS access portal URL (saved in 1Password); reset MFA from the portal.
- **Lost Supabase DB password:** Supabase dashboard → Project Settings → Database → Reset database password. Update `.env.local`.
- **KMS key accidentally disabled:** root user → KMS console → Customer managed keys → re-enable. Key material is preserved for 30 days after a scheduled deletion.
- **Need to rotate IdC permission set:** edit the inline policy in IdC console → re-provision assignment. No code change needed; next `aws sso login` picks up new perms.

## Costs at smoke-test scale

- KMS: $1/mo per CMK + ~$0.03 per 10,000 requests. Smoke test = a few requests/day = sub-cent.
- Supabase Pro: $25/mo flat (covered by your stated unlimited budget).
- AWS account otherwise idle.
- **Total: ~$26/mo while in development.**

## Smoke-test artifacts (throwaway, replaced by later PRDs)

- `cmd/smoketest/main.go` — deleted in PRD 0002 when hexagonal scaffold lands
- `db/smoketest.sql` — replaced by migration framework in PRD 0003
- `credentials_smoketest` table — dropped after first real migration

## Kept artifacts (load-bearing for all later PRDs)

- AWS account, KMS CMK + alias, IdC user + permission set
- Supabase Pro project + DB password
- `~/.aws/config` with `[profile coffer-dev]`
- `go.mod` at module path `github.com/tumultousRamen/coffer`
- This runbook
