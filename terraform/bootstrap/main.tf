# Bootstrap stack (PRD 0009 §2).
#
# Chicken-and-egg: the main stack uses an S3 backend, but the bucket
# doesn't exist yet. This stack provisions the backend + the OIDC
# trust GH Actions needs, using local state. Run ONCE per AWS account.
#
# After `terraform apply`, populate terraform/backend.tf with the
# outputs printed here, then `terraform init` in ../ initializes
# against this backend.
#
# State for this bootstrap stack stays local (terraform.tfstate in
# this directory). The resources it manages (bucket, lock table,
# OIDC provider, two IAM roles) are easily recreatable; losing the
# state file just means a re-apply.

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}

locals {
  account_id     = data.aws_caller_identity.current.account_id
  state_bucket   = "coffer-tf-state-${local.account_id}"
  lock_table     = "coffer-tf-lock"
  kms_arn_glob   = "arn:aws:kms:${var.region}:${local.account_id}:key/*"
}

# ────────────────────────────────────────────────────────────────────
# Terraform state backend: S3 bucket + DynamoDB lock table.
# ────────────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "tf_state" {
  bucket = local.state_bucket
}

resource "aws_s3_bucket_versioning" "tf_state" {
  bucket = aws_s3_bucket.tf_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tf_state" {
  bucket = aws_s3_bucket.tf_state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "tf_state" {
  bucket                  = aws_s3_bucket.tf_state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_dynamodb_table" "tf_lock" {
  name         = local.lock_table
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"
  attribute {
    name = "LockID"
    type = "S"
  }
}

# ────────────────────────────────────────────────────────────────────
# GitHub Actions OIDC provider + IAM roles.
# ────────────────────────────────────────────────────────────────────

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

# Deploy role: assumable only from main branch of the trusted repo.
# Permissions: ECR push + ECS update-service + Secrets Manager read.
data "aws_iam_policy_document" "github_deploy_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repo}:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_role" "github_deploy" {
  name               = "coffer-github-deploy"
  assume_role_policy = data.aws_iam_policy_document.github_deploy_trust.json
}

data "aws_iam_policy_document" "github_deploy_permissions" {
  # ECR push.
  statement {
    effect = "Allow"
    actions = [
      "ecr:GetAuthorizationToken",
    ]
    resources = ["*"]
  }
  statement {
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:CompleteLayerUpload",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
      "ecr:BatchGetImage",
      "ecr:DescribeRepositories",
      "ecr:DescribeImages",
    ]
    resources = ["arn:aws:ecr:${var.region}:${local.account_id}:repository/coffer-vault"]
  }
  # ECS rollout.
  statement {
    effect = "Allow"
    actions = [
      "ecs:UpdateService",
      "ecs:DescribeServices",
      "ecs:DescribeTasks",
      "ecs:DescribeTaskDefinition",
      "ecs:ListTasks",
    ]
    resources = ["*"]
  }
  # Read deploy-time secrets metadata (not the values).
  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:DescribeSecret"]
    resources = ["arn:aws:secretsmanager:${var.region}:${local.account_id}:secret:coffer/*"]
  }
  # CloudWatch logs (read for post-deploy debugging).
  statement {
    effect = "Allow"
    actions = [
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:GetLogEvents",
      "logs:FilterLogEvents",
    ]
    resources = ["arn:aws:logs:${var.region}:${local.account_id}:log-group:/ecs/coffer-vault:*"]
  }
}

resource "aws_iam_role_policy" "github_deploy" {
  name   = "coffer-github-deploy"
  role   = aws_iam_role.github_deploy.id
  policy = data.aws_iam_policy_document.github_deploy_permissions.json
}

# Test role: assumable from any ref on the trusted repo (PRs and
# pushes). Permissions narrow to KMS-on-the-trial-key for integration
# tests; DATABASE_URL_TEST etc. come from GH Secrets, not from AWS.
data "aws_iam_policy_document" "github_test_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repo}:*"]
    }
  }
}

resource "aws_iam_role" "github_test" {
  name               = "coffer-github-test"
  assume_role_policy = data.aws_iam_policy_document.github_test_trust.json
}

data "aws_kms_alias" "master" {
  name = var.kms_key_alias
}

data "aws_iam_policy_document" "github_test_permissions" {
  statement {
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = [data.aws_kms_alias.master.target_key_arn]
  }
}

resource "aws_iam_role_policy" "github_test" {
  name   = "coffer-github-test"
  role   = aws_iam_role.github_test.id
  policy = data.aws_iam_policy_document.github_test_permissions.json
}
