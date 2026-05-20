# Main stack for coffer-vault on ECS Fargate (PRD 0009 §2).
#
# Layout (top-to-bottom):
#   1. provider + lookups
#   2. VPC + subnets + NAT
#   3. ECR repo
#   4. CloudWatch log group
#   5. Secrets Manager (empty shells; populated post-apply per runbook)
#   6. IAM (task execution + task)
#   7. Security groups (ALB + tasks)
#   8. ALB + target groups + listeners
#   9. ECS cluster + task definition + service

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}
data "aws_kms_alias" "master" {
  name = var.kms_key_alias
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  azs        = slice(data.aws_availability_zones.available.names, 0, 2)

  name = "coffer"
  tags = {
    Project = "coffer"
    PRD     = "0009"
  }
}

# ────────────────────────────────────────────────────────────────────
# VPC + subnets + NAT
# ────────────────────────────────────────────────────────────────────

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(local.tags, { Name = "${local.name}-vpc" })
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = merge(local.tags, { Name = "${local.name}-igw" })
}

# Public subnets (ALB + NAT).
resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 4, count.index)
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = true
  tags = merge(local.tags, {
    Name = "${local.name}-public-${local.azs[count.index]}"
    Tier = "public"
  })
}

# Private subnets (ECS tasks).
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 4, count.index + 2)
  availability_zone = local.azs[count.index]
  tags = merge(local.tags, {
    Name = "${local.name}-private-${local.azs[count.index]}"
    Tier = "private"
  })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  tags = merge(local.tags, { Name = "${local.name}-public-rt" })
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Single NAT in AZ 0 (cost-vs-resilience tradeoff per PRD).
resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = merge(local.tags, { Name = "${local.name}-nat-eip" })
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
  tags          = merge(local.tags, { Name = "${local.name}-nat" })
  depends_on    = [aws_internet_gateway.main]
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
  tags = merge(local.tags, { Name = "${local.name}-private-rt" })
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# ────────────────────────────────────────────────────────────────────
# ECR
# ────────────────────────────────────────────────────────────────────

resource "aws_ecr_repository" "vault" {
  name                 = "${local.name}-vault"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = local.tags
}

resource "aws_ecr_lifecycle_policy" "vault" {
  repository = aws_ecr_repository.vault.name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 10 images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 10
        }
        action = { type = "expire" }
      }
    ]
  })
}

# ────────────────────────────────────────────────────────────────────
# CloudWatch logs
# ────────────────────────────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "vault" {
  name              = "/ecs/${local.name}-vault"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

# ────────────────────────────────────────────────────────────────────
# Secrets Manager (empty shells; populated by the runbook post-apply)
# ────────────────────────────────────────────────────────────────────

resource "aws_secretsmanager_secret" "pg_url" {
  # Name matches the operator playbook (PRD 0009 comment) which sources
  # $DATABASE_URL from .env.local and puts it under coffer/database-url.
  # The task def below maps this secret's value into COFFER_PG_URL so the
  # binary (which still reads its COFFER_* env var) sees no change.
  name                    = "coffer/database-url"
  description             = "Supabase pooler DSN. Mapped into COFFER_PG_URL in the task def. Populate via `aws secretsmanager put-secret-value` after first apply."
  recovery_window_in_days = 0
  tags                    = local.tags
}

resource "aws_secretsmanager_secret" "grant_pubkey" {
  name                    = "coffer/grant-pubkey-pem"
  description             = "ed25519 public key (PEM) consumed as COFFER_GRANT_PUBKEY_PEM. Populate via `aws secretsmanager put-secret-value` after first apply."
  recovery_window_in_days = 0
  tags                    = local.tags
}

# ────────────────────────────────────────────────────────────────────
# IAM roles
# ────────────────────────────────────────────────────────────────────

# Task execution role: ECS uses this to pull the image, fetch secrets
# at task-start time, and write logs.
data "aws_iam_policy_document" "task_execution_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "task_execution" {
  name               = "${local.name}-task-execution"
  assume_role_policy = data.aws_iam_policy_document.task_execution_trust.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "task_execution_managed" {
  role       = aws_iam_role.task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "task_execution_extra" {
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
    ]
    resources = [
      aws_secretsmanager_secret.pg_url.arn,
      aws_secretsmanager_secret.grant_pubkey.arn,
    ]
  }
}

resource "aws_iam_role_policy" "task_execution_extra" {
  name   = "${local.name}-task-execution-extra"
  role   = aws_iam_role.task_execution.id
  policy = data.aws_iam_policy_document.task_execution_extra.json
}

# Task role: the running container assumes this. Scoped to the KMS key
# the binary touches (mirrors the local-dev IAM policy from PRD 0001).
data "aws_iam_policy_document" "task_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "task" {
  name               = "${local.name}-task"
  assume_role_policy = data.aws_iam_policy_document.task_trust.json
  tags               = local.tags
}

data "aws_iam_policy_document" "task_permissions" {
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

resource "aws_iam_role_policy" "task" {
  name   = "${local.name}-task"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task_permissions.json
}

# ────────────────────────────────────────────────────────────────────
# Security groups
# ────────────────────────────────────────────────────────────────────

resource "aws_security_group" "alb" {
  name        = "${local.name}-alb"
  description = "coffer ALB ingress"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${local.name}-alb" })
}

resource "aws_security_group" "nlb" {
  name        = "${local.name}-nlb"
  description = "coffer gRPC NLB ingress"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "gRPC (h2c) from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${local.name}-nlb" })
}

resource "aws_security_group" "tasks" {
  name        = "${local.name}-tasks"
  description = "coffer ECS tasks ingress from ALB (REST) and NLB (gRPC)"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "REST from ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  ingress {
    description     = "gRPC from NLB"
    from_port       = 8443
    to_port         = 8443
    protocol        = "tcp"
    security_groups = [aws_security_group.nlb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${local.name}-tasks" })
}

# ────────────────────────────────────────────────────────────────────
# ALB + target groups + listener
# ────────────────────────────────────────────────────────────────────

resource "aws_lb" "main" {
  name               = "${local.name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  tags = local.tags
}

resource "aws_lb_target_group" "http" {
  name        = "${local.name}-http"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path                = "/healthz"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
    timeout             = 5
    matcher             = "200"
  }

  tags = local.tags
}

resource "aws_lb_target_group" "grpc" {
  name        = "${local.name}-grpc"
  port        = 8443
  # AWS constraint: ALB HTTP listeners cannot forward to HTTP2 or GRPC
  # protocol_version target groups (both require HTTPS). Trial has no TLS.
  # Solution: NLB (L4 TCP) for gRPC; ALB stays for REST. NLB doesn't care
  # about HTTP semantics; gRPC frames pass through as TCP. Worker SDK uses
  # -plaintext (h2c). Switch to ALB + HTTPS + GRPC protocol_version when
  # the HTTPS PRD lands (single LB; ACM cert; ALB-level gRPC routing).
  protocol    = "TCP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    # NLB target groups can do HTTP health checks even when forward traffic
    # is TCP. We probe /healthz on the REST port (8080) — same handler the
    # ALB probes. Container stays healthy iff Postgres + KMS are reachable
    # (per cmd/vault/main.go readyz logic; healthz is liveness-only).
    protocol            = "HTTP"
    port                = "8080"
    path                = "/healthz"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
    timeout             = 5
    matcher             = "200"
  }

  tags = local.tags
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.http.arn
  }
}

# ────────────────────────────────────────────────────────────────────
# NLB + listener for gRPC (separate from ALB; see grpc target group
# comment for the AWS-constraint reasoning).
# ────────────────────────────────────────────────────────────────────

resource "aws_lb" "grpc" {
  name                             = "${local.name}-grpc"
  internal                         = false
  load_balancer_type               = "network"
  security_groups                  = [aws_security_group.nlb.id]
  subnets                          = aws_subnet.public[*].id
  enable_cross_zone_load_balancing = true

  tags = local.tags
}

resource "aws_lb_listener" "grpc" {
  load_balancer_arn = aws_lb.grpc.arn
  port              = 443
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.grpc.arn
  }
}

# ────────────────────────────────────────────────────────────────────
# ECS cluster + service
# ────────────────────────────────────────────────────────────────────

resource "aws_ecs_cluster" "main" {
  name = local.name
  tags = local.tags

  setting {
    name  = "containerInsights"
    value = "disabled"
  }
}

resource "aws_ecs_cluster_capacity_providers" "main" {
  cluster_name       = aws_ecs_cluster.main.name
  capacity_providers = ["FARGATE"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

resource "aws_ecs_task_definition" "vault" {
  family                   = "${local.name}-vault"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.task_execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([
    {
      name      = "vault"
      image     = "${aws_ecr_repository.vault.repository_url}:${var.image_tag}"
      essential = true

      portMappings = [
        { containerPort = 8080, protocol = "tcp" },
        { containerPort = 8443, protocol = "tcp" },
      ]

      environment = [
        { name = "COFFER_AWS_REGION", value = var.region },
        { name = "COFFER_AWS_KMS_KEY_ID", value = var.kms_key_alias },
        { name = "COFFER_HTTP_LISTEN", value = ":8080" },
        { name = "COFFER_GRPC_LISTEN", value = ":8443" },
      ]

      secrets = [
        { name = "COFFER_PG_URL", valueFrom = aws_secretsmanager_secret.pg_url.arn },
        { name = "COFFER_GRANT_PUBKEY_PEM", valueFrom = aws_secretsmanager_secret.grant_pubkey.arn },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.vault.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "vault"
        }
      }
    }
  ])

  tags = local.tags
}

resource "aws_ecs_service" "vault" {
  name                              = "${local.name}-vault"
  cluster                           = aws_ecs_cluster.main.id
  task_definition                   = aws_ecs_task_definition.vault.arn
  desired_count                     = var.desired_count
  launch_type                       = "FARGATE"

  # Postgres migrations run on container boot (ADR 0010 §3). Grace
  # period stops ALB from killing the task during that ~30-60s window
  # before the HTTP/gRPC servers are accepting traffic.
  health_check_grace_period_seconds = 120

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.http.arn
    container_name   = "vault"
    container_port   = 8080
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.grpc.arn
    container_name   = "vault"
    container_port   = 8443
  }

  # Ignore image_tag drift caused by GH Actions deploys. GH Actions
  # calls `aws ecs update-service --force-new-deployment` which
  # bumps the task def; subsequent `terraform apply` shouldn't try to
  # roll back to var.image_tag.
  lifecycle {
    ignore_changes = [task_definition]
  }

  depends_on = [aws_lb_listener.http, aws_lb_listener.grpc]

  tags = local.tags
}
