output "alb_dns_name" {
  description = "ALB DNS name. REST: http://<dns>/v1/credentials; gRPC: <dns>:80 with -plaintext."
  value       = aws_lb.main.dns_name
}

output "ecr_repository_url" {
  description = "ECR repo URL. GH Actions deploy.yml builds + pushes here."
  value       = aws_ecr_repository.vault.repository_url
}

output "task_role_arn" {
  description = "IAM role the running container assumes (KMS access)."
  value       = aws_iam_role.task.arn
}

output "task_execution_role_arn" {
  description = "IAM role ECS uses to pull the image + fetch secrets."
  value       = aws_iam_role.task_execution.arn
}

output "log_group_name" {
  description = "CloudWatch log group capturing container stdout/stderr."
  value       = aws_cloudwatch_log_group.vault.name
}

output "secret_pg_url_arn" {
  description = "Secret holding COFFER_PG_URL. Populate post-apply per the runbook."
  value       = aws_secretsmanager_secret.pg_url.arn
}

output "secret_grant_pubkey_arn" {
  description = "Secret holding COFFER_GRANT_PUBKEY_PEM. Populate post-apply per the runbook."
  value       = aws_secretsmanager_secret.grant_pubkey.arn
}

output "cluster_name" {
  description = "ECS cluster name. Used by deploy.yml in `aws ecs update-service --cluster ...`."
  value       = aws_ecs_cluster.main.name
}

output "service_name" {
  description = "ECS service name. Used by deploy.yml."
  value       = aws_ecs_service.vault.name
}
