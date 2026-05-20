variable "region" {
  description = "AWS region. Must match bootstrap. PRD 0009 ships us-west-1 only."
  type        = string
  default     = "us-west-1"
}

variable "image_tag" {
  description = "ECR image tag the ECS task definition pulls. GH Actions overrides this per deploy (github.sha); manual applies use `latest`."
  type        = string
  default     = "latest"
}

variable "kms_key_alias" {
  description = "Existing KMS alias the task role is permitted to use. Mirrors COFFER_AWS_KMS_KEY_ID."
  type        = string
  default     = "alias/coffer-dev-master"
}

variable "task_cpu" {
  description = "Fargate task CPU units. 256 = 0.25 vCPU."
  type        = string
  default     = "256"
}

variable "task_memory" {
  description = "Fargate task memory (MiB)."
  type        = string
  default     = "512"
}

variable "desired_count" {
  description = "Number of running tasks. Trial = 1; production should be >=2."
  type        = number
  default     = 1
}

variable "log_retention_days" {
  description = "CloudWatch log group retention. 7 days for trial."
  type        = number
  default     = 7
}
