variable "region" {
  description = "AWS region for the state bucket + lock table + IAM roles. Must match the main stack's region."
  type        = string
  default     = "us-west-1"
}

variable "github_repo" {
  description = "GitHub repository (org/name) trusted by the OIDC roles. The deploy role is locked to refs/heads/main on this repo; the test role accepts any ref on this repo."
  type        = string
  default     = "tumultousRamen/coffer"
}

variable "kms_key_alias" {
  description = "KMS alias the task role + test role are permitted to use. Mirrors COFFER_AWS_KMS_KEY_ID in the binary's config."
  type        = string
  default     = "alias/coffer-dev-master"
}
