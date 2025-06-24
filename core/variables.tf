# modules/core/variables.tf
variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
}

variable "allowed_ip_ranges" {
  description = "List of allowed IP ranges"
  type        = list(string)
}

variable "admin_user_arns" {
  description = "List of IAM user ARNs for admin access"
  type        = list(string)
}

variable "user_arns" {
  description = "List of IAM user ARNs for user access"
  type        = list(string)
}

variable "application_assume_role_arns" {
  description = "List of ARNs for application access"
  type        = list(string)
}

variable "external_id" {
  description = "External ID for cross-account access"
  type        = string
  sensitive   = true
}

variable "max_tokens_limit" {
  description = "Maximum tokens per request"
  type        = number
}

variable "log_retention_days" {
  description = "Log retention period"
  type        = number
}

variable "default_tags" {
  description = "Default tags"
  type        = map(string)
}

variable "account_id" {
  description = "AWS account ID"
  type        = string
}

variable "region" {
  description = "AWS region"
  type        = string
}
