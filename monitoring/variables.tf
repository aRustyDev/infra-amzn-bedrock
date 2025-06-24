# modules/monitoring/variables.tf
variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "default_tags" {
  description = "Default tags"
  type        = map(string)
}

variable "usage_alarm_threshold" {
  description = "Threshold for Bedrock usage alarm"
  type        = number
}

variable "monthly_budget_limit" {
  description = "Monthly budget limit for Bedrock costs in USD"
  type        = string
}

variable "alert_email_addresses" {
  description = "Email addresses for security alerts"
  type        = list(string)
}

variable "log_retention_days" {
  description = "Log retention period"
  type        = number
}

variable "bedrock_logs_group_name" {
  description = "Name of the Bedrock CloudWatch log group"
  type        = string
}

variable "claude_sonnet_4_model_id" {
  description = "Claude Sonnet 4 model ID"
  type        = string
}

variable "region" {
  description = "AWS region"
  type        = string
}

variable "enable_sns_notifications" {
  description = "Enable SNS email notifications"
  type        = bool
  default     = true
}

variable "enable_budget_alerts" {
  description = "Enable budget alerts"
  type        = bool
  default     = true
}

variable "failed_calls_threshold" {
  description = "Threshold for failed calls alarm"
  type        = number
  default     = 10
}
