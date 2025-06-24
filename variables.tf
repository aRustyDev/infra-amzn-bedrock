# variables.tf (root)
# Core configuration
variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
  
  validation {
    condition = can(regex("^[a-z]{2}-[a-z]+-[0-9]$", var.aws_region))
    error_message = "AWS region must be in the format like 'us-east-1'."
  }
}

variable "project_name" {
  description = "Name of the project (used for resource naming)"
  type        = string
  default     = "claude-sonnet-4"
  
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "Project name must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

# Module toggles
variable "enable_config" {
  description = "Enable AWS Config for compliance monitoring"
  type        = bool
  default     = true
}

variable "enable_config_s3_bucket" {
  description = "Enable S3 bucket creation for AWS Config (only used if enable_config is true)"
  type        = bool
  default     = true
}

variable "enable_cloudtrail" {
  description = "Enable CloudTrail for audit logging"
  type        = bool
  default     = true
}

variable "enable_cloudtrail_s3_bucket" {
  description = "Enable S3 bucket creation for CloudTrail (only used if enable_cloudtrail is true)"
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "Enable GuardDuty for threat detection"
  type        = bool
  default     = true
}

variable "enable_monitoring" {
  description = "Enable monitoring and alerting"
  type        = bool
  default     = true
}

# Network configuration
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
  
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid IPv4 CIDR block."
  }
}

variable "allowed_ip_ranges" {
  description = "List of allowed IP ranges for access to Bedrock"
  type        = list(string)
  default     = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  
  validation {
    condition     = length(var.allowed_ip_ranges) > 0
    error_message = "At least one IP range must be specified."
  }
}

# IAM configuration
variable "admin_user_arns" {
  description = "List of IAM user ARNs that can assume the admin role"
  type        = list(string)
  default     = []
}

variable "user_arns" {
  description = "List of IAM user ARNs that can assume the user role"
  type        = list(string)
  default     = []
}

variable "application_assume_role_arns" {
  description = "List of ARNs that can assume the application role"
  type        = list(string)
  default     = []
}

variable "external_id" {
  description = "External ID for cross-account role assumption (recommended for security)"
  type        = string
  default     = ""
  sensitive   = true
}

# Security configuration
variable "max_tokens_limit" {
  description = "Maximum number of tokens allowed per request"
  type        = number
  default     = 4096
  
  validation {
    condition     = var.max_tokens_limit > 0 && var.max_tokens_limit <= 200000
    error_message = "Max tokens limit must be between 1 and 200000."
  }
}

variable "log_retention_days" {
  description = "Number of days to retain CloudWatch logs"
  type        = number
  default     = 30
  
  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch retention period."
  }
}

# Monitoring configuration
variable "usage_alarm_threshold" {
  description = "Threshold for Bedrock usage alarm"
  type        = number
  default     = 1000
}

variable "alert_email_addresses" {
  description = "Email addresses for security alerts"
  type        = list(string)
  default     = []
}

variable "monthly_budget_limit" {
  description = "Monthly budget limit for Bedrock costs in USD"
  type        = string
  default     = "1000"
}

variable "default_tags" {
  description = "Default tags to apply to all resources"
  type        = map(string)
  default = {
    Terraform   = "true"
    Project     = "Claude-Sonnet-4-Bedrock"
    ManagedBy   = "Terraform"
    CostCenter  = "AI-ML"
    Compliance  = "Required"
  }
}
