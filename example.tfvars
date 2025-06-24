# terraform.tfvars.example
# Copy this file to terraform.tfvars and customize the values

# AWS Configuration
aws_region = "us-east-1"
project_name = "claude-sonnet-4"
environment = "dev"

# Module toggles - Set to false to disable features for development
enable_config     = true   # AWS Config compliance monitoring
enable_cloudtrail = true   # API audit logging
enable_guardduty  = true   # Threat detection
enable_monitoring = true   # CloudWatch dashboards and alerts

# S3 bucket toggles - Control S3 bucket creation per module
enable_config_s3_bucket     = true   # Create S3 bucket for Config
enable_cloudtrail_s3_bucket = true   # Create S3 bucket for CloudTrail

# Development examples:
# enable_config_s3_bucket     = false  # Use existing bucket or disable
# enable_cloudtrail_s3_bucket = false  # Use existing bucket or disable

# Network Configuration
vpc_cidr = "10.0.0.0/16"
allowed_ip_ranges = [
  "203.0.113.0/24",    # Replace with your office IP range
  "198.51.100.0/24",   # Replace with your home IP range
  "10.0.0.0/16"        # VPC internal traffic
]

# IAM Configuration - Replace with actual ARNs
admin_user_arns = [
  "arn:aws:iam::123456789012:user/admin-user-1",
  "arn:aws:iam::123456789012:user/admin-user-2"
]

user_arns = [
  "arn:aws:iam::123456789012:user/bedrock-user-1",
  "arn:aws:iam::123456789012:user/bedrock-user-2"
]

application_assume_role_arns = [
  "arn:aws:iam::123456789012:role/application-role",
  "arn:aws:iam::123456789012:root"  # For cross-account access
]

# Security Configuration
external_id = "unique-external-id-for-cross-account-access"
max_tokens_limit = 4096
log_retention_days = 30

# Monitoring and Alerting (only used if enable_monitoring = true)
usage_alarm_threshold = 1000
monthly_budget_limit = "1000"
alert_email_addresses = [
  "security-team@company.com",
  "admin@company.com"
]

# Tags
default_tags = {
  Terraform   = "true"
  Project     = "Claude-Sonnet-4-Bedrock"
  ManagedBy   = "Terraform"
  CostCenter  = "AI-ML"
  Compliance  = "Required"
  Owner       = "your-team@company.com"
}
