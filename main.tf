# main.tf (root)
# Random string for unique resource names
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# Core infrastructure module (always deployed)
module "core" {
  source = "./core"
  
  # Pass through variables
  project_name              = var.project_name
  environment              = var.environment
  vpc_cidr                 = var.vpc_cidr
  allowed_ip_ranges        = var.allowed_ip_ranges
  admin_user_arns          = var.admin_user_arns
  user_arns               = var.user_arns
  application_assume_role_arns = var.application_assume_role_arns
  external_id             = var.external_id
  max_tokens_limit        = var.max_tokens_limit
  log_retention_days      = var.log_retention_days
  default_tags            = var.default_tags
  
  # Data from root
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# AWS Config module (conditional)
module "config" {
  count  = var.enable_config ? 1 : 0
  source = "./config"
  
  project_name       = var.project_name
  default_tags       = var.default_tags
  account_id         = data.aws_caller_identity.current.account_id
  random_suffix      = random_string.suffix.result
  enable_s3_bucket   = var.enable_config_s3_bucket
}

# CloudTrail module (conditional)
module "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  source = "./cloudtrail"
  
  project_name     = var.project_name
  default_tags     = var.default_tags
  account_id       = data.aws_caller_identity.current.account_id
  region          = data.aws_region.current.name
  random_suffix    = random_string.suffix.result
  enable_s3_bucket = var.enable_cloudtrail_s3_bucket
}

# GuardDuty module (conditional)
module "guardduty" {
  count  = var.enable_guardduty ? 1 : 0
  source = "./guardduty"
  
  default_tags = var.default_tags
}

# Monitoring module (conditional)
module "monitoring" {
  count  = var.enable_monitoring ? 1 : 0
  source = "./monitoring"
  
  project_name            = var.project_name
  default_tags            = var.default_tags
  usage_alarm_threshold   = var.usage_alarm_threshold
  monthly_budget_limit    = var.monthly_budget_limit
  alert_email_addresses   = var.alert_email_addresses
  log_retention_days      = var.log_retention_days
  
  # Dependencies from core module
  bedrock_logs_group_name = module.core.bedrock_logs_group_name
  claude_sonnet_4_model_id = module.core.claude_sonnet_4_model_id
  region                  = data.aws_region.current.name
}
