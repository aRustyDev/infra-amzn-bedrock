# outputs.tf (root)
# Core module outputs
output "vpc_id" {
  description = "ID of the created VPC"
  value       = module.core.vpc_id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = module.core.vpc_cidr_block
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = module.core.private_subnet_ids
}

output "bedrock_runtime_vpc_endpoint_id" {
  description = "ID of the Bedrock runtime VPC endpoint"
  value       = module.core.bedrock_runtime_vpc_endpoint_id
}

output "bedrock_control_vpc_endpoint_id" {
  description = "ID of the Bedrock control plane VPC endpoint"
  value       = module.core.bedrock_control_vpc_endpoint_id
}

output "bedrock_admin_role_arn" {
  description = "ARN of the Bedrock admin role"
  value       = module.core.bedrock_admin_role_arn
}

output "bedrock_user_role_arn" {
  description = "ARN of the Bedrock user role"
  value       = module.core.bedrock_user_role_arn
}

output "bedrock_application_role_arn" {
  description = "ARN of the Bedrock application role"
  value       = module.core.bedrock_application_role_arn
}

output "bedrock_application_instance_profile_name" {
  description = "Name of the instance profile for EC2 instances"
  value       = module.core.bedrock_application_instance_profile_name
}

output "claude_sonnet_4_model_id" {
  description = "Model ID for Claude Sonnet 4"
  value       = module.core.claude_sonnet_4_model_id
}

output "regional_claude_sonnet_4_model_id" {
  description = "Regional Model ID for Claude Sonnet 4"
  value       = module.core.regional_claude_sonnet_4_model_id
}

output "bedrock_runtime_endpoint_url" {
  description = "URL for Bedrock runtime endpoint"
  value       = module.core.bedrock_runtime_endpoint_url
}

output "security_group_ids" {
  description = "Security group IDs"
  value       = module.core.security_group_ids
}

# Conditional outputs
output "cloudwatch_dashboard_url" {
  description = "URL to the CloudWatch dashboard"
  value       = var.enable_monitoring ? module.monitoring[0].cloudwatch_dashboard_url : null
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for alerts"
  value       = var.enable_monitoring ? module.monitoring[0].sns_topic_arn : null
}

output "config_recorder_name" {
  description = "Name of the AWS Config recorder"
  value       = var.enable_config ? module.config[0].config_recorder_name : null
}

output "config_bucket_name" {
  description = "Name of the Config S3 bucket"
  value       = var.enable_config && var.enable_config_s3_bucket ? module.config[0].s3_bucket_name : null
}

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail"
  value       = var.enable_cloudtrail ? module.cloudtrail[0].cloudtrail_arn : null
}

output "cloudtrail_bucket_name" {
  description = "Name of the CloudTrail S3 bucket"
  value       = var.enable_cloudtrail && var.enable_cloudtrail_s3_bucket ? module.cloudtrail[0].s3_bucket_name : null
}

output "guardduty_detector_id" {
  description = "ID of the GuardDuty detector"
  value       = var.enable_guardduty ? module.guardduty[0].detector_id : null
}
