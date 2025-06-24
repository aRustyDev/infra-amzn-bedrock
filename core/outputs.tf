# modules/core/outputs.tf
output "vpc_id" {
  description = "ID of the created VPC"
  value       = aws_vpc.bedrock_vpc.id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.bedrock_vpc.cidr_block
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private[*].id
}

output "bedrock_runtime_vpc_endpoint_id" {
  description = "ID of the Bedrock runtime VPC endpoint"
  value       = aws_vpc_endpoint.bedrock_runtime.id
}

output "bedrock_control_vpc_endpoint_id" {
  description = "ID of the Bedrock control plane VPC endpoint"
  value       = aws_vpc_endpoint.bedrock_control.id
}

output "bedrock_admin_role_arn" {
  description = "ARN of the Bedrock admin role"
  value       = aws_iam_role.bedrock_admin_role.arn
}

output "bedrock_user_role_arn" {
  description = "ARN of the Bedrock user role"
  value       = aws_iam_role.bedrock_user_role.arn
}

output "bedrock_application_role_arn" {
  description = "ARN of the Bedrock application role"
  value       = aws_iam_role.bedrock_application_role.arn
}

output "bedrock_application_instance_profile_name" {
  description = "Name of the instance profile for EC2 instances"
  value       = aws_iam_instance_profile.bedrock_application_profile.name
}

output "claude_sonnet_4_model_id" {
  description = "Model ID for Claude Sonnet 4"
  value       = local.claude_sonnet_4_model_id
}

output "regional_claude_sonnet_4_model_id" {
  description = "Regional Model ID for Claude Sonnet 4"
  value       = local.regional_claude_sonnet_4_model_id
}

output "bedrock_runtime_endpoint_url" {
  description = "URL for Bedrock runtime endpoint"
  value       = "https://bedrock-runtime.${var.region}.amazonaws.com"
}

output "security_group_ids" {
  description = "Security group IDs"
  value = {
    vpc_endpoint = aws_security_group.bedrock_vpc_endpoint.id
    compute      = aws_security_group.bedrock_compute.id
  }
}

output "bedrock_logs_group_name" {
  description = "Name of the Bedrock CloudWatch log group"
  value       = aws_cloudwatch_log_group.bedrock_logs.name
}

output "vpc_flow_logs_group_name" {
  description = "Name of the VPC Flow Logs CloudWatch log group"
  value       = aws_cloudwatch_log_group.vpc_flow_logs.name
}
