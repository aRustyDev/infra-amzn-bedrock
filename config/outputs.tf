# modules/config/outputs.tf
output "config_recorder_name" {
  description = "Name of the AWS Config recorder"
  value       = aws_config_configuration_recorder.bedrock_config.name
}

output "config_delivery_channel_name" {
  description = "Name of the Config delivery channel"
  value       = aws_config_delivery_channel.bedrock_config.name
}

output "config_role_arn" {
  description = "ARN of the Config IAM role"
  value       = aws_iam_role.config_role.arn
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket used by Config"
  value       = local.s3_bucket_name
}

output "s3_bucket_arn" {
  description = "ARN of the S3 bucket used by Config"
  value       = var.enable_s3_bucket ? module.s3_bucket[0].bucket_arn : null
}
