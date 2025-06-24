# modules/cloudtrail/outputs.tf
output "cloudtrail_arn" {
  description = "ARN of the CloudTrail"
  value       = aws_cloudtrail.bedrock_trail.arn
}

output "cloudtrail_name" {
  description = "Name of the CloudTrail"
  value       = aws_cloudtrail.bedrock_trail.name
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket used by CloudTrail"
  value       = local.s3_bucket_name
}

output "s3_bucket_arn" {
  description = "ARN of the S3 bucket used by CloudTrail"
  value       = var.enable_s3_bucket ? module.s3_bucket[0].bucket_arn : null
}
