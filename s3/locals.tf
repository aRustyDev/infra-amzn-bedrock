# modules/s3/locals.tf
locals {
  common_tags = merge(var.default_tags, {
    Module = "s3"
    Purpose = var.bucket_purpose
  })
  
  # Purpose-specific configurations
  bucket_configs = {
    config = {
      service_principal = "config.amazonaws.com"
      trail_arn = null
    }
    cloudtrail = {
      service_principal = "cloudtrail.amazonaws.com"
      trail_arn = "arn:aws:cloudtrail:${var.region}:${var.account_id}:trail/${var.project_name}-cloudtrail"
    }
  }
  
  config = local.bucket_configs[var.bucket_purpose]
}
