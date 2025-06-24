# modules/cloudtrail/locals.tf
locals {
  common_tags = merge(var.default_tags, {
    Module = "cloudtrail"
  })
  
  # Use either created bucket or existing bucket
  s3_bucket_name = var.enable_s3_bucket ? module.s3_bucket[0].bucket_name : var.existing_s3_bucket_name
}
