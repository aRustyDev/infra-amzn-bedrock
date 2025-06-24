# modules/cloudtrail/main.tf
# S3 bucket for CloudTrail (conditional)
module "s3_bucket" {
  count  = var.enable_s3_bucket ? 1 : 0
  source = "../s3"
  
  project_name     = var.project_name
  bucket_purpose   = "cloudtrail"
  random_suffix    = var.random_suffix
  default_tags     = var.default_tags
  account_id       = var.account_id
  region          = var.region
  enable_versioning = true
  force_destroy    = true
}

# CloudTrail for API auditing
resource "aws_cloudtrail" "bedrock_trail" {
  name                          = "${var.project_name}-cloudtrail"
  s3_bucket_name               = local.s3_bucket_name
  include_global_service_events = true
  is_multi_region_trail        = true
  enable_logging               = true

  event_selector {
    read_write_type                 = "All"
    include_management_events       = true
    exclude_management_event_sources = []

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:bedrock:*"]
    }
  }

  dynamic "insight_selector" {
    for_each = var.enable_insight_selectors ? [1] : []
    content {
      insight_type = "ApiCallRateInsight"
    }
  }

  tags = local.common_tags
}
