# security.tf
# Additional security configurations

# Random string for unique bucket names
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# AWS Config Rules for compliance monitoring
resource "aws_config_configuration_recorder" "bedrock_config" {
  name     = "${var.project_name}-config-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported = true
    include_global_resource_types = true
  }

  depends_on = [aws_config_delivery_channel.bedrock_config]
}

resource "aws_config_delivery_channel" "bedrock_config" {
  name           = "${var.project_name}-config-delivery"
  s3_bucket_name = aws_s3_bucket.config_bucket.id
}

# S3 bucket for AWS Config
resource "aws_s3_bucket" "config_bucket" {
  bucket        = "${var.project_name}-config-${random_string.suffix.result}"
  force_destroy = true

  tags = local.common_tags
}

resource "aws_s3_bucket_versioning" "config_bucket_versioning" {
  bucket = aws_s3_bucket.config_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "config_bucket_encryption" {
  bucket = aws_s3_bucket.config_bucket.id

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "config_bucket_pab" {
  bucket = aws_s3_bucket.config_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "config_bucket_policy" {
  bucket = aws_s3_bucket.config_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.config_bucket.arn
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = local.account_id
          }
        }
      },
      {
        Sid    = "AWSConfigBucketExistenceCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.config_bucket.arn
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = local.account_id
          }
        }
      },
      {
        Sid    = "AWSConfigBucketDelivery"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.config_bucket.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
            "AWS:SourceAccount" = local.account_id
          }
        }
      }
    ]
  })
}

# IAM role for AWS Config
resource "aws_iam_role" "config_role" {
  name = "${var.project_name}-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "config_role_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

# Config rules for security compliance
resource "aws_config_config_rule" "iam_password_policy" {
  name = "${var.project_name}-iam-password-policy"

  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }

  depends_on = [aws_config_configuration_recorder.bedrock_config]

  tags = local.common_tags
}

resource "aws_config_config_rule" "encrypted_volumes" {
  name = "${var.project_name}-encrypted-volumes"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  depends_on = [aws_config_configuration_recorder.bedrock_config]

  tags = local.common_tags
}

# CloudTrail for API auditing
resource "aws_cloudtrail" "bedrock_trail" {
  name                          = "${var.project_name}-cloudtrail"
  s3_bucket_name               = aws_s3_bucket.cloudtrail_bucket.id
  include_global_service_events = true
  is_multi_region_trail        = true
  enable_logging               = true

  event_selector {
    read_write_type                 = "All"
    include_management_events       = true
    exclude_management_event_sources = []

    data_resource {
      type   = "AWS::Bedrock::*"
      values = ["arn:aws:bedrock:*"]
    }
  }

  insight_selector {
    insight_type = "ApiCallRateInsight"
  }

  tags = local.common_tags
}

# S3 bucket for CloudTrail
resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket        = "${var.project_name}-cloudtrail-${random_string.suffix.result}"
  force_destroy = true

  tags = local.common_tags
}

resource "aws_s3_bucket_versioning" "cloudtrail_bucket_versioning" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "cloudtrail_bucket_encryption" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_bucket_pab" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_bucket.arn
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${var.project_name}-cloudtrail"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_bucket.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
            "AWS:SourceArn" = "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${var.project_name}-cloudtrail"
          }
        }
      }
    ]
  })
}

# SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-security-alerts"

  tags = local.common_tags
}

resource "aws_sns_topic_subscription" "email_alerts" {
  count     = length(var.alert_email_addresses)
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email_addresses[count.index]
}

# GuardDuty for threat detection
resource "aws_guardduty_detector" "bedrock_guardduty" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = false
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = local.common_tags
}
