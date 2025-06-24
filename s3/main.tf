# modules/s3/main.tf
# S3 bucket
resource "aws_s3_bucket" "bucket" {
  bucket        = "${var.project_name}-${var.bucket_purpose}-${var.random_suffix}"
  force_destroy = var.force_destroy

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-${var.bucket_purpose}-bucket"
  })
}

resource "aws_s3_bucket_versioning" "bucket_versioning" {
  count  = var.enable_versioning ? 1 : 0
  bucket = aws_s3_bucket.bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "bucket_encryption" {
  bucket = aws_s3_bucket.bucket.id

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "bucket_pab" {
  bucket = aws_s3_bucket.bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Bucket policy - Config specific
resource "aws_s3_bucket_policy" "config_bucket_policy" {
  count  = var.bucket_purpose == "config" ? 1 : 0
  bucket = aws_s3_bucket.bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"
        Principal = {
          Service = local.config.service_principal
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.bucket.arn
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = var.account_id
          }
        }
      },
      {
        Sid    = "AWSConfigBucketExistenceCheck"
        Effect = "Allow"
        Principal = {
          Service = local.config.service_principal
        }
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.bucket.arn
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = var.account_id
          }
        }
      },
      {
        Sid    = "AWSConfigBucketDelivery"
        Effect = "Allow"
        Principal = {
          Service = local.config.service_principal
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.bucket.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
            "AWS:SourceAccount" = var.account_id
          }
        }
      }
    ]
  })
}

# Bucket policy - CloudTrail specific
resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  count  = var.bucket_purpose == "cloudtrail" ? 1 : 0
  bucket = aws_s3_bucket.bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = local.config.service_principal
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.bucket.arn
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = local.config.trail_arn
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = local.config.service_principal
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.bucket.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
            "AWS:SourceArn" = local.config.trail_arn
          }
        }
      }
    ]
  })
}
