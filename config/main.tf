# modules/config/main.tf
# S3 bucket for Config (conditional)
module "s3_bucket" {
  count  = var.enable_s3_bucket ? 1 : 0
  source = "../s3"
  
  project_name     = var.project_name
  bucket_purpose   = "config"
  random_suffix    = var.random_suffix
  default_tags     = var.default_tags
  account_id       = var.account_id
  region          = data.aws_region.current.name
  enable_versioning = true
  force_destroy    = true
}

# Data source for region
data "aws_region" "current" {}

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
  s3_bucket_name = local.s3_bucket_name
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
