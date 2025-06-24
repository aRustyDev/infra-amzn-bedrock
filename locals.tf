# locals.tf
locals {
  # Data sources
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  
  # VPC configuration
  vpc_cidr = var.vpc_cidr
  azs      = slice(data.aws_availability_zones.available.names, 0, 2)
  
  private_subnet_cidrs = [
    cidrsubnet(local.vpc_cidr, 8, 1),
    cidrsubnet(local.vpc_cidr, 8, 2)
  ]
  
  # Model configuration
  claude_sonnet_4_model_id = "anthropic.claude-sonnet-4-20250514-v1:0"
  regional_claude_sonnet_4_model_id = "us.anthropic.claude-sonnet-4-20250514-v1:0"
  
  # Common tags
  common_tags = merge(var.default_tags, {
    Project     = "Claude-Sonnet-4-Bedrock"
    Terraform   = "true"
    Environment = var.environment
  })
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}
