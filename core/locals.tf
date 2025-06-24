# modules/core/locals.tf
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  # VPC configuration
  azs = slice(data.aws_availability_zones.available.names, 0, 2)
  
  private_subnet_cidrs = [
    cidrsubnet(var.vpc_cidr, 8, 1),
    cidrsubnet(var.vpc_cidr, 8, 2)
  ]
  
  # Model configuration
  claude_sonnet_4_model_id = "anthropic.claude-sonnet-4-20250514-v1:0"
  regional_claude_sonnet_4_model_id = "us.anthropic.claude-sonnet-4-20250514-v1:0"
  
  # Common tags
  common_tags = merge(var.default_tags, {
    Module      = "core"
    Environment = var.environment
  })
}
