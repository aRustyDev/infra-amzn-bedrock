# main.tf
# VPC and networking
resource "aws_vpc" "bedrock_vpc" {
  cidr_block           = local.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-vpc"
  })
}

resource "aws_subnet" "private" {
  count = length(local.private_subnet_cidrs)
  
  vpc_id            = aws_vpc.bedrock_vpc.id
  cidr_block        = local.private_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-private-subnet-${count.index + 1}"
    Type = "Private"
  })
}

# Route table for private subnets
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.bedrock_vpc.id
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-private-rt"
  })
}

resource "aws_route_table_association" "private" {
  count = length(aws_subnet.private)
  
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Security group for VPC endpoints
resource "aws_security_group" "bedrock_vpc_endpoint" {
  name_prefix = "${var.project_name}-bedrock-vpce-sg"
  description = "Security group for Bedrock VPC endpoints"
  vpc_id      = aws_vpc.bedrock_vpc.id
  
  # Allow HTTPS inbound from specified IP ranges
  dynamic "ingress" {
    for_each = var.allowed_ip_ranges
    content {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
      description = "HTTPS from ${ingress.value}"
    }
  }
  
  # Allow inbound from VPC CIDR
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.bedrock_vpc.cidr_block]
    description = "HTTPS from VPC"
  }
  
  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-bedrock-vpce-sg"
  })
}

# Security group for compute resources
resource "aws_security_group" "bedrock_compute" {
  name_prefix = "${var.project_name}-bedrock-compute-sg"
  description = "Security group for compute resources accessing Bedrock"
  vpc_id      = aws_vpc.bedrock_vpc.id
  
  # Allow outbound HTTPS to VPC endpoint security group
  egress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.bedrock_vpc_endpoint.id]
    description     = "HTTPS to Bedrock VPC endpoint"
  }
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-bedrock-compute-sg"
  })
}

# VPC Endpoints for Bedrock
resource "aws_vpc_endpoint" "bedrock_runtime" {
  vpc_id              = aws_vpc.bedrock_vpc.id
  service_name        = "com.amazonaws.${local.region}.bedrock-runtime"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.bedrock_vpc_endpoint.id]
  private_dns_enabled = true
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ]
        Resource = [
          "arn:aws:bedrock:${local.region}::foundation-model/${local.claude_sonnet_4_model_id}",
          "arn:aws:bedrock:${local.region}::foundation-model/${local.regional_claude_sonnet_4_model_id}"
        ]
        Condition = {
          StringEquals = {
            "aws:PrincipalArn" = [
              aws_iam_role.bedrock_user_role.arn,
              aws_iam_role.bedrock_application_role.arn
            ]
          }
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges
          }
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-bedrock-runtime-vpce"
  })
}

resource "aws_vpc_endpoint" "bedrock_control" {
  vpc_id              = aws_vpc.bedrock_vpc.id
  service_name        = "com.amazonaws.${local.region}.bedrock"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.bedrock_vpc_endpoint.id]
  private_dns_enabled = true
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"
        Action = [
          "bedrock:GetFoundationModel",
          "bedrock:ListFoundationModels",
          "bedrock:GetModelInvocationLoggingConfiguration"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:PrincipalArn" = [
              aws_iam_role.bedrock_admin_role.arn
            ]
          }
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges
          }
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-bedrock-control-vpce"
  })
}

# IAM Roles and Policies
# Admin role for Bedrock management
resource "aws_iam_role" "bedrock_admin_role" {
  name = "${var.project_name}-bedrock-admin-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = var.admin_user_arns
        }
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = local.region
          }
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges
          }
          Bool = {
            "aws:SecureTransport" = "true"
          }
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-bedrock-admin-role"
    Role = "Admin"
  })
}

resource "aws_iam_policy" "bedrock_admin_policy" {
  name        = "${var.project_name}-bedrock-admin-policy"
  description = "Administrative policy for Bedrock management"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "BedrockModelAccess"
        Effect = "Allow"
        Action = [
          "bedrock:GetFoundationModel",
          "bedrock:ListFoundationModels",
          "bedrock:GetModelInvocationLoggingConfiguration",
          "bedrock:PutModelInvocationLoggingConfiguration",
          "bedrock:DeleteModelInvocationLoggingConfiguration"
        ]
        Resource = "*"
        Condition = {
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges
          }
        }
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = [
          "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/bedrock/*"
        ]
      },
      {
        Sid    = "IAMPassRole"
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = [
          aws_iam_role.bedrock_user_role.arn,
          aws_iam_role.bedrock_application_role.arn
        ]
      }
    ]
  })
  
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "bedrock_admin_policy_attachment" {
  role       = aws_iam_role.bedrock_admin_role.name
  policy_arn = aws_iam_policy.bedrock_admin_policy.arn
}

# User role for Bedrock usage
resource "aws_iam_role" "bedrock_user_role" {
  name = "${var.project_name}-bedrock-user-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = var.user_arns
        }
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = local.region
          }
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges
          }
          Bool = {
            "aws:SecureTransport" = "true"
          }
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-bedrock-user-role"
    Role = "User"
  })
}

resource "aws_iam_policy" "bedrock_user_policy" {
  name        = "${var.project_name}-bedrock-user-policy"
  description = "User policy for Bedrock Claude Sonnet 4 access"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ClaudeSonnet4Access"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ]
        Resource = [
          "arn:aws:bedrock:${local.region}::foundation-model/${local.claude_sonnet_4_model_id}",
          "arn:aws:bedrock:${local.region}::foundation-model/${local.regional_claude_sonnet_4_model_id}"
        ]
        Condition = {
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges
          }
          StringEquals = {
            "bedrock:inputModality" = ["TEXT"]
            "bedrock:outputModality" = ["TEXT"]
          }
          NumericLessThan = {
            "bedrock:maxTokens" = var.max_tokens_limit
          }
        }
      },
      {
        Sid    = "GetModelInfo"
        Effect = "Allow"
        Action = [
          "bedrock:GetFoundationModel"
        ]
        Resource = [
          "arn:aws:bedrock:${local.region}::foundation-model/${local.claude_sonnet_4_model_id}"
        ]
      }
    ]
  })
  
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "bedrock_user_policy_attachment" {
  role       = aws_iam_role.bedrock_user_role.name
  policy_arn = aws_iam_policy.bedrock_user_policy.arn
}

# Application role for programmatic access
resource "aws_iam_role" "bedrock_application_role" {
  name = "${var.project_name}-bedrock-application-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = local.region
          }
          Bool = {
            "aws:SecureTransport" = "true"
          }
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = var.application_assume_role_arns
        }
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = local.region
            "sts:ExternalId" = var.external_id != "" ? var.external_id : null
          }
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges
          }
          Bool = {
            "aws:SecureTransport" = "true"
          }
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-bedrock-application-role"
    Role = "Application"
  })
}

resource "aws_iam_policy" "bedrock_application_policy" {
  name        = "${var.project_name}-bedrock-application-policy"
  description = "Application policy for Bedrock Claude Sonnet 4 access with enhanced security"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ClaudeSonnet4ApplicationAccess"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ]
        Resource = [
          "arn:aws:bedrock:${local.region}::foundation-model/${local.claude_sonnet_4_model_id}",
          "arn:aws:bedrock:${local.region}::foundation-model/${local.regional_claude_sonnet_4_model_id}"
        ]
        Condition = {
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges
          }
          StringEquals = {
            "bedrock:inputModality" = ["TEXT"]
            "bedrock:outputModality" = ["TEXT"]
          }
          NumericLessThan = {
            "bedrock:maxTokens" = var.max_tokens_limit
          }
          DateGreaterThan = {
            "aws:CurrentTime" = "2025-01-01T00:00:00Z"
          }
        }
      },
      {
        Sid    = "CloudWatchMetrics"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "AWS/Bedrock"
          }
        }
      }
    ]
  })
  
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "bedrock_application_policy_attachment" {
  role       = aws_iam_role.bedrock_application_role.name
  policy_arn = aws_iam_policy.bedrock_application_policy.arn
}

# Instance profile for EC2 instances
resource "aws_iam_instance_profile" "bedrock_application_profile" {
  name = "${var.project_name}-bedrock-application-profile"
  role = aws_iam_role.bedrock_application_role.name
  
  tags = local.common_tags
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "bedrock_logs" {
  name              = "/aws/bedrock/${var.project_name}"
  retention_in_days = var.log_retention_days
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-bedrock-logs"
  })
}

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/flowlogs/${var.project_name}"
  retention_in_days = var.log_retention_days
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-vpc-flow-logs"
  })
}

# VPC Flow Logs
resource "aws_flow_log" "bedrock_vpc_flow_log" {
  iam_role_arn    = aws_iam_role.flow_log_role.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.bedrock_vpc.id
  
  tags = merge(local.common_tags, {
    Name = "${var.project_name}-vpc-flow-logs"
  })
}

# IAM role for VPC Flow Logs
resource "aws_iam_role" "flow_log_role" {
  name = "${var.project_name}-vpc-flow-log-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })
  
  tags = local.common_tags
}

resource "aws_iam_role_policy" "flow_log_policy" {
  name = "${var.project_name}-vpc-flow-log-policy"
  role = aws_iam_role.flow_log_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Effect   = "Allow"
        Resource = "${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*"
      }
    ]
  })
}
