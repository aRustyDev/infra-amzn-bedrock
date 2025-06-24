# modules/guardduty/main.tf
locals {
  common_tags = merge(var.default_tags, {
    Module = "guardduty"
  })
}

# GuardDuty for threat detection
resource "aws_guardduty_detector" "bedrock_guardduty" {
  enable = true

  datasources {
    s3_logs {
      enable = var.enable_s3_protection
    }
    kubernetes {
      audit_logs {
        enable = var.enable_kubernetes_protection
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = var.enable_malware_protection
        }
      }
    }
  }

  tags = local.common_tags
}
