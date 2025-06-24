# infra-amzn-bedrock
Terraform Infrastructure description to deploy a model to amazon bedrock, for development puposes.

## 🔒 **Security Features**

**Network Security:**
- VPC endpoints with AWS PrivateLink for private connectivity to Bedrock without internet exposure
- IP-based access restrictions through security groups and endpoint policies
- Private subnets with no internet gateway requirements
- VPC Flow Logs for network traffic monitoring

**IAM Best Practices:**
- Three-tier role structure following least-privilege principles:
  - **Admin Role**: Model management and configuration
  - **User Role**: Limited Claude Sonnet 4 inference access
  - **Application Role**: Programmatic access for applications
- Conditional access policies with IP restrictions, encrypted transport requirements, and token limits
- External ID support for cross-account access

**Compliance & Monitoring:**
- AWS Config for compliance monitoring
- CloudTrail with Bedrock-specific event logging for audit trails
- GuardDuty integration for threat detection
- CloudWatch alarms for usage anomalies

## 🏗️ **Infrastructure Components**

The project creates:
- Dedicated VPC with private subnets across multiple AZs
- VPC endpoints for both Bedrock Runtime and Control Plane APIs
- Security groups with strict HTTPS-only access
- IAM roles with granular permissions for Claude Sonnet 4 (model ID: anthropic.claude-sonnet-4-20250514-v1:0)
- CloudWatch dashboards and cost budgets
- Encrypted S3 buckets for logs and configuration

## 📋 **Quick Start**

1. **Enable Model Access:**
```bash
aws bedrock put-foundation-model-availability \
  --region us-east-1 \
  --model-id anthropic.claude-sonnet-4-20250514-v1:0
```

2. **Configure Variables:**
Copy `terraform.tfvars.example` to `terraform.tfvars` and update with your IP ranges and IAM user ARNs.

3. **Deploy:**
```bash
terraform init
terraform plan
terraform apply
```

4. **Test Access:**
```bash
# Assume user role
aws sts assume-role --role-arn $(terraform output -raw bedrock_user_role_arn) --role-session-name test

# Invoke Claude Sonnet 4
aws bedrock invoke-model --model-id anthropic.claude-sonnet-4-20250514-v1:0 --body '{"anthropic_version":"bedrock-2023-05-31","max_tokens":100,"messages":[{"role":"user","content":"Hello!"}]}'
```

## 🛡️ **Security Highlights**

- **Zero Trust Network**: All access requires IP allowlisting and proper IAM roles
- **Defense in Depth**: Multiple security layers including network, IAM, and application-level controls
- **Audit Ready**: Complete audit trail with CloudTrail and CloudWatch logging
- **Cost Controls**: Budget alerts and usage monitoring to prevent unexpected charges
- **Compliance**: AWS Config rules for security compliance monitoring

The project implements AWS and Anthropic's recommended security best practices including proper IAM role configuration, encryption at rest and in transit, and network isolation through VPC endpoints.

This infrastructure provides enterprise-ready access to Claude Sonnet 4 while maintaining strict security controls and comprehensive monitoring capabilities.
