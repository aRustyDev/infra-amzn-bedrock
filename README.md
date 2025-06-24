# infra-amzn-bedrock

This Terraform project creates a secure, production-ready infrastructure for accessing Claude Sonnet 4 through Amazon Bedrock with IP restrictions and IAM best practices. The project is organized using a modular architecture for flexible deployment options.

## 🏗️ Project Structure

```
claude-sonnet-4-bedrock/
├── providers.tf                 # Provider configuration
├── main.tf                      # Root module orchestration
├── variables.tf                 # Root variables with module toggles
├── outputs.tf                   # Root outputs
├── terraform.tfvars.example     # Example configuration
├── README.md                    # This file
└── modules/
    ├── core/                    # Core infrastructure (VPC, IAM, Bedrock)
    │   ├── main.tf
    │   ├── variables.tf
    │   ├── outputs.tf
    │   └── locals.tf
    ├── s3/                      # S3 buckets for Config and CloudTrail
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── config/                  # AWS Config compliance monitoring
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── cloudtrail/              # CloudTrail audit logging
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── guardduty/               # GuardDuty threat detection
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    └── monitoring/              # CloudWatch monitoring and alerting
        ├── main.tf
        ├── variables.tf
        ├── outputs.tf
        └── locals.tf
```

## 🔧 Modular Architecture Benefits

### **Selective Deployment**
Enable/disable features based on your needs:

```hcl
# For development - minimal setup
enable_s3_buckets = false   # Disable S3 buckets
enable_config     = false   # Disable AWS Config
enable_cloudtrail = false   # Disable CloudTrail
enable_guardduty  = false   # Disable GuardDuty
enable_monitoring = false   # Disable monitoring

# For production - full security stack
enable_s3_buckets = true    # Enable all features
enable_config     = true
enable_cloudtrail = true
enable_guardduty  = true
enable_monitoring = true
```

### **Module Dependencies**
- **Core**: Always deployed (VPC, IAM, Bedrock access)
- **S3**: Required for Config and CloudTrail
- **Config**: Requires S3 module
- **CloudTrail**: Requires S3 module
- **GuardDuty**: Standalone
- **Monitoring**: Standalone but uses core resources

## 🚀 Quick Start

### **Development Setup (Minimal)**
```hcl
# terraform.tfvars
enable_s3_buckets = false
enable_config     = false
enable_cloudtrail = false
enable_guardduty  = false
enable_monitoring = false
```

### **Production Setup (Full Security)**
```hcl
# terraform.tfvars
enable_s3_buckets = true
enable_config     = true
enable_cloudtrail = true
enable_guardduty  = true
enable_monitoring = true
```

### **Staged Deployment**
```bash
# Stage 1: Core only
terraform apply -target=module.core

# Stage 2: Add S3 buckets
terraform apply -target=module.s3

# Stage 3: Add Config
terraform apply -target=module.config

# Stage 4: Full deployment
terraform apply
```

## 📋 Module Details

### **Core Module** (Always Required)
- VPC with private subnets
- VPC endpoints for Bedrock
- IAM roles and policies
- Security groups
- CloudWatch log groups
- VPC Flow Logs

**Key Resources:**
- `aws_vpc.bedrock_vpc`
- `aws_vpc_endpoint.bedrock_runtime`
- `aws_iam_role.bedrock_user_role`
- `aws_iam_role.bedrock_application_role`

### **S3 Module** (Conditional)
- Encrypted S3 buckets for Config and CloudTrail
- Bucket policies for service access
- Public access blocks

**Key Resources:**
- `aws_s3_bucket.config_bucket`
- `aws_s3_bucket.cloudtrail_bucket`

### **Config Module** (Conditional)
- AWS Config recorder and delivery channel
- Config rules for compliance
- IAM role for Config service

**Key Resources:**
- `aws_config_configuration_recorder.bedrock_config`
- `aws_config_config_rule.iam_password_policy`

### **CloudTrail Module** (Conditional)
- Multi-region CloudTrail
- Bedrock-specific data events
- API call rate insights

**Key Resources:**
- `aws_cloudtrail.bedrock_trail`

### **GuardDuty Module** (Conditional)
- Threat detection and monitoring
- S3 protection
- Malware protection

**Key Resources:**
- `aws_guardduty_detector.bedrock_guardduty`

### **Monitoring Module** (Conditional)
- CloudWatch dashboard
- Usage and error alarms
- SNS notifications
- Cost budgets

**Key Resources:**
- `aws_cloudwatch_dashboard.bedrock_dashboard`
- `aws_cloudwatch_metric_alarm.high_bedrock_usage`
- `aws_budgets_budget.bedrock_budget`

## 🔒 Security Features

All modules implement security best practices:
- **Least privilege IAM policies**
- **Encrypted storage** (S3, CloudWatch)
- **IP-based access controls**
- **VPC isolation** with private subnets
- **Audit trails** and compliance monitoring

## 🛠️ Usage Examples

### **Development Workflow**
```bash
# Start with core only
terraform apply -var="enable_monitoring=false" -var="enable_config=false"

# Test Bedrock access
aws bedrock invoke-model --model-id anthropic.claude-sonnet-4-20250514-v1:0 ...

# Add monitoring when needed
terraform apply -var="enable_monitoring=true"
```

### **Production Deployment**
```bash
# Full deployment with all security features
terraform apply

# Verify all modules
terraform output | grep -E "(config|cloudtrail|guardduty|monitoring)"
```

### **Cost Optimization**
```bash
# Disable expensive features for testing
terraform apply \
  -var="enable_guardduty=false" \
  -var="enable_cloudtrail=false" \
  -var="log_retention_days=1"
```

## 💰 Cost Optimization

### **Module Cost Impact**
- **Core**: ~$15/month (VPC endpoints, logs)
- **S3**: ~$1/month (storage)
- **Config**: ~$2/month (evaluations)
- **CloudTrail**: ~$2/month (events)
- **GuardDuty**: ~$3/month (findings)
- **Monitoring**: ~$1/month (dashboards)

### **Development Cost Savings**
Disable modules you don't need:
```hcl
# Minimal development setup (~$15/month)
enable_s3_buckets = false
enable_config     = false
enable_cloudtrail = false
enable_guardduty  = false
enable_monitoring = false
```

## 🔧 Customization

### **Adding New Modules**
1. Create module directory: `modules/new-module/`
2. Add module call in root `main.tf`
3. Add enable toggle in `variables.tf`
4. Add outputs to root `outputs.tf`

### **Module Dependencies**
Use `depends_on` for module dependencies:
```hcl
module "config" {
  count  = var.enable_config ? 1 : 0
  source = "./modules/config"
  
  config_bucket_id = var.enable_s3_buckets ? module.s3[0].config_bucket_id : null
  
  depends_on = [module.s3]
}
```

## 🛡️ Security Best Practices

### **Module Isolation**
- Each module has its own IAM roles
- Resource-level permissions
- Module-specific tagging

### **Progressive Security**
- Start with core security (VPC, IAM)
- Add compliance (Config, CloudTrail)
- Add monitoring (CloudWatch, GuardDuty)

## 📞 Support

For module-specific issues:
- **Core Module**: VPC, IAM, Bedrock connectivity
- **S3 Module**: Bucket permissions, encryption
- **Config Module**: Compliance rules, service roles
- **CloudTrail Module**: Audit logging, event selectors
- **GuardDuty Module**: Threat detection settings
- **Monitoring Module**: Alarms, dashboards, budgets

## 🤝 Contributing

When adding new modules:
1. Follow the established structure
2. Include proper variable validation
3. Add comprehensive outputs
4. Update the root module integration
5. Test both enabled/disabled states

---

**🎯 Key Benefit**: This modular approach allows you to deploy just what you need for development while providing a clear path to full production security when ready.
