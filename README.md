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
    ├── s3/                      # Generic, reusable S3 bucket module
    ├── config/                  # AWS Config (calls s3 module internally)
    ├── cloudtrail/              # CloudTrail (calls s3 module internally)
    ├── guardduty/               # GuardDuty threat detection
    └── monitoring/              # CloudWatch monitoring and alerting
```

## 🔧 Improved S3 Architecture

### **Generic S3 Module**
The `s3` module is now a reusable component that can create purpose-specific buckets:

```hcl
module "s3_bucket" {
  source = "../s3"
  
  project_name   = "my-project"
  bucket_purpose = "config"        # or "cloudtrail"
  random_suffix  = "abc123"
  account_id     = "123456789012"
  region        = "us-east-1"
}
```

### **Module-Specific S3 Control**
Each consumer module controls its own S3 bucket creation:

```hcl
# terraform.tfvars
enable_config               = true   # Enable Config module
enable_config_s3_bucket     = true   # Config creates its own S3 bucket

enable_cloudtrail           = true   # Enable CloudTrail module  
enable_cloudtrail_s3_bucket = false  # CloudTrail uses existing bucket
```

## 🚀 Flexible Deployment Options

### **Development Setup (No S3 Costs)**
```hcl
# terraform.tfvars
enable_config               = true
enable_config_s3_bucket     = false  # Use existing or no bucket

enable_cloudtrail           = true
enable_cloudtrail_s3_bucket = false  # Use existing or no bucket

enable_guardduty  = false  # Disable to save costs
enable_monitoring = false  # Disable to save costs
```

### **Production Setup (Full Security)**
```hcl
# terraform.tfvars
enable_config               = true
enable_config_s3_bucket     = true   # Create dedicated bucket

enable_cloudtrail           = true
enable_cloudtrail_s3_bucket = true   # Create dedicated bucket

enable_guardduty  = true   # Full threat detection
enable_monitoring = true   # Full monitoring stack
```

### **Hybrid Setup (Existing Buckets)**
```hcl
# terraform.tfvars
enable_config               = true
enable_config_s3_bucket     = false
# Config module can be configured to use existing bucket via:
# existing_s3_bucket_name = "my-existing-config-bucket"

enable_cloudtrail           = true  
enable_cloudtrail_s3_bucket = true   # Create new bucket for CloudTrail
```

## 📋 Module Details

### **Core Module** (Always Required)
- VPC with private subnets and endpoints
- IAM roles for admin, user, and application access
- Security groups and VPC Flow Logs
- CloudWatch log groups

### **S3 Module** (Generic, Reusable)
- Creates purpose-specific S3 buckets
- Handles bucket policies for different AWS services
- Supports Config, CloudTrail, and extensible for future services
- Configurable encryption, versioning, and access controls

**Usage by other modules:**
```hcl
module "s3_bucket" {
  source = "../s3"
  
  bucket_purpose = "config"  # Automatically configures policies for Config service
  # ... other variables
}
```

### **Config Module** (Conditional)
- AWS Config recorder and delivery channel
- Config rules for compliance
- **Optionally creates S3 bucket** via internal s3 module call
- Can use existing S3 bucket if `enable_s3_bucket = false`

### **CloudTrail Module** (Conditional)
- Multi-region CloudTrail with Bedrock-specific events
- **Optionally creates S3 bucket** via internal s3 module call
- Can use existing S3 bucket if `enable_s3_bucket = false`

### **GuardDuty Module** (Conditional)
- Threat detection and monitoring
- Configurable protection features

### **Monitoring Module** (Conditional)
- CloudWatch dashboards and alarms
- SNS notifications and cost budgets

## 🎯 Key Benefits

### **1. Granular Control**
```hcl
# Enable Config but use existing bucket
enable_config           = true
enable_config_s3_bucket = false

# Enable CloudTrail and create new bucket
enable_cloudtrail           = true
enable_cloudtrail_s3_bucket = true
```

### **2. Cost Optimization**
- **Development**: Disable S3 bucket creation to save ~$2-5/month per service
- **Staging**: Mix of new and existing buckets based on needs
- **Production**: Full bucket creation for isolation and compliance

### **3. Reusable S3 Module**
- Single S3 module handles all bucket types
- Purpose-specific policies (Config vs CloudTrail)
- Easy to extend for new services (future Lambda modules, etc.)

### **4. No Dependencies Between Modules**
- Config module doesn't depend on CloudTrail module
- Each module manages its own S3 bucket independently
- Simpler dependency graph and faster deployments

## 🛠️ Usage Examples

### **Progressive Deployment**
```bash
# Stage 1: Core infrastructure only
terraform apply -target=module.core

# Stage 2: Add Config without S3
terraform apply -var="enable_config=true" -var="enable_config_s3_bucket=false"

# Stage 3: Add Config S3 bucket
terraform apply -var="enable_config_s3_bucket=true"

# Stage 4: Add CloudTrail with its own bucket
terraform apply -var="enable_cloudtrail=true"
```

### **Mixed Environment**
```bash
# Config uses existing corporate bucket, CloudTrail creates new
terraform apply \
  -var="enable_config=true" \
  -var="enable_config_s3_bucket=false" \
  -var="enable_cloudtrail=true" \
  -var="enable_cloudtrail_s3_bucket=true"
```

### **Development Environment** 
```bash
# Minimal setup - no S3 costs
terraform apply \
  -var="enable_config_s3_bucket=false" \
  -var="enable_cloudtrail_s3_bucket=false" \
  -var="enable_guardduty=false" \
  -var="enable_monitoring=false"
```

## 🔒 Security Features

All modules maintain enterprise-grade security:
- **Least privilege IAM policies**
- **IP-based access restrictions**
- **Encrypted storage and transit**
- **VPC isolation with private subnets**
- **Comprehensive audit trails**

## 💰 Cost Impact

### **S3 Bucket Costs by Module**
- **Config S3**: ~$1-2/month (compliance data)
- **CloudTrail S3**: ~$1-3/month (audit logs)
- **No S3**: $0/month (use existing buckets)

### **Total Monthly Costs**
- **Core only**: ~$15/month
- **+ Config (no S3)**: ~$17/month  
- **+ Config (with S3)**: ~$19/month
- **+ CloudTrail (with S3)**: ~$22/month
- **+ Full stack**: ~$28/month

## 🎛️ Configuration Examples

### **terraform.tfvars for Development**
```hcl
# Enable services but minimize costs
enable_config               = true
enable_config_s3_bucket     = false  # Save $2/month

enable_cloudtrail           = true
enable_cloudtrail_s3_bucket = false  # Save $2/month

enable_guardduty  = false  # Save $3/month
enable_monitoring = false  # Save $1/month
```

### **terraform.tfvars for Production**
```hcl
# Full security and compliance
enable_config               = true
enable_config_s3_bucket     = true

enable_cloudtrail           = true
enable_cloudtrail_s3_bucket = true

enable_guardduty  = true
enable_monitoring = true
```

## 🚀 Future Extensibility

The S3 module can easily support new bucket purposes:

```hcl
# Future: Lambda function artifacts
module "lambda_s3" {
  source = "./modules/s3"
  
  bucket_purpose = "lambda"  # New purpose
  # ... rest of config
}
```

This architecture provides the perfect balance of **flexibility**, **cost control**, and **maintainability** while ensuring each module remains focused and independent.
