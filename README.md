# infra-amzn-bedrock
This Terraform project creates a secure, production-ready infrastructure for accessing Claude Sonnet 4 through Amazon Bedrock with IP restrictions and IAM best practices.

## 🏗️ Architecture Overview

```
Internet --> [IP Allowlist] --> VPC --> [VPC Endpoints] --> Amazon Bedrock
                                 |
                                 ├── Private Subnets (Multi-AZ)
                                 ├── Security Groups
                                 ├── IAM Roles & Policies
                                 └── Monitoring & Logging
```

## 🔒 Security Features

### Network Security
- **VPC Isolation**: Dedicated VPC with private subnets across multiple AZs
- **VPC Endpoints**: AWS PrivateLink connectivity to Bedrock (no internet required)
- **IP Restrictions**: Configurable IP-based access controls
- **Security Groups**: Strict HTTPS-only (port 443) access controls

### IAM Security
- **Three-Tier Role Structure**:
  - **Admin Role**: Full Bedrock management capabilities
  - **User Role**: Limited Claude Sonnet 4 inference access
  - **Application Role**: Programmatic access for applications
- **Conditional Access**: IP restrictions, encrypted transport requirements
- **Token Limits**: Configurable maximum tokens per request
- **External ID**: Support for cross-account access security

### Compliance & Monitoring
- **AWS Config**: Compliance rule monitoring
- **CloudTrail**: Complete API audit trail with Bedrock-specific logging
- **GuardDuty**: Threat detection and security monitoring
- **VPC Flow Logs**: Network traffic analysis
- **CloudWatch**: Real-time metrics and alerting

## 📁 File Structure

```
claude-sonnet-4-bedrock/
├── providers.tf              # Provider configuration
├── variables.tf              # Input variables
├── locals.tf                 # Local values and data sources
├── main.tf                   # Core infrastructure (VPC, IAM, VPC endpoints)
├── security.tf               # Security services (Config, CloudTrail, GuardDuty)
├── monitoring.tf             # Monitoring and alerting
├── outputs.tf                # Output values
├── terraform.tfvars.example  # Example variable values
└── README.md                 # This file
```

## 🚀 Quick Start

### Prerequisites

1. **AWS CLI** configured with appropriate permissions
2. **Terraform** >= 1.0 installed
3. **Bedrock Model Access** enabled for Claude Sonnet 4

### Step 1: Enable Bedrock Model Access

```bash
# Enable Claude Sonnet 4 model access
aws bedrock put-foundation-model-availability \
  --region us-east-1 \
  --model-id anthropic.claude-sonnet-4-20250514-v1:0

# Verify model is available
aws bedrock list-foundation-models \
  --by-provider anthropic \
  --region us-east-1
```

### Step 2: Configure Variables

```bash
# Copy example configuration
cp terraform.tfvars.example terraform.tfvars

# Edit with your specific values
vim terraform.tfvars
```

**Key Variables to Update:**
- `allowed_ip_ranges`: Your office/home IP ranges
- `admin_user_arns`: IAM users for admin access
- `user_arns`: IAM users for inference access
- `alert_email_addresses`: Email addresses for alerts

### Step 3: Deploy Infrastructure

```bash
# Initialize Terraform
terraform init

# Validate configuration
terraform validate

# Plan deployment
terraform plan

# Apply changes
terraform apply
```

### Step 4: Test Deployment

```bash
# Get user role ARN
USER_ROLE_ARN=$(terraform output -raw bedrock_user_role_arn)

# Assume role
aws sts assume-role \
  --role-arn $USER_ROLE_ARN \
  --role-session-name test-session

# Test Claude Sonnet 4 access
aws bedrock invoke-model \
  --model-id anthropic.claude-sonnet-4-20250514-v1:0 \
  --body '{"anthropic_version":"bedrock-2023-05-31","max_tokens":100,"messages":[{"role":"user","content":"Hello Claude!"}]}' \
  --output text \
  --query 'body' | base64 -d
```

## 💡 Usage Examples

### Python SDK Example

```python
import boto3
import json

# Assume the user role first
sts = boto3.client('sts')
role_arn = "arn:aws:iam::123456789012:role/claude-sonnet-4-bedrock-user-role"

assumed_role = sts.assume_role(
    RoleArn=role_arn,
    RoleSessionName='claude-session'
)

credentials = assumed_role['Credentials']

# Create Bedrock client with assumed role
bedrock = boto3.client(
    'bedrock-runtime',
    aws_access_key_id=credentials['AccessKeyId'],
    aws_secret_access_key=credentials['SecretAccessKey'],
    aws_session_token=credentials['SessionToken'],
    region_name='us-east-1'
)

# Invoke Claude Sonnet 4
response = bedrock.invoke_model(
    modelId='anthropic.claude-sonnet-4-20250514-v1:0',
    body=json.dumps({
        'anthropic_version': 'bedrock-2023-05-31',
        'max_tokens': 1000,
        'messages': [
            {
                'role': 'user',
                'content': 'Explain quantum computing in simple terms.'
            }
        ]
    })
)

result = json.loads(response['body'].read())
print(result['content'][0]['text'])
```

### AWS CLI Example

```bash
# Using temporary credentials from assumed role
aws bedrock invoke-model \
  --model-id anthropic.claude-sonnet-4-20250514-v1:0 \
  --body '{
    "anthropic_version": "bedrock-2023-05-31",
    "max_tokens": 1000,
    "messages": [
      {
        "role": "user",
        "content": "Write a Python function to calculate fibonacci numbers."
      }
    ]
  }' \
  output.json

# Display the response
cat output.json | jq -r '.body' | base64 -d | jq '.content[0].text'
```

## 📊 Monitoring

### CloudWatch Dashboard
Access your monitoring dashboard:
```bash
echo $(terraform output -raw cloudwatch_dashboard_url)
```

### Key Metrics Monitored
- **API Invocations**: Total requests to Claude Sonnet 4
- **Latency**: Response times for API calls
- **Error Rates**: Client and server errors
- **Token Usage**: Input/output token consumption
- **Cost**: Real-time cost tracking

### Alerts Configured
- High API usage (configurable threshold)
- Failed API calls (>10 errors)
- Budget alerts (80% and 100% of monthly budget)

## 🔧 Customization

### Adjusting Security Settings

```hcl
# In terraform.tfvars
allowed_ip_ranges = [
  "203.0.113.0/24",  # Office network
  "198.51.100.0/24"  # Home network
]

max_tokens_limit = 8192  # Increase token limit
```

### Adding More Users

```hcl
# In terraform.tfvars
user_arns = [
  "arn:aws:iam::123456789012:user/developer1",
  "arn:aws:iam::123456789012:user/developer2",
  "arn:aws:iam::123456789012:user/data-scientist1"
]
```

### Cross-Account Access

```hcl
# In terraform.tfvars
application_assume_role_arns = [
  "arn:aws:iam::OTHER-ACCOUNT:root"
]
external_id = "SecureExternalId123"
```

## 🛠️ Troubleshooting

### Common Issues

1. **Access Denied Errors**
   ```bash
   # Check your IP address
   curl ifconfig.me
   
   # Verify it's in allowed ranges
   terraform output allowed_ip_ranges
   ```

2. **Model Not Available**
   ```bash
   # Check model access
   aws bedrock list-foundation-models --by-provider anthropic
   
   # Request access if needed
   aws bedrock put-foundation-model-availability \
     --model-id anthropic.claude-sonnet-4-20250514-v1:0
   ```

3. **VPC Endpoint Issues**
   ```bash
   # Check endpoint status
   aws ec2 describe-vpc-endpoints \
     --vpc-endpoint-ids $(terraform output -raw bedrock_runtime_vpc_endpoint_id)
   ```

### Debugging Commands

```bash
# Check current AWS identity
aws sts get-caller-identity

# Verify role trust policy
aws iam get-role --role-name claude-sonnet-4-bedrock-user-role

# Test role assumption
aws sts assume-role \
  --role-arn $(terraform output -raw bedrock_user_role_arn) \
  --role-session-name debug-session
```

## 💰 Cost Optimization

### Expected Costs
- **VPC Endpoints**: ~$7.20/month per endpoint (2 endpoints)
- **CloudWatch Logs**: Based on log volume
- **Bedrock Usage**: Pay-per-token (input/output)
- **Other AWS Services**: Minimal costs for Config, CloudTrail, etc.

### Cost Control Features
- **Budget Alerts**: Automatic notifications at 80% and 100% thresholds
- **Token Limits**: Configurable per-request token limits
- **Usage Monitoring**: Real-time tracking of API calls

## 🧹 Cleanup

To destroy all resources:

```bash
terraform destroy
```

**⚠️ Warning**: This will permanently delete all created resources including logs and configurations.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Follow Terraform best practices
2. Update documentation for any changes
3. Test in development environment first
4. Ensure security controls remain in place

## 📞 Support

For issues related to:
- **Terraform**: Check [Terraform documentation](https://terraform.io/docs)
- **AWS Bedrock**: Consult [AWS Bedrock documentation](https://docs.aws.amazon.com/bedrock/)
- **Claude Sonnet 4**: Refer to [Anthropic documentation](https://docs.anthropic.com/)

---

**🔐 S
