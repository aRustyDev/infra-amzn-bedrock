# modules/cloudtrail/variables.tf
variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "default_tags" {
  description = "Default tags"
  type        = map(string)
}

variable "account_id" {
  description = "AWS account ID"
  type        = string
}

variable "region" {
  description = "AWS region"
  type        = string
}

variable "random_suffix" {
  description = "Random suffix for unique resource names"
  type        = string
}

variable "enable_s3_bucket" {
  description = "Enable S3 bucket creation for CloudTrail"
  type        = bool
  default     = true
}

variable "existing_s3_bucket_name" {
  description = "Name of existing S3 bucket to use (if enable_s3_bucket is false)"
  type        = string
  default     = null
}

variable "enable_insight_selectors" {
  description = "Enable CloudTrail Insights"
  type        = bool
  default     = true
}
