# modules/s3/variables.tf
variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "bucket_purpose" {
  description = "Purpose of the bucket (config, cloudtrail, etc.)"
  type        = string
  
  validation {
    condition     = contains(["config", "cloudtrail"], var.bucket_purpose)
    error_message = "Bucket purpose must be either 'config' or 'cloudtrail'."
  }
}

variable "random_suffix" {
  description = "Random suffix for unique bucket names"
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

variable "enable_versioning" {
  description = "Enable S3 bucket versioning"
  type        = bool
  default     = true
}

variable "force_destroy" {
  description = "Allow force destroy of bucket"
  type        = bool
  default     = true
}
