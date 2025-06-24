# modules/guardduty/variables.tf
variable "default_tags" {
  description = "Default tags"
  type        = map(string)
}

variable "enable_s3_protection" {
  description = "Enable S3 protection in GuardDuty"
  type        = bool
  default     = true
}

variable "enable_kubernetes_protection" {
  description = "Enable Kubernetes protection in GuardDuty"
  type        = bool
  default     = false
}

variable "enable_malware_protection" {
  description = "Enable malware protection in GuardDuty"
  type        = bool
  default     = true
}
