# modules/guardduty/outputs.tf
output "detector_id" {
  description = "ID of the GuardDuty detector"
  value       = aws_guardduty_detector.bedrock_guardduty.id
}

output "detector_arn" {
  description = "ARN of the GuardDuty detector"
  value       = aws_guardduty_detector.bedrock_guardduty.arn
}
