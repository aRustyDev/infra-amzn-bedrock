# modules/monitoring/outputs.tf
output "sns_topic_arn" {
  description = "ARN of the SNS topic for alerts"
  value       = var.enable_sns_notifications ? aws_sns_topic.alerts[0].arn : null
}

output "cloudwatch_dashboard_url" {
  description = "URL to the CloudWatch dashboard"
  value       = "https://${var.region}.console.aws.amazon.com/cloudwatch/home?region=${var.region}#dashboards:name=${aws_cloudwatch_dashboard.bedrock_dashboard.dashboard_name}"
}

output "budget_name" {
  description = "Name of the cost budget"
  value       = var.enable_budget_alerts ? aws_budgets_budget.bedrock_budget[0].name : null
}

output "high_usage_alarm_name" {
  description = "Name of the high usage alarm"
  value       = aws_cloudwatch_metric_alarm.high_bedrock_usage.alarm_name
}

output "failed_calls_alarm_name" {
  description = "Name of the failed calls alarm"
  value       = aws_cloudwatch_metric_alarm.failed_bedrock_calls.alarm_name
}

output "dashboard_name" {
  description = "Name of the CloudWatch dashboard"
  value       = aws_cloudwatch_dashboard.bedrock_dashboard.dashboard_name
}
