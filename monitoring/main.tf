# modules/monitoring/main.tf
# SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  count = var.enable_sns_notifications ? 1 : 0
  name  = "${var.project_name}-security-alerts"

  tags = local.common_tags
}

resource "aws_sns_topic_subscription" "email_alerts" {
  count     = var.enable_sns_notifications ? length(var.alert_email_addresses) : 0
  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = var.alert_email_addresses[count.index]
}

# CloudWatch alarms for security monitoring
resource "aws_cloudwatch_metric_alarm" "high_bedrock_usage" {
  alarm_name          = "${var.project_name}-high-bedrock-usage"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Invocations"
  namespace           = "AWS/Bedrock"
  period              = "300"
  statistic           = "Sum"
  threshold           = var.usage_alarm_threshold
  alarm_description   = "This metric monitors high Bedrock API usage"
  alarm_actions       = var.enable_sns_notifications ? [aws_sns_topic.alerts[0].arn] : []

  dimensions = {
    ModelId = var.claude_sonnet_4_model_id
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "failed_bedrock_calls" {
  alarm_name          = "${var.project_name}-failed-bedrock-calls"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "InvocationClientErrors"
  namespace           = "AWS/Bedrock"
  period              = "300"
  statistic           = "Sum"
  threshold           = var.failed_calls_threshold
  alarm_description   = "This metric monitors failed Bedrock API calls"
  alarm_actions       = var.enable_sns_notifications ? [aws_sns_topic.alerts[0].arn] : []

  dimensions = {
    ModelId = var.claude_sonnet_4_model_id
  }

  tags = local.common_tags
}

# CloudWatch Dashboard
resource "aws_cloudwatch_dashboard" "bedrock_dashboard" {
  dashboard_name = "${var.project_name}-bedrock-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/Bedrock", "Invocations", "ModelId", var.claude_sonnet_4_model_id],
            [".", "InvocationLatency", ".", "."],
            [".", "InvocationClientErrors", ".", "."],
            [".", "InvocationServerErrors", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.region
          title   = "Bedrock Model Metrics"
          period  = 300
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 6
        width  = 24
        height = 6

        properties = {
          query   = "SOURCE '${var.bedrock_logs_group_name}' | fields @timestamp, @message | sort @timestamp desc | limit 100"
          region  = var.region
          title   = "Recent Bedrock API Calls"
        }
      }
    ]
  })
}

# Cost monitoring
resource "aws_budgets_budget" "bedrock_budget" {
  count        = var.enable_budget_alerts ? 1 : 0
  name         = "${var.project_name}-bedrock-budget"
  budget_type  = "COST"
  limit_amount = var.monthly_budget_limit
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  time_period_start = "2025-01-01_00:00"

  cost_filters = {
    Service = ["Amazon Bedrock"]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                 = 80
    threshold_type            = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = var.alert_email_addresses
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                 = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = var.alert_email_addresses
  }

  tags = local.common_tags
}
