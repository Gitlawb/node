# Alerting (enabled when alert_email is set): SNS email + CloudWatch alarms
# on external API health (Route 53 health check), EC2 status, CPU, and RDS
# free storage. The email subscription must be confirmed once via the link
# SNS sends.

locals {
  alarms_enabled = var.alert_email != ""
}

resource "aws_sns_topic" "alerts" {
  count = local.alarms_enabled ? 1 : 0
  name  = "${var.name_prefix}-alerts"
  tags  = local.common_tags
}

resource "aws_sns_topic_subscription" "email" {
  count     = local.alarms_enabled ? 1 : 0
  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# External HTTPS /health probe — catches everything the EC2-level checks
# can't (container down, caddy broken, cert expired, DNS wrong).
resource "aws_route53_health_check" "api" {
  count             = local.alarms_enabled && var.domain_name != "" ? 1 : 0
  fqdn              = var.domain_name
  port              = 443
  type              = "HTTPS"
  resource_path     = "/health"
  request_interval  = 30
  failure_threshold = 3
  tags              = merge(local.common_tags, { Name = "${var.name_prefix}-api" })
}

# Route 53 health check metrics are only published in us-east-1; this module
# already runs there by default.
resource "aws_cloudwatch_metric_alarm" "api_health" {
  count               = local.alarms_enabled && var.domain_name != "" ? 1 : 0
  alarm_name          = "${var.name_prefix}-api-health"
  alarm_description   = "https://${var.domain_name}/health is failing"
  namespace           = "AWS/Route53"
  metric_name         = "HealthCheckStatus"
  dimensions          = { HealthCheckId = aws_route53_health_check.api[0].id }
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]
  ok_actions          = [aws_sns_topic.alerts[0].arn]
  tags                = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "status_check" {
  count               = local.alarms_enabled ? 1 : 0
  alarm_name          = "${var.name_prefix}-status-check"
  alarm_description   = "EC2 status checks failing on the node instance"
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed"
  dimensions          = { InstanceId = aws_instance.node.id }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]
  ok_actions          = [aws_sns_topic.alerts[0].arn]
  tags                = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  count               = local.alarms_enabled ? 1 : 0
  alarm_name          = "${var.name_prefix}-cpu-high"
  alarm_description   = "Node instance CPU above 80% for 15 minutes"
  namespace           = "AWS/EC2"
  metric_name         = "CPUUtilization"
  dimensions          = { InstanceId = aws_instance.node.id }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]
  ok_actions          = [aws_sns_topic.alerts[0].arn]
  tags                = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "rds_storage_low" {
  count               = local.alarms_enabled && var.use_rds ? 1 : 0
  alarm_name          = "${var.name_prefix}-rds-storage-low"
  alarm_description   = "RDS free storage below 2 GB"
  namespace           = "AWS/RDS"
  metric_name         = "FreeStorageSpace"
  dimensions          = { DBInstanceIdentifier = aws_db_instance.node[0].identifier }
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 2147483648
  comparison_operator = "LessThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]
  ok_actions          = [aws_sns_topic.alerts[0].arn]
  tags                = local.common_tags
}
