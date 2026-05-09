resource "aws_cloudwatch_metric_alarm" "cpu_alarm" {

  alarm_name = "high-cpu"

  comparison_operator = "GreaterThanThreshold"

  evaluation_periods = 1

  metric_name = "CPUUtilization"

  namespace = "AWS/EC2"

  period = 300

  statistic = "Average"

  threshold = 80

  alarm_actions = [aws_sns_topic.orc_notifications.arn]
}