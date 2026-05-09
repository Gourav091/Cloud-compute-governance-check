resource "aws_cloudwatch_log_group" "orc_logs"{
    name = "/aws/lambda/orc-input-validation"     #The actual log group name in AWS CloudWatch
    retention_in_days = 30
}