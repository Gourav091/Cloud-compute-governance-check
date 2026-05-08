resource "aws_cloudwatch_log_group" "orc_logs"{
    name = "/aws/lambda/orc"     #The actual log group name in AWS CloudWatch
}