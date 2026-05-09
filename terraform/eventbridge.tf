resource "aws_cloudwatch_event_rule" "orc_schedule" {

    name = "orc-scheduler"
    schedule_expression = "rate(1 day)"
}