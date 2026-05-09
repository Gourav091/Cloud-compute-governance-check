resource "aws_cloudwatch_dashboard" "orc_dashboard" {

  dashboard_name = "orc-dashboard"

  dashboard_body = jsonencode({
    widgets = []
  })
}