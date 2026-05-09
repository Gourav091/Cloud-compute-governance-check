resource "aws_sfn_state_machine" "orc_workflow" {
  name = "orc-workflow"
  role_arn = aws_iam_role.lambda_role.arn
  definition = file("../stepfunctions/orc_workflow.json")
}