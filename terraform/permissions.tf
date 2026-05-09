resource "aws_lambda_permission" "apigw_permission" {

  statement_id = "AllowAPIGatewayInvoke"

  action = "lambda:InvokeFunction"

  function_name = aws_lambda_function.orc_lambda.function_name

  principal = "apigateway.amazonaws.com"
}