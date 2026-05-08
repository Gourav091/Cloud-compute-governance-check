resource "aws_iam_role" "lambda_role" {

    name = "orc-lambda-role"
    assume_role_policy = jsondecode({
        Version = "2012-10-17"

        Statement = [
        {
                Action = "sts:AssumeRole"
                Effect = Allow
                Principal = {
                    Service = "lambda.amazonaws.com"
                }
        }
        ]
    })

}