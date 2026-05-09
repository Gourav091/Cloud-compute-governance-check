resource "aws_lambda_function" "input_validation_lambda" {
    function_name = "orc-input-validation"
    package_type = "Image"
    image_uri = "${aws_ecr_repository.input_validation_repo.repository_url}:latest"
    role = aws_iam_role.lambda_role.arn
    timeout = 300  #5mins
    memory_size = 512

    vpc_config {
    subnet_ids = [aws_subnet.private_subnet.id]
    security_group_ids = [aws_security_group.lambda_sg.id]
    }
}