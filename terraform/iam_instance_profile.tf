resource "aws_iam_role" "ec2_role" {

  name = "orc-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_instance_profile" "ec2_profile" {

  name = "orc-ec2-profile"

  role = aws_iam_role.ec2_role.name
}