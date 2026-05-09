resource "aws_launch_template" "orc_lt" {

  name_prefix = "orc-template"

  image_id = "ami-12345678"

  instance_type = "t3.medium"
}