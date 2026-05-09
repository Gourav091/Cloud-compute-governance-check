resource "aws_autoscaling_group" "orc_asg" {

  desired_capacity = 1

  max_size = 2

  min_size = 1

  vpc_zone_identifier = [aws_subnet.private_subnet.id]

  launch_template {
    id      = aws_launch_template.orc_lt.id
    version = "$Latest"
  }
}