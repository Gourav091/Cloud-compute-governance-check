resource "aws_instance" "orc_ec2" {
    ami = "ami-xxxxxxxxx"
    instance_type = "t3.medium"
    subnet_id = aws_subnet.private_subnet.id
    vpc_security_group_ids = [aws_security_group.ec2_sg.id]
    iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

    tags = {
        "Name" = "orc-ec2"
    }
}