resource "aws_ebs_volume" "orc_ebs" {
    availability_zone = "us-east-1a"
    size = 100
    type = "gp3"
    encrypted = true
}

resource "aws_volume_attachment" "ebs_attach" {
    device_name = "/dev/sdf"
    volume_id = aws_ebs_volume.orc_ebs.id
    instance_id = aws_instance.orc_ec2.id
}