resource "aws_security_group" "lambda_sg" {
    name = "lambda-sg"
    vpc_id = aws_vpc.orc_vpc.id
    egress = {
        from_port = 0
        to_port = 0
        protocol = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }
}

resource "aws_security_group" "ec2_sg" {
    name = "ec2-sg"
    vpc_id = aws_vpc.orc_vpc.id
    ingress = {
        from_port = 22
        to_port = 22
        protocol = "tcp"
        cidr_blocks = var.vpc_cidr
    }

    egress = {
        from_port = 0
        to_port = 0
        protocol = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }
}