resource "aws_eip" "nat_eip" {
  domain = "vpc"
}

resource "aws_nat_gateway" "orc_nat" {

  allocation_id = aws_eip.nat_eip.id

  subnet_id = aws_subnet.public_subnet.id

  tags = {
    Name = "orc-nat-gateway"
  }
}