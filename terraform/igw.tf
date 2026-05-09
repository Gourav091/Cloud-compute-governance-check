resource "aws_internet_gateway" "orc_igw" {

  vpc_id = aws_vpc.orc_vpc.id

  tags = {
    Name = "orc-igw"
  }
}