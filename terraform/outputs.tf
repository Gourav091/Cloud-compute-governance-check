output "vpc_id" {
  value = aws_vpc.orc_vpc.id
}

output "private_subnet_id" {
  value = aws_subnet.private_subnet.id
}