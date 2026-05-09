resource "aws_vpc" "orc_vpc" {
    cidr_block = var.vpc_cidr 
    enable_dns_hostnames = true
    enable_dns_support = true
    tags = merge(local.common_tags, {
    Name = "orc-vpc"
  })

}
