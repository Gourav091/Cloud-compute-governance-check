locals {
  common_tags = {
    Environment = var.environment
    Project = "ORC"
    ManagedBy = "Terraform"
  }
}