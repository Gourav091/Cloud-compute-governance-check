terraform {
  backend "s3" {

    bucket = "terraform-state-bucket"
    key = "orc/terraform.tfstate"
    region = "us-east-1"
    dynamodb_table = "terraform-lock"
  }
}