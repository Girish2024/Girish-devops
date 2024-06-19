terraform {
  backend "s3" {
    bucket         = "adasdasd33refdsfdsfd"
    key            = "terraform.tfstate"
    region         = "us-east-1"
#    dynamodb_table = "external-terraform-locks"
    encrypt        = true
  }
}
