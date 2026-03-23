# Terraform main.tf — provider config with secrets

provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_db_instance" "payments" {
  identifier = "payments-db"
  engine     = "postgres"
  username   = "admin"
  password   = "Sup3rS3cr3t_P@ssw0rd_2024"

  tags = {
    Owner       = "devops@securecorp.com"
    ContactPhone = "+1-555-867-5309"
  }
}

resource "aws_instance" "api" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.medium"
  private_ip    = "10.240.0.15"
}
