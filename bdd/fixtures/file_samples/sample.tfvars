# Terraform variable values — embedded secrets for sanitizer testing

# AWS provider credentials
aws_access_key     = "AKIAIOSFODNN7EXAMPLE"
aws_secret_key     = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
aws_region         = "us-east-1"

# Azure provider credentials
azure_subscription_id = "12345678-1234-1234-1234-123456789012"
ARM_CLIENT_SECRET     = "ABCDEFab12345678ABCDEFabcdef1234567890ab"
azure_tenant_id       = "abcdef12-abcd-abcd-abcd-abcdef123456"

# Database connection
db_connection_string  = "postgres://admin:Passw0rd!@prod-db.corp.internal:5432/payments"
db_password           = "Sup3rS3cr3t_P@ssw0rd_2024"

# Terraform Cloud token
terraform_token = "ABCDEFGHIJklmno.atlasv1.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB"

# GCP service account key file path
gcp_credentials       = "/etc/gcp-sa.json"

# Internal network
db_host               = "payments-db-primary.prod.internal"
cache_ip              = "10.240.0.15"

# Contact
ops_email             = "devops@securecorp.com"
