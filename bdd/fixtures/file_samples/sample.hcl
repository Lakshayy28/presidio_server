# Vault agent config with secrets

storage "consul" {
  address = "consul.prod.internal:8500"
  token   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"
}

listener "tcp" {
  address     = "10.240.0.15:8200"
  tls_disable = 0
}

seal "awskms" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# Vault admin: admin@securecorp.com
# Support phone: +1-555-867-5309
