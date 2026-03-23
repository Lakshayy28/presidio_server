#!/bin/bash
# Deployment script with embedded credentials

export DATABASE_URL="postgres://admin:Passw0rd!@db.prod.internal:5432/payments"
export API_KEY="sk_live_ABCDEFGHIJKLMNOPQRSTUVWXabcdefgh"
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

echo "Deploying as devops@securecorp.com"
echo "Contact: +1-555-867-5309"
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" \
  https://api.securecorp.com/deploy
