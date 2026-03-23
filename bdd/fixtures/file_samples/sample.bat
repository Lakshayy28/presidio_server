@echo off
REM Windows batch script with embedded secrets

SET DATABASE_URL=Server=db.prod.internal;Database=payments;User Id=admin;Password=Sup3rS3cr3t_P@ssw0rd
SET API_KEY=sk_live_ABCDEFGHIJKLMNOPQRSTUVWXabcdefgh
SET AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
SET ADMIN_EMAIL=devops@securecorp.com
SET CONTACT_PHONE=+1-555-867-5309
SET SERVER_IP=10.240.0.15

echo Deploying to production...
