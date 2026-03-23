# PowerShell module with secrets

function Connect-PaymentsDb {
    param(
        [string]$ConnectionString = "Server=db.prod.internal;Database=payments;User Id=admin;Password=Sup3rS3cr3t_P@ssw0rd"
    )
    $apiKey = "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXabcdefgh"
    $contact = "devops@securecorp.com"
    $phone = "+1-555-867-5309"
    $server = "10.240.0.15"
}
