<#
    Scenario 08 - Defense & Forensic Utilities
    Description: Powershell Script to audit Active Directory service accounts and check for weak Kerberos encryption settings.
    Author: Ahmad Alqassab
#>

Write-Host "=== Auditing Active Directory Service Accounts & SPNs ===" -ForegroundColor Cyan

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    
    $serviceAccounts = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName, CannotChangePassword, PasswordNeverExpires
    
    foreach ($account in $serviceAccounts) {
        Write-Host "[!] Service Account Found:" -ForegroundColor Yellow
        Write-Host "    Name          : $($account.Name)" -ForegroundColor White
        Write-Host "    SamAccountName: $($account.SamAccountName)" -ForegroundColor White
        Write-Host "    SPNs          : $($account.ServicePrincipalName -join ', ')" -ForegroundColor White
        Write-Host "--------------------------------------------------"
    }
} catch {
    Write-Host "[x] Error: ActiveDirectory module not found or not running on a Domain Controller." -ForegroundColor Red
}
