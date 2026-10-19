<#
    Scenario 07 - Defense & Forensic Utilities
    Description: Powershell Script to audit active SMB shares and check administrative shares exposure.
    Author: Ahmad Alqassab
#>

Write-Host "=== Auditing Active SMB Shares & Administrative Exposures ===" -ForegroundColor Cyan

Get-SmbShare | ForEach-Object {
    $shareName = $_.Name
    $sharePath = $_.Path
    
    if ($shareName -in @("C$", "ADMIN$", "IPC$")) {
        Write-Host "[!] DEFAULT ADMINISTRATIVE SHARE DETECTED:" -ForegroundColor Yellow
        Write-Host "    Share Name : $shareName" -ForegroundColor White
        Write-Host "    Path       : $sharePath" -ForegroundColor White
        Write-Host "--------------------------------------------------"
    } else {
        Write-Host "[+] Standard Share: $shareName ($sharePath)" -ForegroundColor Green
    }
}
