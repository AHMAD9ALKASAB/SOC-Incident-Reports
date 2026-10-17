<#
    Scenario 06 - Defense & Forensic Utilities
    Description: Powershell Script to check LSASS protection status (RunAsPPL) on Windows Endpoints.
    Author: Ahmad Alqassab
#>

Write-Host "=== Auditing LSASS Process Protection (RunAsPPL) ===" -ForegroundColor Cyan

$lsassPPL = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue

if ($lsassPPL.RunAsPPL -eq 1) {
    Write-Host "[+] LSASS Protection (RunAsPPL) is ENABLED. System is secured against standard dumping." -ForegroundColor Green
} else {
    Write-Host "[!] WARNING: LSASS Protection (RunAsPPL) is NOT Enabled or Missing!" -ForegroundColor Red
    Write-Host "    Recommendation: Enable RunAsPPL via GPO or Registry to prevent memory dumping." -ForegroundColor Yellow
}
