<#
    Scenario 05 - Defense & Forensic Utilities
    Description: Powershell Script to audit and detect suspicious scheduled tasks containing encoded powershell execution.
    Author: Ahmad Alqassab
#>

Write-Host "=== Auditing Registered Scheduled Tasks for Encoded Commands ===" -ForegroundColor Cyan

# Fetch all scheduled tasks
Get-ScheduledTask | ForEach-Object {
    $taskName =$_.TaskName
    $actions =$_.Actions
    
    foreach ($action in$actions) {
        if ($action.Execute -like "*powershell*" -and ($action.Arguments -like "*-e *" -or $action.Arguments -like "*-EncodedCommand*")) {
            Write-Host "[!] SUSPICIOUS TASK DETECTED:" -ForegroundColor Red
            Write-Host "    Task Name : $taskName" -ForegroundColor Yellow
            Write-Host "    Path      : $($_.TaskPath)" -ForegroundColor Yellow
            Write-Host "    Execute   : $($action.Execute)" -ForegroundColor Yellow
            Write-Host "    Arguments : $($action.Arguments)" -ForegroundColor Yellow
            Write-Host "----------------------------------------------------"
        }
    }
}
