<#
STIG: WN11-CC-000175
Severity: CAT III
Requirement: Windows 11 must be configured to prevent the Application Compatibility Program Inventory from collecting data.
Remediation: Configure the DisableInventory registry value to 1.
Validation: Verify that DisableInventory is configured as REG_DWORD 1.
Implementation Options: Local Registry, Local Group Policy, Domain Group Policy

.SYNOPSIS
    Remediates STIG WN11-CC-000175 by disabling the Application Compatibility Program Inventory.

.NOTES
    Author: Trevor Pulliam
    LinkedIn: linkedin.com/in/trevor-pulliam/
    GitHub: github.com/trevorlawrence
    Date Created: 09/10/2026
    Last Modified: 09/10/2026
    Version: 1.0
    CVEs: N/A
    Plugin IDs: N/A
    STIG-ID: WN11-CC-000175

    NOTE: Domain Group Policy may override local policy settings. Final compliance was validated using an authenticated Tenable Policy Compliance scan.

.TESTED ON
    Date(s) Tested: 09/10/2026
    Tested By: Trevor Pulliam
    Systems Tested: Windows 11 Pro 25H2
    PowerShell Ver.: 5.1.26100.9444

#>

# Verify Administrator privileges
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

# Registry configuration
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
$valueName = "DisableInventory"
$requiredValue = 1

Write-Host ""
Write-Host "Applying WN11-CC-000175 remediation..." -ForegroundColor Cyan

# Create registry key if it does not exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Configure the required registry value
New-ItemProperty `
    -Path $registryPath `
    -Name $valueName `
    -PropertyType DWord `
    -Value $requiredValue `
    -Force | Out-Null

# Local verification
$verifiedValue = Get-ItemPropertyValue `
    -Path $registryPath `
    -Name $valueName `
    -ErrorAction SilentlyContinue

if ($verifiedValue -eq $requiredValue) {
    Write-Host ""
    Write-Host "WN11-CC-000175 remediation successful." -ForegroundColor Green
    Write-Host "DisableInventory is configured to REG_DWORD 1."
}
else {
    Write-Host ""
    Write-Host "WN11-CC-000175 verification failed." -ForegroundColor Red
    Write-Host "Current value: $verifiedValue"
    exit 1
}
