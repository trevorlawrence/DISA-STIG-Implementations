<#
STIG: WN11-CC-000110
Severity: CAT II
Requirement: Printing over HTTP must be prevented.
Remediation: Uses the Windows Registry to configure the policy setting so that printing over HTTP is disabled.
Validation: The resulting registry value was verified locally, followed by an authenticated Tenable Policy Compliance scan to confirm remediation.
Implementation Options: PowerShell, Local Group Policy, or Domain GPO.

.SYNOPSIS
    This PowerShell script ensures that printing over HTTP is disabled.

.NOTES
    Author          : Trevor Pulliam
    LinkedIn        : linkedin.com/in/trevor-pulliam/
    GitHub          : github.com/trevorlawrence
    Date Created    : 2026-09-09
    Last Modified   : 2026-09-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000110

    NOTE: Domain Group Policy may override local policy settings. Final compliance was validated using an authenticated Tenable Policy Compliance scan.

.TESTED ON
    Date(s) Tested  : 2026-09-09
    Tested By       : Trevor Pulliam
    Systems Tested  : Windows 11 Pro 25H2
    PowerShell Ver. : 5.1.26100.9444

#>

# Require Administrator privileges
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

# Define registry path and required configuration
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
$valueName = "DisableHTTPPrinting"
$requiredValue = 1

# Create the registry path if it does not exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Configure the required STIG setting
New-ItemProperty `
    -Path $registryPath `
    -Name $valueName `
    -PropertyType DWord `
    -Value $requiredValue `
    -Force | Out-Null

# Verify the applied configuration
$verifiedValue = (Get-ItemProperty `
    -Path $registryPath `
    -Name $valueName `
    -ErrorAction SilentlyContinue).$valueName

if ($verifiedValue -eq $requiredValue) {
    Write-Host ""
    Write-Host "WN11-CC-000110 remediation successful." -ForegroundColor Green
    Write-Host "Printing over HTTP is disabled."
}
else {
    Write-Host ""
    Write-Host "WN11-CC-000110 verification failed." -ForegroundColor Red
    Write-Host "Current configuration: $verifiedValue"
    exit 1
}
