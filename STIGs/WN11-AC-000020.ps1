<#
STIG: WN11-AC-000020
Severity: CAT II
Requirement: The password history must be configured to 24 passwords remembered.
Remediation: Uses the Windows net accounts utility to configure the password history policy to remember the previous 24 passwords.
Validation: The resulting password policy was verified locally using net accounts, followed by an authenticated Tenable Policy Compliance scan to confirm remediation.
Implementation Options: PowerShell, Local Group Policy, or Domain GPO.

.SYNOPSIS
    This PowerShell script ensures that Windows password history is configured
    to remember the previous 24 passwords.

.NOTES
    Author          : Trevor Pulliam
    LinkedIn        : linkedin.com/in/trevor-pulliam/
    GitHub          : github.com/trevorlawrence
    Date Created    : 2026-09-09
    Last Modified   : 2026-09-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AC-000020

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

# Configure password history to remember the previous 24 passwords
net accounts /uniquepw:24 | Out-Null

if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to configure password history." -ForegroundColor Red
    exit 1
}

# Verify the applied configuration
$passwordPolicy = net accounts

$historySetting = $passwordPolicy | Where-Object {
    $_ -match "Unique passwords remembered"
}

if ($historySetting -match "24") {
    Write-Host ""
    Write-Host "WN11-AC-000020 remediation successful." -ForegroundColor Green
    Write-Host "Password history is configured to remember 24 passwords."
}
else {
    Write-Host ""
    Write-Host "WN11-AC-000020 verification failed." -ForegroundColor Red
    Write-Host "Current configuration: $historySetting"
    exit 1
}
