<#
STIG: WN11-00-000260
Severity: CAT III
Requirement: The Windows 11 time service must synchronize with an appropriate DOD time source.
Remediation: Uses the Windows Time Service configuration utility to configure a domain-joined system to synchronize time through the Active Directory domain hierarchy.
Validation: The resulting Windows Time Service configuration was verified locally using w32tm, followed by an authenticated Tenable Policy Compliance scan to confirm remediation.
Implementation Options: PowerShell, Local Group Policy, or Domain GPO.

.SYNOPSIS
    This PowerShell script ensures that a domain-joined Windows 11 system
    synchronizes time through the Active Directory domain hierarchy.

.NOTES
    Author          : Trevor Pulliam
    LinkedIn        : linkedin.com/in/trevor-pulliam/
    GitHub          : github.com/trevorlawrence
    Date Created    : 2026-09-09
    Last Modified   : 2026-09-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-00-000260

    NOTE: Domain Group Policy may override local policy settings. Final compliance was validated using an authenticated Tenable Policy Compliance scan.
    NOTE: This script is intended for domain-joined systems using the Active Directory domain hierarchy for time synchronization. Systems requiring manual NTP configuration
must use an authorized DoD time source.

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

# Verify that the system is joined to a domain
$computerSystem = Get-CimInstance Win32_ComputerSystem

if (-not $computerSystem.PartOfDomain) {
    Write-Host ""
    Write-Host "WN11-00-000260 remediation cannot be applied." -ForegroundColor Red
    Write-Host "This script is intended for domain-joined Windows systems."
    exit 1
}

# Configure Windows Time Service to synchronize through the domain hierarchy
w32tm /config /syncfromflags:domhier /update | Out-Null

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Failed to configure Windows Time Service." -ForegroundColor Red
    exit 1
}

# Restart the Windows Time Service to apply the configuration
Restart-Service W32Time -Force

if ($?) {
    Write-Host ""
    Write-Host "Windows Time Service restarted successfully."
}
else {
    Write-Host ""
    Write-Host "Failed to restart Windows Time Service." -ForegroundColor Red
    exit 1
}

# Force a time synchronization
w32tm /resync | Out-Null

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Windows Time Service was configured, but synchronization failed." -ForegroundColor Yellow
    Write-Host "Verify domain connectivity and the domain time hierarchy."
    exit 1
}

# Verify the applied configuration
$timeConfiguration = w32tm /query /configuration

$typeSetting = $timeConfiguration | Where-Object {
    $_ -match "^\s*Type:"
}

if ($typeSetting -match "NT5DS") {
    Write-Host ""
    Write-Host "WN11-00-000260 remediation successful." -ForegroundColor Green
    Write-Host "Windows Time Service is configured to synchronize through the domain hierarchy."
    Write-Host "NTP Client Type: NT5DS"
}
else {
    Write-Host ""
    Write-Host "WN11-00-000260 verification failed." -ForegroundColor Red
    Write-Host "Current NTP Client configuration: $typeSetting"
    exit 1
}
