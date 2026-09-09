<#
STIG: WN11-SO-000025
Severity: CAT II
Requirement: The built-in guest account must be renamed.
Remediation: Uses secedit to configure the Windows Security Options policy so that the built-in Guest account is assigned a non-default name.
Validation: The resulting security policy was exported and verified locally, followed by an authenticated Tenable Policy Compliance scan to confirm remediation.
Implementation Options: PowerShell, Local Group Policy, or Domain GPO.

.SYNOPSIS
    This PowerShell script ensures that the built-in Guest account
    is renamed from its default name.

.NOTES
    Author          : Trevor Pulliam
    LinkedIn        : linkedin.com/in/trevor-pulliam/
    GitHub          : github.com/trevorlawrence
    Date Created    : 2026-09-09
    Last Modified   : 2026-09-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000025

    NOTE: Domain Group Policy may override local security policy settings. Final compliance was validated using an authenticated Tenable Policy Compliance scan.

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

# Define temporary security policy files
$exportPath = "$env:TEMP\WN11-SO-000025.inf"
$databasePath = "$env:TEMP\WN11-SO-000025.sdb"
$verificationPath = "$env:TEMP\WN11-SO-000025-Verification.inf"

# Define the required Guest account name
$requiredGuestName = "Guest_Account"

# Export the current local security policy
secedit /export /cfg $exportPath /quiet

if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to export the local security policy." -ForegroundColor Red
    exit 1
}

# Read the exported security policy
$securityPolicy = Get-Content $exportPath

# Locate the existing NewGuestName setting
$guestNameIndex = -1

for ($i = 0; $i -lt $securityPolicy.Count; $i++) {
    if ($securityPolicy[$i] -match "^NewGuestName\s*=") {
        $guestNameIndex = $i
        break
    }
}

# Required configuration:
# NewGuestName = Guest_Account
$requiredSetting = "NewGuestName = $requiredGuestName"

if ($guestNameIndex -ge 0) {

    # Replace the existing configuration
    $securityPolicy[$guestNameIndex] = $requiredSetting

}
else {

    # Find the [System Access] section
    $systemAccessIndex = $securityPolicy.IndexOf("[System Access]")

    if ($systemAccessIndex -eq -1) {
        Write-Host "The [System Access] section could not be found." -ForegroundColor Red
        Remove-Item $exportPath -Force -ErrorAction SilentlyContinue
        exit 1
    }

    # Add the required setting immediately after [System Access]
    $securityPolicy = @(
        $securityPolicy[0..$systemAccessIndex]
        $requiredSetting
        $securityPolicy[($systemAccessIndex + 1)..($securityPolicy.Count - 1)]
    )
}

# Write the modified security policy
Set-Content -Path $exportPath -Value $securityPolicy

# Apply the modified security policy
secedit /configure /db $databasePath /cfg $exportPath /areas SECURITYPOLICY /quiet

if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to apply the security policy." -ForegroundColor Red
    Remove-Item $exportPath -Force -ErrorAction SilentlyContinue
    Remove-Item $databasePath -Force -ErrorAction SilentlyContinue
    exit 1
}

# Re-export the applied policy for verification
secedit /export /cfg $verificationPath /quiet

if ($LASTEXITCODE -ne 0) {
    Write-Host "Remediation was applied, but verification failed." -ForegroundColor Yellow
}
else {

    $verification = Get-Content $verificationPath

    $verifiedSetting = $verification | Where-Object {
        $_ -match "^NewGuestName\s*="
    }

    # Normalize the exported value by removing quotation marks
    $verifiedGuestName = $verifiedSetting -replace '^NewGuestName\s*=\s*"?([^"]+)"?$', '$1'

    if ($verifiedGuestName -eq $requiredGuestName) {
        Write-Host ""
        Write-Host "WN11-SO-000025 remediation successful." -ForegroundColor Green
        Write-Host "The built-in Guest account has been renamed to '$requiredGuestName'."
    }
    else {
        Write-Host ""
        Write-Host "WN11-SO-000025 verification failed." -ForegroundColor Red
        Write-Host "Current configuration: $verifiedSetting"
        exit 1
    }
}

# Clean up temporary files
Remove-Item $exportPath -Force -ErrorAction SilentlyContinue
Remove-Item $databasePath -Force -ErrorAction SilentlyContinue
Remove-Item $verificationPath -Force -ErrorAction SilentlyContinue
