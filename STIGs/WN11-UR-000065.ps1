<#
STIG: WN11-UR-000065
Severity: CAT I
Requirement: The "Debug programs" user right must be assigned only to the Administrators group.
Remediation: Uses secedit to configure the Windows User Rights Assignment policy so that SeDebugPrivilege is assigned exclusively to the built-in Administrators group.
Validation: The resulting security policy was exported and verified locally, followed by an authenticated Tenable Policy Compliance scan to confirm remediation.

.SYNOPSIS
    This PowerShell script ensures that the "Debug programs" user right
    is assigned only to the built-in Administrators group.

.NOTES
    Author          : Trevor Pulliam
    LinkedIn        : linkedin.com/in/trevor-pulliam/
    GitHub          : github.com/trevorlawrence
    Date Created    : 2026-09-09
    Last Modified   : 2026-09-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-UR-000065

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
$exportPath = "$env:TEMP\WN11-UR-000065.inf"
$databasePath = "$env:TEMP\WN11-UR-000065.sdb"

# Export the current local security policy
secedit /export /cfg $exportPath /quiet

if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to export the local security policy." -ForegroundColor Red
    exit 1
}

# Read the exported security policy
$securityPolicy = Get-Content $exportPath

# Locate the existing SeDebugPrivilege setting
$debugPrivilegeIndex = -1

for ($i = 0; $i -lt $securityPolicy.Count; $i++) {
    if ($securityPolicy[$i] -match "^SeDebugPrivilege\s*=") {
        $debugPrivilegeIndex = $i
        break
    }
}

# Required configuration:
# SeDebugPrivilege = Administrators
$requiredSetting = "SeDebugPrivilege = *S-1-5-32-544"

if ($debugPrivilegeIndex -ge 0) {

    # Replace the existing configuration
    $securityPolicy[$debugPrivilegeIndex] = $requiredSetting

}
else {

    # Find the [Privilege Rights] section
    $privilegeRightsIndex = $securityPolicy.IndexOf("[Privilege Rights]")

    if ($privilegeRightsIndex -eq -1) {
        Write-Host "The [Privilege Rights] section could not be found." -ForegroundColor Red
        Remove-Item $exportPath -Force -ErrorAction SilentlyContinue
        exit 1
    }

    # Add the required setting immediately after [Privilege Rights]
    $securityPolicy = @(
        $securityPolicy[0..$privilegeRightsIndex]
        $requiredSetting
        $securityPolicy[($privilegeRightsIndex + 1)..($securityPolicy.Count - 1)]
    )
}

# Write the modified security policy
Set-Content -Path $exportPath -Value $securityPolicy

# Apply the modified security policy
secedit /configure /db $databasePath /cfg $exportPath /areas USER_RIGHTS /quiet

if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to apply the security policy." -ForegroundColor Red
    Remove-Item $exportPath -Force -ErrorAction SilentlyContinue
    Remove-Item $databasePath -Force -ErrorAction SilentlyContinue
    exit 1
}

# Re-export the applied policy for verification
$verificationPath = "$env:TEMP\WN11-UR-000065-Verification.inf"

secedit /export /cfg $verificationPath /quiet

if ($LASTEXITCODE -ne 0) {
    Write-Host "Remediation was applied, but verification failed." -ForegroundColor Yellow
}
else {

    $verification = Get-Content $verificationPath

    $verifiedSetting = $verification | Where-Object {
        $_ -match "^SeDebugPrivilege\s*="
    }

    if ($verifiedSetting -eq $requiredSetting) {
        Write-Host ""
        Write-Host "WN11-UR-000065 remediation successful." -ForegroundColor Green
        Write-Host "The 'Debug programs' user right is assigned only to Administrators."
    }
    else {
        Write-Host ""
        Write-Host "WN11-UR-000065 verification failed." -ForegroundColor Red
        Write-Host "Current configuration: $verifiedSetting"
    }
}

# Clean up temporary files
Remove-Item $exportPath -Force -ErrorAction SilentlyContinue
Remove-Item $databasePath -Force -ErrorAction SilentlyContinue
Remove-Item $verificationPath -Force -ErrorAction SilentlyContinue
