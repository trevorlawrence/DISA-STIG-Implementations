```powershell
<#
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

# Locate the [Privilege Rights] section
$privilegeRightsIndex = $securityPolicy.IndexOf("[Privilege Rights]")

if ($privilegeRightsIndex -eq -1) {
    Write-Host "The [Privilege Rights] section could not be found." -ForegroundColor Red
    Remove-Item $exportPath -Force -ErrorAction SilentlyContinue
    exit 1
}

# Find the existing SeDebugPrivilege entry
$debugPrivilegeIndex = -1

for ($i = $privilegeRightsIndex + 1; $i -lt $securityPolicy.Count; $i++) {

    if ($securityPolicy[$i] -match "^\[.*\]$") {
        break
    }

    if ($securityPolicy[$i] -match "^SeDebugPrivilege\s*=") {
        $debugPrivilegeIndex = $i
        break
    }
}

# Required configuration:
# SeDebugPrivilege = Administrators (S-1-5-32-544)
$requiredSetting = "SeDebugPrivilege = *S-1-5-32-544"

if ($debugPrivilegeIndex -ge 0) {

    # Replace the existing configuration
    $securityPolicy[$debugPrivilegeIndex] = $requiredSetting

}
else {

    # Find the end of the [Privilege Rights] section
    $insertIndex = $privilegeRightsIndex + 1

    while (
        $insertIndex -lt $securityPolicy.Count -and
        $securityPolicy[$insertIndex] -notmatch "^\[.*\]$"
    ) {
        $insertIndex++
    }

    # Insert the required configuration
    $securityPolicy = @(
        $securityPolicy[0..($insertIndex - 1)]
        $requiredSetting
        $securityPolicy[$insertIndex..($securityPolicy.Count - 1)]
    )
}

# Write the modified security policy
Set-Content -Path $exportPath -Value $securityPolicy

# Apply the modified security policy
secedit /configure /db $databasePath /cfg $exportPath /areas USER_RIGHTS /quiet

if ($LASTEXITCODE -eq 0) {

    Write-Host ""
    Write-Host "WN11-UR-000065 remediation completed successfully." -ForegroundColor Green
    Write-Host "Debug programs is now assigned only to the Administrators group."

}
else {

    Write-Host ""
    Write-Host "WN11-UR-000065 remediation failed." -ForegroundColor Red
}

# Clean up temporary files
Remove-Item $exportPath -Force -ErrorAction SilentlyContinue
Remove-Item $databasePath -Force -ErrorAction SilentlyContinue
```
