# DISA STIG Remediation Scripts
This repository contains PowerShell scripts used to remediate DISA Security Technical Implementation Guide (STIG) findings identified through Tenable vulnerability scans on Windows 11 systems.

## About

The Defense Information Systems Agency (DISA) is a U.S. Department of Defense (DoD) agency responsible for providing information technology and cybersecurity services to support military and defense organizations. As part of its cybersecurity mission, DISA develops STIGs that establish secure configuration requirements for information systems and help reduce security risks across DoD environments. This repository documents practical STIG remediation using manual and PowerShell solutions. The implemented STIGs are ordered from highest severity (CAT I) to lowest (CAT III).

## STIGs Implemented

| STIG ID | Title | Severity |
|---------|-------|----------|
| WN11-CC-000180 | Autoplay must be turned off for non-volume devices | CAT I |
| WN11-UR-000065 | The 'Debug programs' user right must only be assigned to the Administrators
group | CAT I |
| WN11-AC-000020 | The password history must be configured to 24 passwords remembered | CAT II |
| WN11-SO-000025 | The built-in guest account must be renamed | CAT II |
| WN11-CC-000110 | Printing over HTTP must be prevented | CAT II |
| WN11-CC-000206 | Windows Update must not obtain updates from other PCs on the internet | CAT III |
| WN11-00-000260 | The Windows 11 time service must synchronize with an appropriate DOD time source | CAT III |

## Methodology

1. Performed an authenticated Tenable Policy Compliance scan against a Windows 11 endpoint using the applicable DISA Windows 11 STIG v2r8 audit.
2. Reviewed failed compliance checks to identify security configuration gaps and determine the affected system settings.
3. Analyzed STIG requirements and remediation guidance using [stigaview.com](https://stigaview.com).
4. Developed PowerShell remediation scripts to automate configuration changes.
5. Applied and validated remediation changes with administrative privileges.
6. Re-scanned the endpoint with Tenable to verify remediation and confirm the STIG finding transitioned from **Failed → Passed**.

## Usage

```powershell
# Run as Administrator
.\WN11-CC-000315.ps1
```

Each script sets a specific registry value required by the corresponding STIG.

## Verification

After running a script, verify compliance by either:
- Re-running a Tenable STIG scan
- Manually checking the registry value with `Get-ItemProperty`

## Environment Tested

- **OS:** Windows 11 Pro 25H2
- **PowerShell:** 5.1
- **Scanner:** Tenable Vulnerability Management
- **STIG Version:** DISA Microsoft Windows 11 STIG v2r8

## Author

**Trevor L. Pulliam** — Cybersecurity Analyst Intern at Log(N) Pacific
