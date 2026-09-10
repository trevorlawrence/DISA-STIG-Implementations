# DISA STIG Remediation & Compliance
This repository contains PowerShell scripts used to remediate DISA Security Technical Implementation Guide (STIG) findings identified through Tenable vulnerability scans on Windows 11 systems.

## About

The Defense Information Systems Agency (DISA) is a U.S. Department of Defense (DoD) agency responsible for providing information technology and cybersecurity services to support military and defense organizations. As part of its cybersecurity mission, DISA develops STIGs that establish secure configuration requirements for information systems and help reduce security risks across DoD environments. This repository documents practical STIG remediation using manual and PowerShell solutions. The implemented STIGs are ordered from highest severity (CAT I) to lowest (CAT III).

## STIGs Implemented

| STIG ID | Title | Severity |
|---------|-------|----------|
| [WN11-CC-000180](https://github.com/trevorlawrence/DISA-STIG-Implementations/blob/main/STIGs/WN11-CC-000180.ps1) | Autoplay must be turned off for non-volume devices | CAT I |
| [WN11-UR-000065](https://github.com/trevorlawrence/DISA-STIG-Implementations/blob/main/STIGs/WN11-UR-000065.ps1) | The 'Debug programs' user right must only be assigned to the Administrators group | CAT I |
| [WN11-AC-000020](https://github.com/trevorlawrence/DISA-STIG-Implementations/blob/main/STIGs/WN11-AC-000020.ps1) | The password history must be configured to 24 passwords remembered | CAT II |
| [WN11-SO-000025](https://github.com/trevorlawrence/DISA-STIG-Implementations/blob/main/STIGs/WN11-SO-000025.ps1) | The built-in guest account must be renamed | CAT II |
| [WN11-CC-000110](https://github.com/trevorlawrence/DISA-STIG-Implementations/blob/main/STIGs/WN11-CC-000110.ps1) | Printing over HTTP must be prevented | CAT II |
| [WN11-CC-000175](https://github.com/trevorlawrence/DISA-STIG-Implementations/blob/main/STIGs/WN11-CC-000175.ps1) | The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft | CAT III |

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
.\WN11-CC-000180.ps1
```

Each script implements the configuration required by its corresponding STIG
using the appropriate Windows administrative mechanism.

## Other Implementation Methods

PowerShell is used in this repository to automate STIG remediation. The following
STIGs can also be implemented through Windows administrative tools or centralized
configuration management.

### WN11-CC-000180
**Autoplay must be turned off for non-volume devices**

- **Local Group Policy:** Computer Configuration → Administrative Templates → Windows Components → AutoPlay Policies → Disallow Autoplay for non-volume devices → Enabled
- **Domain GPO:** Apply the same policy through a domain-based Group Policy Object.

### WN11-AC-000020
**The password history must be configured to 24 passwords remembered**

- **Local Group Policy:** Computer Configuration → Windows Settings → Security Settings → Account Policies → Password Policy → Enforce password history → 24 passwords
- **Domain GPO:** Apply the same policy through a domain-based Group Policy Object.

### WN11-SO-000025
**The built-in guest account must be renamed**

- **Local Group Policy:** Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → Accounts: Rename guest account
- **Domain GPO:** Apply the same policy through a domain-based Group Policy Object.

### WN11-CC-000110
**Printing over HTTP must be prevented**

- **Local Group Policy:** Computer Configuration → Administrative Templates → System → Internet Communication Management → Internet Communication settings → Turn off printing over HTTP → Enabled
- **Domain GPO:** Apply the same policy through a domain-based Group Policy Object.

### WN11-CC-000175
**The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft**

- **Local Group Policy:** Computer Configuration → Administrative Templates → Windows Components → Application Compatibility → Turn off Inventory Collector → Enabled
- **Domain GPO:** Apply the same policy through a domain-based Group Policy Object.

### WN11-UR-000065
**The "Debug programs" user right must only be assigned to the Administrators group**

- **Local Group Policy:** Computer Configuration → Windows Settings → Security Settings → Local Policies → User Rights Assignment → Debug programs
- **Domain GPO:** Apply the user-right assignment through a domain-based Group Policy Object.

> **Note:** Domain Group Policy may override local configuration. Organizations should use centralized configuration management where appropriate.

## Verification

After running a script, verify compliance by either:
* Re-running a Tenable STIG scan
* Manually checking the resulting configuration

## Environment Tested

- **OS:** Windows 11 Pro 25H2
- **PowerShell:** 5.1
- **Scanner:** Tenable Vulnerability Management
- **STIG Version:** DISA Microsoft Windows 11 STIG v2r8

## Author

**Trevor L. Pulliam** — Cybersecurity Analyst Intern at Log(N) Pacific
