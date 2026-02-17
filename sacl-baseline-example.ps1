#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Optional SACL baseline template for WELA Object Access rules (Event IDs 4657 / 4663).

.DESCRIPTION
    This script sets System Audit ACL entries on high-value registry keys and file paths
    that are referenced by WELA's Sigma-based security rules.

    WHY IS THIS NEEDED?
    Enabling an Object Access audit subcategory (e.g. "Registry" or "File System") only
    tells Windows to CHECK for SACLs -- it does not generate events on its own. Without
    SACLs on the target objects, no 4657/4663 events will ever appear in the Security log,
    even though the audit policy looks correct. This script closes that gap.

    PREREQUISITES (both must be met for events to appear):
      1. Advanced Audit Policy subcategories must be enabled:
         - "Object Access > Registry"  (for 4657)
         - "Object Access > File System" (for 4663)
         You can enable them via GPO or:
           auditpol /set /subcategory:"Registry" /success:enable /failure:enable
           auditpol /set /subcategory:"File System" /success:enable /failure:enable
      2. SACLs must be set on the target objects (this script).

    Without BOTH prerequisites, events 4657/4663 will NOT be generated.

.NOTES
    - This is an EXAMPLE. Adjust paths and audit flags to your environment.
    - SACLs can generate high event volume. Start with critical paths, monitor volume,
      then expand gradually.
    - Run this script on each endpoint (or deploy via GPO Startup Script / SCCM / Intune).
    - WELA's "configure" mode does NOT enable Object Access subcategories or set SACLs.
      This is intentional -- SACL deployment requires environment-specific tuning.

.LINK
    https://github.com/Yamato-Security/WELA
#>

# --- Configuration -----------------------------------------------------------
# Audit principal: "Everyone" is standard for SACLs (captures all users).
$auditIdentity = [System.Security.Principal.NTAccount]"Everyone"

# --- Registry SACL Targets (Event ID 4657) -----------------------------------
# These keys are monitored by 284 Sigma rules covering persistence, defense evasion,
# credential access, and privilege escalation techniques.

$registryTargets = @(
    # Autostart / Persistence
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

    # DLL injection / hijacking
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"                        # AppInit_DLLs
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls"
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"

    # Services (broad -- high volume, consider narrowing to specific services)
    "HKLM:\SYSTEM\CurrentControlSet\Services"

    # Security providers / credential handling
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"

    # Scheduled Tasks persistence
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"

    # COM object hijacking
    "HKLM:\SOFTWARE\Classes\CLSID"

    # Windows Defender exclusions (defense evasion)
    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes"
    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"

    # PowerShell execution policy
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
)

# Per-user autostart keys (applied to current user only -- for broader coverage,
# deploy via user logon script or GPO User Configuration).
$registryTargetsHKCU = @(
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
)

# --- File System SACL Targets (Event ID 4663) --------------------------------
# These paths are monitored by 21 Sigma rules covering credential theft,
# lateral movement tools, and suspicious file access.

$fileTargets = @(
    # Windows Credentials
    "$env:SystemRoot\System32\config"                                                    # SAM, SECURITY, SYSTEM hives
    "$env:LOCALAPPDATA\Microsoft\Credentials"                                            # DPAPI credential blobs

    # Browser credential stores (Chrome, Edge, Firefox)
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"                                  # Login Data, Cookies
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
    "$env:APPDATA\Mozilla\Firefox\Profiles"

    # Startup folders
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

    # Sysmon configuration (tampering detection)
    "$env:SystemRoot\Sysmon.xml"
    "$env:SystemRoot\Sysmon64.xml"
)

# --- Result Tracking ---------------------------------------------------------

$script:okCount   = 0
$script:failCount = 0
$script:skipCount = 0

# --- Helper Functions ---------------------------------------------------------

function Set-RegistrySACL {
    param (
        [string] $Path,
        [System.Security.Principal.NTAccount] $Identity
    )
    if (-not (Test-Path $Path)) {
        $script:skipCount++
        Write-Host "  [SKIP] Key not found: $Path" -ForegroundColor DarkGray
        return
    }
    try {
        $acl = Get-Acl -Path $Path -Audit
        $auditRule = New-Object System.Security.AccessControl.RegistryAuditRule(
            $Identity,
            [System.Security.AccessControl.RegistryRights]::SetValue -bor
            [System.Security.AccessControl.RegistryRights]::CreateSubKey -bor
            [System.Security.AccessControl.RegistryRights]::Delete,
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AuditFlags]::Success -bor
            [System.Security.AccessControl.AuditFlags]::Failure
        )
        $acl.AddAuditRule($auditRule)
        Set-Acl -Path $Path -AclObject $acl
        $script:okCount++
        Write-Host "  [OK]   $Path" -ForegroundColor Green
    } catch {
        $script:failCount++
        Write-Host "  [FAIL] $Path -- $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Set-FileSACL {
    param (
        [string] $Path,
        [System.Security.Principal.NTAccount] $Identity
    )
    if (-not (Test-Path $Path)) {
        $script:skipCount++
        Write-Host "  [SKIP] Path not found: $Path" -ForegroundColor DarkGray
        return
    }
    try {
        $acl = Get-Acl -Path $Path -Audit
        $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            $Identity,
            [System.Security.AccessControl.FileSystemRights]::Write -bor
            [System.Security.AccessControl.FileSystemRights]::Delete -bor
            [System.Security.AccessControl.FileSystemRights]::ReadData,
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AuditFlags]::Success -bor
            [System.Security.AccessControl.AuditFlags]::Failure
        )
        $acl.AddAuditRule($auditRule)
        Set-Acl -Path $Path -AclObject $acl
        $script:okCount++
        Write-Host "  [OK]   $Path" -ForegroundColor Green
    } catch {
        $script:failCount++
        Write-Host "  [FAIL] $Path -- $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --- Main ---------------------------------------------------------------------

Write-Host "`n=== WELA SACL Baseline (Example) ===" -ForegroundColor Cyan
Write-Host "Setting audit entries for Object Access events (4657 / 4663).`n"

Write-Host "[Registry - HKLM targets]" -ForegroundColor Yellow
foreach ($key in $registryTargets) {
    Set-RegistrySACL -Path $key -Identity $auditIdentity
}

Write-Host "`n[Registry - HKCU targets]" -ForegroundColor Yellow
foreach ($key in $registryTargetsHKCU) {
    Set-RegistrySACL -Path $key -Identity $auditIdentity
}

Write-Host "`n[File System targets]" -ForegroundColor Yellow
foreach ($path in $fileTargets) {
    Set-FileSACL -Path $path -Identity $auditIdentity
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
$summaryParts = @()
if ($script:okCount -gt 0)   { $summaryParts += "OK: $($script:okCount)" }
if ($script:failCount -gt 0) { $summaryParts += "FAIL: $($script:failCount)" }
if ($script:skipCount -gt 0) { $summaryParts += "SKIP: $($script:skipCount)" }
$summaryLine = "  " + ($summaryParts -join " | ")

if ($script:failCount -gt 0) {
    Write-Host $summaryLine -ForegroundColor Red
} elseif ($script:skipCount -gt 0) {
    Write-Host $summaryLine -ForegroundColor Yellow
} else {
    Write-Host $summaryLine -ForegroundColor Green
}

Write-Host "`n=== Done ===" -ForegroundColor Cyan
Write-Host @"

SACLs alone are not enough. Windows requires BOTH audit subcategories AND SACLs
to generate Object Access events. Without the subcategories enabled, the SACLs
set by this script will have no effect and events 4657/4663 will not appear.

Next steps:
  1. Ensure audit subcategories are enabled:
     auditpol /set /subcategory:"Registry" /success:enable /failure:enable
     auditpol /set /subcategory:"File System" /success:enable /failure:enable
  2. Verify events appear: Get-WinEvent -LogName Security -MaxEvents 50 | Where-Object { $_.Id -in 4657,4663 }
  3. Monitor event volume for 24-48h before expanding to additional paths.
"@
Write-Host ""
Write-Host "Press any key to close..." -ForegroundColor DarkGray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
