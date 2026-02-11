#Requires -RunAsAdministrator
<#
.SYNOPSIS
    WELA Prerequisites Health Check - verifies that Windows telemetry prerequisites are met.

.DESCRIPTION
    Checks whether the host is correctly configured to generate the security events
    that WELA's Sigma-based rules depend on.

    Checks performed:
      1. Audit subcategories (via auditpol) - are the required policies enabled?
      2. Registry settings - command line auditing, PowerShell logging policies.
      3. Channel enablement - are the event log channels referenced by rules enabled?
      4. Log sizes - do key logs meet recommended minimum sizes?

    Run this BEFORE deploying WELA to identify gaps, or AFTER 'WELA.ps1 configure'
    to verify that configuration was applied correctly.

.PARAMETER Detailed
    Show all checks including PASSes. By default only WARN and FAIL are shown.

.LINK
    https://github.com/Yamato-Security/WELA
#>

param(
    [switch] $Detailed
)

# --- Helper Functions (standalone copies from WELA.ps1) ---------------------------

function Test-ChannelEnabled {
    param (
        [Parameter(Mandatory = $true)]
        [string[]] $ChannelNames
    )
    foreach ($name in $ChannelNames) {
        try {
            $logs = Get-WinEvent -ListLog $name -ErrorAction Stop
            foreach ($log in $logs) {
                if ($log.IsEnabled) { return $true }
            }
        } catch {
            # Channel not found or inaccessible
        }
    }
    return $false
}

function CheckRegistryValue {
    param (
        [string] $registryPath,
        [string] $valueName,
        [int] $expectedValue
    )
    try {
        $value = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction Stop
        if ($value.$valueName -eq $expectedValue) {
            return $true
        } else {
            return $false
        }
    } catch {
        return $false
    }
}

# --- Result Tracking --------------------------------------------------------------

$script:passCount = 0
$script:warnCount = 0
$script:failCount = 0

function Write-Result {
    param (
        [ValidateSet("PASS", "WARN", "FAIL")]
        [string] $Status,
        [string] $Message
    )
    switch ($Status) {
        "PASS" {
            $script:passCount++
            if ($Detailed) {
                Write-Host "  [PASS] $Message" -ForegroundColor Green
            }
        }
        "WARN" {
            $script:warnCount++
            Write-Host "  [WARN] $Message" -ForegroundColor Yellow
        }
        "FAIL" {
            $script:failCount++
            Write-Host "  [FAIL] $Message" -ForegroundColor Red
        }
    }
}

# --- Check 1: Audit Subcategories ------------------------------------------------

function Test-AuditSubcategories {
    Write-Host ""
    Write-Host "[Audit Subcategories]" -ForegroundColor Cyan

    # Run auditpol with forced English output
    $tempFile = [System.IO.Path]::GetTempFileName()
    try {
        Start-Process -FilePath "cmd.exe" `
            -ArgumentList "/c chcp 437 & auditpol /get /category:* /r" `
            -NoNewWindow -Wait -RedirectStandardOutput $tempFile

        # Parse: build hashtable of subcategory name -> setting
        $auditMap = @{}
        Get-Content -Path $tempFile | Select-Object -Skip 1 | ForEach-Object {
            if ([string]::IsNullOrWhiteSpace($_)) { return }
            $cols = $_ -split ','
            if ($cols.Count -ge 5) {
                $subName = $cols[2].Trim()
                $setting = $cols[4].Trim()
                if ($subName) { $auditMap[$subName] = $setting }
            }
        }
    } finally {
        Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
    }

    # Required subcategories (from ConfigureAuditSettings + checklist section 2.1)
    $required = @(
        @{ Name = "Process Creation";              Note = "drives 4688 rules" }
        @{ Name = "Logon";                          Note = "drives 4624/4625" }
        @{ Name = "Special Logon";                  Note = "privileged logons" }
        @{ Name = "Credential Validation";          Note = "NTLM visibility" }
        @{ Name = "User Account Management";        Note = "account lifecycle" }
        @{ Name = "Security Group Management";      Note = "group changes" }
        @{ Name = "Audit Policy Change";            Note = "4719 tampering detection" }
        @{ Name = "System Integrity";               Note = "boot/code integrity" }
        @{ Name = "Security System Extension";      Note = "7045 service install" }
        @{ Name = "Security State Change";          Note = "system state changes" }
        @{ Name = "Logoff";                         Note = "session tracking" }
        @{ Name = "Account Lockout";                Note = "brute force detection" }
        @{ Name = "Other Logon/Logoff Events";      Note = "additional logon events" }
        @{ Name = "Kerberos Authentication Service"; Note = "Kerberos auth" }
        @{ Name = "Kerberos Service Ticket Operations"; Note = "Kerberos tickets" }
        @{ Name = "Sensitive Privilege Use";        Note = "privilege escalation" }
        @{ Name = "File Share";                     Note = "5140/5145 lateral movement" }
        @{ Name = "Other Object Access Events";    Note = "scheduled tasks, etc." }
        @{ Name = "Certification Services";         Note = "AD CS abuse" }
        @{ Name = "SAM";                            Note = "SAM database access" }
    )

    # Optional but recommended (high volume, needs SACLs)
    $optional = @(
        @{ Name = "File System";  Note = "4663 file access (needs SACLs)" }
        @{ Name = "Registry";     Note = "4657 registry changes (needs SACLs)" }
    )

    foreach ($sub in $required) {
        $setting = $auditMap[$sub.Name]
        $isNoAudit = (-not $setting) -or ($setting -match '(?i)No Auditing|Keine')
        $isSuccessAndFailure = $setting -match '(?i)Success and Failure'
        if ($isNoAudit) {
            Write-Result "FAIL" "$($sub.Name): No Auditing ($($sub.Note))"
        } elseif ($isSuccessAndFailure) {
            Write-Result "PASS" "$($sub.Name): $setting"
        } else {
            Write-Result "WARN" "$($sub.Name): $setting (recommend: Success and Failure)"
        }
    }

    foreach ($sub in $optional) {
        $setting = $auditMap[$sub.Name]
        $isNoAudit = (-not $setting) -or ($setting -match '(?i)No Auditing|Keine')
        if ($isNoAudit) {
            Write-Result "WARN" "$($sub.Name): No Auditing ($($sub.Note))"
        } else {
            Write-Result "PASS" "$($sub.Name): $setting"
        }
    }
}

# --- Check 2: Registry Settings --------------------------------------------------

function Test-RegistrySettings {
    Write-Host ""
    Write-Host "[Registry Settings]" -ForegroundColor Cyan

    $checks = @(
        @{
            Path     = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
            Name     = "ProcessCreationIncludeCmdLine_Enabled"
            Expected = 1
            Label    = "Command Line Auditing (4688 includes command line)"
        }
        @{
            Path     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
            Name     = "EnableScriptBlockLogging"
            Expected = 1
            Label    = "PowerShell Script Block Logging (4104)"
        }
        @{
            Path     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
            Name     = "EnableModuleLogging"
            Expected = 1
            Label    = "PowerShell Module Logging (4103)"
        }
    )

    foreach ($check in $checks) {
        if (CheckRegistryValue -registryPath $check.Path -valueName $check.Name -expectedValue $check.Expected) {
            Write-Result "PASS" "$($check.Label)"
        } else {
            Write-Result "FAIL" "$($check.Label) ($($check.Name) not set to $($check.Expected))"
        }
    }
}

# --- Check 3: Channel Enablement -------------------------------------------------

function Test-ChannelAvailability {
    Write-Host ""
    Write-Host "[Channel Enablement]" -ForegroundColor Cyan

    # Load channels from security_rules.json if available
    $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
    $rulesPath = Join-Path $scriptDir "security_rules.json"
    $ruleChannels = @()

    if (Test-Path $rulesPath) {
        try {
            $rules = Get-Content -Path $rulesPath -Raw | ConvertFrom-Json
            # Internal WELA identifiers that are not real Windows Event Log channels
            $internalNames = @("sec", "pwsh")
            $ruleChannels = $rules | ForEach-Object { $_.channel } |
                ForEach-Object { $_ } |
                Where-Object { $_ -and ($internalNames -notcontains $_) } |
                Sort-Object -Unique
        } catch {
            Write-Host "  Could not parse security_rules.json, using built-in channel list." -ForegroundColor DarkGray
        }
    }

    # Fallback: built-in list of key channels
    if ($ruleChannels.Count -eq 0) {
        $ruleChannels = @(
            "Security"
            "System"
            "Application"
            "Microsoft-Windows-PowerShell/Operational"
            "Windows PowerShell"
            "Microsoft-Windows-Sysmon/Operational"
            "Microsoft-Windows-Windows Defender/Operational"
            "Microsoft-Windows-AppLocker/EXE and DLL"
            "Microsoft-Windows-AppLocker/MSI and Script"
            "Microsoft-Windows-CodeIntegrity/Operational"
            "Microsoft-Windows-TaskScheduler/Operational"
            "Microsoft-Windows-WMI-Activity/Operational"
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
            "Microsoft-Windows-SmbClient/Security"
            "Microsoft-Windows-NTLM/Operational"
            "Microsoft-Windows-Bits-Client/Operational"
            "Microsoft-Windows-WinRM/Operational"
            "Microsoft-Windows-DriverFrameworks-UserMode/Operational"
            "Microsoft-Windows-PrintService/Operational"
            "Microsoft-Windows-Security-Mitigations/KernelMode"
            "Microsoft-Windows-Security-Mitigations/UserMode"
            "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
        )
    }

    foreach ($channel in $ruleChannels) {
        try {
            $log = Get-WinEvent -ListLog $channel -ErrorAction Stop
            if ($log.IsEnabled) {
                Write-Result "PASS" "$channel"
            } else {
                Write-Result "FAIL" "$channel (found but DISABLED)"
            }
        } catch {
            Write-Result "WARN" "$channel (not found - role-specific or not installed)"
        }
    }
}

# --- Check 4: Log Sizes ----------------------------------------------------------

function Test-LogSizes {
    Write-Host ""
    Write-Host "[Log Sizes]" -ForegroundColor Cyan

    # Recommended minimum sizes (from AuditFileSize in WELA.ps1)
    $logSizes = @{
        "Security"                                                               = 256
        "Microsoft-Windows-PowerShell/Operational"                               = 256
        "Windows PowerShell"                                                     = 256
        "System"                                                                 = 128
        "Application"                                                            = 128
        "Microsoft-Windows-Windows Defender/Operational"                          = 128
        "Microsoft-Windows-Bits-Client/Operational"                              = 128
        "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"     = 256
        "Microsoft-Windows-NTLM/Operational"                                     = 128
        "Microsoft-Windows-SmbClient/Security"                                   = 128
        "Microsoft-Windows-CodeIntegrity/Operational"                            = 128
        "Microsoft-Windows-WMI-Activity/Operational"                             = 128
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"     = 128
        "Microsoft-Windows-TaskScheduler/Operational"                            = 128
        "Microsoft-Windows-AppLocker/EXE and DLL"                                = 256
    }

    foreach ($logName in $logSizes.Keys | Sort-Object) {
        $recommended = $logSizes[$logName]
        try {
            $logInfo = Get-WinEvent -ListLog $logName -ErrorAction Stop
            $currentMB = [math]::Floor($logInfo.MaximumSizeInBytes / 1MB)
            if ($currentMB -ge $recommended) {
                Write-Result "PASS" "$logName`: $currentMB MB (recommended: $recommended MB+)"
            } else {
                Write-Result "WARN" "$logName`: $currentMB MB (recommended: $recommended MB+)"
            }
        } catch {
            # Channel not available, skip silently (already covered in channel check)
        }
    }
}

# --- Main -------------------------------------------------------------------------

Write-Host ""
Write-Host "=== WELA Prerequisites Health Check ===" -ForegroundColor Cyan
Write-Host "Checking whether this host meets telemetry prerequisites for WELA detection rules."
if (-not $Detailed) {
    Write-Host "(Only showing WARN/FAIL. Use -Detailed to see all checks.)" -ForegroundColor DarkGray
}

Test-AuditSubcategories
Test-RegistrySettings
Test-ChannelAvailability
Test-LogSizes

# SACL note (cannot check programmatically)
Write-Host ""
Write-Host "[SACLs]" -ForegroundColor Cyan
Write-Host "  [INFO] SACL checks cannot be performed automatically." -ForegroundColor DarkGray
Write-Host "  [INFO] For Object Access events (4657/4663), SACLs must be set on target objects." -ForegroundColor DarkGray
Write-Host "  [INFO] See config/sacl-baseline-example.ps1 for a template." -ForegroundColor DarkGray

# Summary
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
$summaryParts = @()
if ($script:passCount -gt 0) { $summaryParts += "PASS: $($script:passCount)" }
if ($script:warnCount -gt 0) { $summaryParts += "WARN: $($script:warnCount)" }
if ($script:failCount -gt 0) { $summaryParts += "FAIL: $($script:failCount)" }
$summaryLine = "  " + ($summaryParts -join " | ")

if ($script:failCount -gt 0) {
    Write-Host $summaryLine -ForegroundColor Red
} elseif ($script:warnCount -gt 0) {
    Write-Host $summaryLine -ForegroundColor Yellow
} else {
    Write-Host $summaryLine -ForegroundColor Green
}
Write-Host ""
Write-Host "Press any key to close..." -ForegroundColor DarkGray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
