#Requires -Version 5.1
<#
.SYNOPSIS
    Audits a Windows machine against 17 CIS checks and exports a pass/fail report (CSV + HTML).

.DESCRIPTION
    READ-ONLY: this script only reads settings. It never changes anything on the machine.

    Each check maps to a CIS Microsoft Windows Benchmark recommendation (or a CIS Control
    where the Benchmark has no single matching item) and to a NIST CSF 2.0 subcategory,
    so the results feed straight into the NIST CSF gap analysis in /docs.

    Run from an elevated prompt (Run as administrator) for full results. Without admin
    rights, the checks that need it show ERROR instead of PASS/FAIL.

.EXAMPLE
    .\Invoke-CisAudit.ps1 -OutputPath .\reports\before.csv
#>
[CmdletBinding()]
param(
    [string]$OutputPath = ".\reports\audit-$(Get-Date -Format 'yyyyMMdd-HHmm').csv"
)

# Turn every error into one the try/catch below can see, so a broken check shows up as ERROR.
$ErrorActionPreference = 'Stop'

# ======================================================================================
# Helpers
# ======================================================================================

# Every check returns the same kind of object, so the CSV columns always line up.
#   -Passed $true -> PASS    -Passed $false -> FAIL    -Passed $null -> ERROR
function New-CheckResult {
    param(
        [string]$Id,
        [string]$Title,
        [string]$CisRef,
        [string]$NistCsf,
        [string]$Expected,
        [string]$Actual,
        [object]$Passed,
        [string]$Remediation
    )
    if ($null -eq $Passed) { $status = 'ERROR' }
    elseif ($Passed)       { $status = 'PASS' }
    else                   { $status = 'FAIL' }

    [PSCustomObject]@{
        CheckId     = $Id
        Title       = $Title
        Status      = $status
        Expected    = $Expected
        Actual      = $Actual
        NistCsf     = $NistCsf
        CisRef      = $CisRef
        Remediation = $Remediation
        Computer    = $env:COMPUTERNAME
        Timestamp   = (Get-Date).ToString('s')
    }
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Reads one line from "net accounts" (password and lockout policy). English Windows only.
function Get-NetAccountsValue {
    param([string]$Label)
    $line = net accounts | Where-Object { $_ -like "$Label*" } | Select-Object -First 1
    if ($line) { return ($line -split ':\s+', 2)[1].Trim() }
    return $null
}

# Returns a registry value, or $null if the key or value doesn't exist ("not configured").
function Get-RegValue {
    param([string]$Path, [string]$Name)
    $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $item) { return $item.$Name }
    return $null
}

# Reads one setting from the local security policy. Needs admin.
function Get-SecPolValue {
    param([string]$Name)
    $tmp = Join-Path $env:TEMP "cis-audit-secpol-$PID.inf"
    secedit /export /cfg $tmp /areas SECURITYPOLICY | Out-Null
    try {
        $line = Get-Content $tmp | Where-Object { $_ -match "^\s*$Name\s*=" } | Select-Object -First 1
        if ($line) { return ($line -split '=', 2)[1].Trim() }
        return $null
    }
    finally {
        Remove-Item $tmp -ErrorAction SilentlyContinue
    }
}

# ======================================================================================
# Account checks
# ======================================================================================

function Test-MinPasswordLength {
    $actual = Get-NetAccountsValue 'Minimum password length'
    New-CheckResult -Id 'ACCT-01' -Title 'Minimum password length is 14 or more characters' `
        -CisRef "Benchmark: Ensure 'Minimum password length' is set to '14 or more character(s)'" `
        -NistCsf 'PR.AA-01' -Expected '>= 14' -Actual $actual `
        -Passed ([int]$actual -ge 14) `
        -Remediation 'secpol.msc > Account Policies > Password Policy > Minimum password length = 14'
}

function Test-GuestAccountDisabled {
    # The built-in Guest account always has a SID ending in -501, even if it was renamed.
    $guest = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }
    $enabled = [bool]($guest -and $guest.Enabled)
    if ($enabled) { $actual = 'Enabled' } else { $actual = 'Disabled' }
    New-CheckResult -Id 'ACCT-02' -Title 'Built-in Guest account is disabled' `
        -CisRef "Benchmark: Ensure 'Accounts: Guest account status' is set to 'Disabled'" `
        -NistCsf 'PR.AA-05' -Expected 'Disabled' -Actual $actual `
        -Passed (-not $enabled) `
        -Remediation 'secpol.msc > Local Policies > Security Options > Accounts: Guest account status = Disabled'
}

function Test-LockoutThreshold {
    $raw = Get-NetAccountsValue 'Lockout threshold'
    if ($raw -eq 'Never') { $n = 0 } else { $n = [int]$raw }
    New-CheckResult -Id 'ACCT-03' -Title 'Account lockout threshold is 1-5 failed attempts' `
        -CisRef "Benchmark: Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'" `
        -NistCsf 'PR.AA-03' -Expected '1-5' -Actual $raw `
        -Passed ($n -ge 1 -and $n -le 5) `
        -Remediation 'secpol.msc > Account Policies > Account Lockout Policy > Account lockout threshold = 5'
}

function Test-PasswordComplexity {
    $v = Get-SecPolValue 'PasswordComplexity'
    New-CheckResult -Id 'ACCT-04' -Title 'Password complexity requirements are enabled' `
        -CisRef "Benchmark: Ensure 'Password must meet complexity requirements' is set to 'Enabled'" `
        -NistCsf 'PR.AA-01' -Expected '1 (Enabled)' -Actual $v `
        -Passed ($v -eq '1') `
        -Remediation 'secpol.msc > Account Policies > Password Policy > Password must meet complexity requirements = Enabled'
}

function Test-LocalAdminCount {
    try {
        # S-1-5-32-544 = local Administrators group, whatever its display name is
        $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.Name })
    }
    catch {
        # Get-LocalGroupMember fails on some machines (orphaned or cloud accounts); fall back to net.exe
        $members = @(net localgroup Administrators | Select-Object -Skip 6 |
                     Where-Object { $_ -and $_ -notmatch 'command completed' })
    }
    New-CheckResult -Id 'ACCT-05' -Title 'Local Administrators group has 2 or fewer members' `
        -CisRef 'CIS Control 5.4: Restrict Administrator Privileges to Dedicated Administrator Accounts' `
        -NistCsf 'PR.AA-05' -Expected '<= 2 members' -Actual ("$($members.Count): " + ($members -join ', ')) `
        -Passed ($members.Count -le 2) `
        -Remediation 'Remove everyday user accounts from Administrators (lusrmgr.msc); use a separate admin account when needed'
}

function Test-BuiltinAdminDisabled {
    # The built-in Administrator account always has a SID ending in -500.
    $admin = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }
    $enabled = [bool]($admin -and $admin.Enabled)
    if ($enabled) { $actual = 'Enabled' } else { $actual = 'Disabled' }
    New-CheckResult -Id 'ACCT-06' -Title 'Built-in Administrator account is disabled' `
        -CisRef "Benchmark: Ensure 'Accounts: Administrator account status' is set to 'Disabled'" `
        -NistCsf 'PR.AA-05' -Expected 'Disabled' -Actual $actual `
        -Passed (-not $enabled) `
        -Remediation 'secpol.msc > Local Policies > Security Options > Accounts: Administrator account status = Disabled'
}

# ======================================================================================
# Network checks
# ======================================================================================

function Test-FirewallEnabled {
    $profiles = Get-NetFirewallProfile
    $actual = ($profiles | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join '; '
    $off = @($profiles | Where-Object { "$($_.Enabled)" -ne 'True' })
    New-CheckResult -Id 'NET-01' -Title 'Windows Firewall is on for Domain, Private and Public profiles' `
        -CisRef "Benchmark: Ensure 'Windows Firewall: <Profile>: Firewall state' is set to 'On (recommended)'" `
        -NistCsf 'PR.IR-01' -Expected 'All profiles True' -Actual $actual `
        -Passed ($off.Count -eq 0) `
        -Remediation 'wf.msc > Windows Defender Firewall Properties > Firewall state = On for each profile'
}

function Test-Smb1Disabled {
    $v = (Get-SmbServerConfiguration).EnableSMB1Protocol
    New-CheckResult -Id 'NET-02' -Title 'SMBv1 server protocol is disabled' `
        -CisRef "Benchmark: Ensure 'Configure SMB v1 server' is set to 'Disabled'" `
        -NistCsf 'PR.PS-01' -Expected 'False' -Actual "$v" `
        -Passed (-not $v) `
        -Remediation 'Set-SmbServerConfiguration -EnableSMB1Protocol $false (admin PowerShell)'
}

function Test-LlmnrDisabled {
    $v = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
    if ($null -eq $v) { $actual = 'Not configured (LLMNR on)' } else { $actual = "EnableMulticast=$v" }
    New-CheckResult -Id 'NET-03' -Title 'LLMNR (multicast name resolution) is turned off' `
        -CisRef "Benchmark: Ensure 'Turn off multicast name resolution' is set to 'Enabled'" `
        -NistCsf 'PR.IR-01' -Expected 'EnableMulticast=0' -Actual $actual `
        -Passed ($v -eq 0) `
        -Remediation 'gpedit.msc > Computer Config > Admin Templates > Network > DNS Client > Turn off multicast name resolution = Enabled'
}

function Test-RdpNla {
    $deny = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    $nla = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
    if ($deny -eq 1) {
        $actual = 'RDP disabled'
        $passed = $true
    }
    else {
        $actual = "RDP enabled; NLA (UserAuthentication)=$nla"
        $passed = ($nla -eq 1)
    }
    New-CheckResult -Id 'NET-04' -Title 'Remote Desktop is off, or requires Network Level Authentication' `
        -CisRef "Benchmark: Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'" `
        -NistCsf 'PR.AA-03' -Expected 'RDP disabled, or NLA=1' -Actual $actual `
        -Passed $passed `
        -Remediation 'Settings > System > Remote Desktop: turn off, or under Advanced settings require Network Level Authentication'
}

# ======================================================================================
# System checks
# ======================================================================================

function Test-DefenderRealtime {
    $s = Get-MpComputerStatus
    New-CheckResult -Id 'SYS-01' -Title 'Microsoft Defender real-time protection is on' `
        -CisRef "Benchmark: Ensure 'Turn off real-time protection' is set to 'Disabled'" `
        -NistCsf 'DE.CM-09' -Expected 'True' -Actual "$($s.RealTimeProtectionEnabled)" `
        -Passed ([bool]$s.RealTimeProtectionEnabled) `
        -Remediation 'Windows Security > Virus & threat protection > Manage settings > Real-time protection = On'
}

function Test-BitLocker {
    $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive
    $actual = "$($vol.ProtectionStatus)"
    New-CheckResult -Id 'SYS-02' -Title "BitLocker is protecting the system drive ($env:SystemDrive)" `
        -CisRef 'CIS Control 3.6: Encrypt Data on End-User Devices' `
        -NistCsf 'PR.DS-01' -Expected 'On' -Actual $actual `
        -Passed ($actual -eq 'On') `
        -Remediation 'Control Panel > BitLocker Drive Encryption > Turn on BitLocker (Pro/Enterprise editions)'
}

function Test-RecentUpdates {
    $latest = Get-HotFix | Where-Object { $_.InstalledOn } |
              Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($latest) {
        $days = ((Get-Date) - $latest.InstalledOn).Days
        $actual = "$($latest.HotFixID) installed $($latest.InstalledOn.ToString('yyyy-MM-dd')) ($days days ago)"
    }
    else {
        $days = 9999
        $actual = 'No installed updates found'
    }
    New-CheckResult -Id 'SYS-03' -Title 'An update was installed in the last 30 days' `
        -CisRef 'CIS Control 7.3: Perform Automated Operating System Patch Management' `
        -NistCsf 'PR.PS-02' -Expected '<= 30 days' -Actual $actual `
        -Passed ($days -le 30) `
        -Remediation 'Settings > Windows Update > Check for updates; keep automatic updates on'
}

function Test-UacEnabled {
    $v = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
    New-CheckResult -Id 'SYS-04' -Title 'User Account Control (Admin Approval Mode) is on' `
        -CisRef "Benchmark: Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'" `
        -NistCsf 'PR.AA-05' -Expected 'EnableLUA=1' -Actual "EnableLUA=$v" `
        -Passed ($v -eq 1) `
        -Remediation 'secpol.msc > Local Policies > Security Options > User Account Control: Run all administrators in Admin Approval Mode = Enabled'
}

# ======================================================================================
# Logging checks
# ======================================================================================

function Test-ScriptBlockLogging {
    $v = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
    if ($null -eq $v) { $actual = 'Not configured' } else { $actual = "EnableScriptBlockLogging=$v" }
    New-CheckResult -Id 'LOG-01' -Title 'PowerShell script block logging is on' `
        -CisRef "Benchmark: Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled'" `
        -NistCsf 'PR.PS-04' -Expected 'EnableScriptBlockLogging=1' -Actual $actual `
        -Passed ($v -eq 1) `
        -Remediation 'gpedit.msc > Computer Config > Admin Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging = Enabled'
}

function Test-AuditLogon {
    # Subcategory GUID for "Logon", so this works whatever the display language is
    $out = auditpol /get '/subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}' /r
    if ($LASTEXITCODE -ne 0) { throw 'auditpol failed - run as administrator' }
    $row = $out | Where-Object { $_ } | ConvertFrom-Csv | Select-Object -First 1
    $setting = $row.'Inclusion Setting'
    New-CheckResult -Id 'LOG-02' -Title 'Successful and failed logons are audited' `
        -CisRef "Benchmark: Ensure 'Audit Logon' is set to 'Success and Failure'" `
        -NistCsf 'PR.PS-04' -Expected 'Success and Failure' -Actual $setting `
        -Passed ($setting -eq 'Success and Failure') `
        -Remediation 'auditpol /set /subcategory:"Logon" /success:enable /failure:enable (admin prompt)'
}

function Test-SecurityLogSize {
    $log = Get-WinEvent -ListLog Security
    $kb = [int]($log.MaximumSizeInBytes / 1KB)
    New-CheckResult -Id 'LOG-03' -Title 'Security event log can hold at least 196,608 KB' `
        -CisRef "Benchmark: Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'" `
        -NistCsf 'PR.PS-04' -Expected '>= 196608 KB' -Actual "$kb KB" `
        -Passed ($kb -ge 196608) `
        -Remediation 'eventvwr.msc > Windows Logs > Security > Properties > Maximum log size = 196608 KB'
}

# ======================================================================================
# Run everything
# ======================================================================================

if (-not (Test-IsAdmin)) {
    Write-Warning 'Not running as administrator - some checks will show ERROR. For full results: right-click Windows PowerShell > Run as administrator.'
}

$checks = @(
    'Test-MinPasswordLength', 'Test-GuestAccountDisabled', 'Test-LockoutThreshold',
    'Test-PasswordComplexity', 'Test-LocalAdminCount', 'Test-BuiltinAdminDisabled',
    'Test-FirewallEnabled', 'Test-Smb1Disabled', 'Test-LlmnrDisabled', 'Test-RdpNla',
    'Test-DefenderRealtime', 'Test-BitLocker', 'Test-RecentUpdates', 'Test-UacEnabled',
    'Test-ScriptBlockLogging', 'Test-AuditLogon', 'Test-SecurityLogSize'
)

$results = foreach ($check in $checks) {
    try {
        & $check
    }
    catch {
        New-CheckResult -Id $check -Title "$check could not run" -CisRef '' -NistCsf '' `
            -Expected '' -Actual $_.Exception.Message -Passed $null `
            -Remediation 'Usually: run as administrator, or this feature is not available on this Windows edition'
    }
}

# Score = passed / (checks that actually ran)
$scored = @($results | Where-Object { $_.Status -ne 'ERROR' })
$passed = @($scored | Where-Object { $_.Status -eq 'PASS' }).Count
if ($scored.Count -gt 0) { $score = [math]::Round(100 * $passed / $scored.Count) } else { $score = 0 }
$summary = "Compliance score: $score% ($passed of $($scored.Count) checks passed, $($results.Count - $scored.Count) errors)"

# CSV
$folder = Split-Path -Parent $OutputPath
if ($folder -and -not (Test-Path $folder)) { New-Item -ItemType Directory -Path $folder | Out-Null }
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# HTML (same data, easier to screenshot for the README)
$htmlPath = [IO.Path]::ChangeExtension($OutputPath, '.html')
$style = '<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#101828}' +
         'table{border-collapse:collapse}td,th{border:1px solid #e4e7ec;padding:6px 10px;font-size:13px;vertical-align:top}' +
         'th{background:#0c1220;color:#fff;text-align:left}</style>'
$pre = "<h1>Windows CIS Audit</h1><p><b>$summary</b><br>Computer: $env:COMPUTERNAME &middot; $(Get-Date -Format 'yyyy-MM-dd HH:mm')</p>"
($results | Select-Object CheckId, Status, Title, Expected, Actual, NistCsf, CisRef |
    ConvertTo-Html -Title 'Windows CIS Audit' -Head $style -PreContent $pre) `
    -replace '<td>PASS</td>', '<td style="color:#067647;font-weight:bold">PASS</td>' `
    -replace '<td>FAIL</td>', '<td style="color:#b42318;font-weight:bold">FAIL</td>' `
    -replace '<td>ERROR</td>', '<td style="color:#b54708;font-weight:bold">ERROR</td>' |
    Out-File -FilePath $htmlPath -Encoding utf8

# Console
$results | Format-Table CheckId, Status, Title, Actual -AutoSize -Wrap | Out-Host
Write-Host $summary
Write-Host "CSV report:  $OutputPath"
Write-Host "HTML report: $htmlPath"
