<#
.SYNOPSIS
    CIS Windows 11 Admin Build Review with POC Evidence
.DESCRIPTION
    140+ checks covering CIS L1/L2 benchmarks, attack surface, and defense posture.
    REQUIRES ADMINISTRATOR. POC runs automatically.
    Single self-contained HTML report with all evidence embedded.
.EXAMPLE
    .\CIS_Win11_Admin_BuildReview.ps1
    .\CIS_Win11_Admin_BuildReview.ps1 -OutputPath C:\Temp
#>
[CmdletBinding()]
param([string]$OutputPath = "$env:USERPROFILE\Desktop")

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
if (-not $isAdmin) {
    Write-Host "`n  [!] This script REQUIRES Administrator privileges." -ForegroundColor Red
    Write-Host "  Right-click PowerShell > Run as Administrator`n" -ForegroundColor Yellow
    exit
}

$Script:Results = [System.Collections.ArrayList]::new()
$Script:StartTime = Get-Date
$Script:ComputerName = $env:COMPUTERNAME
$Script:OSVersion = try { (Get-CimInstance Win32_OperatingSystem).Caption } catch { "Unknown" }
$Script:OSBuild = try { (Get-CimInstance Win32_OperatingSystem).BuildNumber } catch { "Unknown" }
$Script:CurrentUser = "$env:USERDOMAIN\$env:USERNAME"
$Script:POCTag = "CISv4_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$Script:IsDomainJoined = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).PartOfDomain

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$CheckTitle,
        [Parameter(Mandatory)][ValidateSet("Pass","Fail","Warning","Info","Error")][string]$Status,
        [string]$Expected = "", [string]$Actual = "", [string]$Description = "",
        [ValidateSet("Critical","High","Medium","Low","Informational")][string]$Severity = "Medium",
        [string]$Remediation = "", [string]$ExploitCmd = "", [string]$POCResult = "",
        [string]$CISRef = ""
    )
    $title = if ($CISRef) { "[$CISRef] $CheckTitle" } else { $CheckTitle }
    $null = $Script:Results.Add([PSCustomObject]@{
        Category=$Category; CheckTitle=$title; Status=$Status; Expected=$Expected
        Actual=$Actual; Description=$Description; Severity=$Severity
        Remediation=$Remediation; ExploitCmd=$ExploitCmd; POCResult=$POCResult
    })
}

function Get-RegValue { param([string]$Path, [string]$Name, $Default=$null)
    try { $v = Get-ItemProperty -Path "Registry::$Path" -Name $Name -ErrorAction Stop; return $v.$Name } catch { return $Default }
}

function ConvertTo-HtmlSafe { param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $a = [string][char]38; $dq = [string][char]34
    $Text = $Text -replace $a, ($a + 'amp;')
    $Text = $Text -replace '<', ($a + 'lt;')
    $Text = $Text -replace '>', ($a + 'gt;')
    $Text = $Text -replace $dq, ($a + 'quot;')
    return $Text
}

function Get-IcaclsOutput { param([string]$Path)
    try { return (icacls $Path 2>$null) -join "`n" } catch { return "icacls failed" }
}

function Write-Section { param([string]$Name) Write-Host "`n[+] $Name" -ForegroundColor Green }


# ============================================================================
# 1. ACCOUNT POLICIES (CIS 1.x)
# ============================================================================
function Test-AccountPolicies {
    Write-Section "Account Policies (CIS 1.x)"

    $netAccounts = net accounts 2>$null
    $poc = ($netAccounts | Out-String).Trim()

    $minLen = if ($netAccounts -match "Minimum password length:\s+(\d+)") { [int]$Matches[1] } else { 0 }
    $maxAge = if ($netAccounts -match "Maximum password age \(days\):\s+(\d+|Unlimited)") { $Matches[1] } else { "Unknown" }
    $minAge = if ($netAccounts -match "Minimum password age \(days\):\s+(\d+)") { [int]$Matches[1] } else { 0 }
    $lockThresh = if ($netAccounts -match "Lockout threshold:\s+(\w+)") { $Matches[1] } else { "Unknown" }
    $lockDuration = if ($netAccounts -match "Lockout duration \(minutes\):\s+(\d+)") { [int]$Matches[1] } else { 0 }
    $lockWindow = if ($netAccounts -match "Lockout observation window.*?:\s+(\d+)") { [int]$Matches[1] } else { 0 }
    $history = if ($netAccounts -match "Length of password history maintained:\s+(\d+|None)") { $Matches[1] } else { "0" }

    Add-Finding -Category "Account Policies" -CheckTitle "Password history" -CISRef "1.1.1" `
        -Status $(if($history -ne "None" -and [int]$history -ge 24){"Pass"}else{"Fail"}) `
        -Expected "24" -Actual $history -Severity "Medium" -POCResult $poc `
        -Remediation "GPO: Enforce password history = 24"

    Add-Finding -Category "Account Policies" -CheckTitle "Maximum password age" -CISRef "1.1.2" `
        -Status $(if($maxAge -ne "Unlimited" -and [int]$maxAge -le 365){"Pass"}else{"Warning"}) `
        -Expected "365 days" -Actual $maxAge -Severity "Medium" `
        -Remediation "GPO: Maximum password age = 365"

    Add-Finding -Category "Account Policies" -CheckTitle "Minimum password age" -CISRef "1.1.3" `
        -Status $(if($minAge -ge 1){"Pass"}else{"Fail"}) -Expected "1+" -Actual "$minAge" `
        -Severity "Medium" -Remediation "GPO: Minimum password age = 1"

    Add-Finding -Category "Account Policies" -CheckTitle "Minimum password length" -CISRef "1.1.4" `
        -Status $(if($minLen -ge 14){"Pass"}elseif($minLen -ge 8){"Warning"}else{"Fail"}) `
        -Expected "14" -Actual "$minLen" -Severity $(if($minLen -lt 8){"Critical"}else{"High"}) `
        -POCResult $poc -Remediation "GPO: Minimum password length = 14"

    # Complexity - export secpol
    $secpolWorked = $false
    try {
        $tmpInf = Join-Path $env:TEMP "$Script:POCTag.inf"
        $secResult = secedit /export /cfg $tmpInf /areas SECURITYPOLICY 2>&1
        if ((Test-Path $tmpInf) -and (Get-Item $tmpInf -ErrorAction SilentlyContinue).Length -gt 100) {
            $secpol = Get-Content $tmpInf -ErrorAction Stop
            Remove-Item $tmpInf -Force -ErrorAction SilentlyContinue
            $secpolWorked = $true

        $complexity = if ($secpol -match "PasswordComplexity\s*=\s*(\d+)") { [int]$Matches[1] } else { 0 }
        $reversible = if ($secpol -match "ClearTextPassword\s*=\s*(\d+)") { [int]$Matches[1] } else { 0 }

        Add-Finding -Category "Account Policies" -CheckTitle "Password complexity" -CISRef "1.1.5" `
            -Status $(if($complexity -eq 1){"Pass"}else{"Fail"}) -Expected "1 (Enabled)" `
            -Actual $complexity -Severity "High" -Remediation "GPO: Password must meet complexity = Enabled" `
            -POCResult "secedit export: PasswordComplexity=$complexity"

        Add-Finding -Category "Account Policies" -CheckTitle "Reversible encryption" -CISRef "1.1.6" `
            -Status $(if($reversible -eq 0){"Pass"}else{"Fail"}) -Expected "0 (Disabled)" `
            -Actual $reversible -Severity "Critical" -Remediation "GPO: Store passwords using reversible encryption = Disabled" `
            -ExploitCmd $(if($reversible -eq 1){"Plaintext passwords extractable from AD"}else{""})

        # Lockout
        $lockDur = if ($secpol -match "LockoutDuration\s*=\s*(\d+)") { [int]$Matches[1] } else { 0 }
        $lockWin = if ($secpol -match "ResetLockoutCount\s*=\s*(\d+)") { [int]$Matches[1] } else { 0 }
        $lockThr = if ($secpol -match "LockoutBadCount\s*=\s*(\d+)") { [int]$Matches[1] } else { 0 }

        Add-Finding -Category "Account Policies" -CheckTitle "Account lockout duration" -CISRef "1.2.1" `
            -Status $(if($lockDur -ge 15){"Pass"}else{"Fail"}) -Expected "15+ min" `
            -Actual "$lockDur min" -Severity "High" -Remediation "GPO: Account lockout duration = 15"

        Add-Finding -Category "Account Policies" -CheckTitle "Account lockout threshold" -CISRef "1.2.2" `
            -Status $(if($lockThr -gt 0 -and $lockThr -le 5){"Pass"}elseif($lockThr -gt 5){"Warning"}else{"Fail"}) `
            -Expected "5 or fewer" -Actual $(if($lockThr -eq 0){"Never"}else{$lockThr}) -Severity "High" `
            -Remediation "GPO: Account lockout threshold = 5" `
            -ExploitCmd $(if($lockThr -eq 0){"Unlimited brute force without lockout"}else{""})

        Add-Finding -Category "Account Policies" -CheckTitle "Reset lockout counter" -CISRef "1.2.3" `
            -Status $(if($lockWin -ge 15){"Pass"}else{"Fail"}) -Expected "15+ min" `
            -Actual "$lockWin min" -Severity "Medium" -Remediation "GPO: Reset account lockout counter after = 15"

        # Admin/Guest account rename
        $adminRenamed = if ($secpol -match 'NewAdministratorName\s*=\s*"(.+?)"') { $Matches[1] } else { "Administrator" }
        $guestRenamed = if ($secpol -match 'NewGuestName\s*=\s*"(.+?)"') { $Matches[1] } else { "Guest" }

        Add-Finding -Category "Account Policies" -CheckTitle "Administrator account renamed" -CISRef "2.3.1.5" `
            -Status $(if($adminRenamed -ne "Administrator"){"Pass"}else{"Fail"}) `
            -Expected "Not 'Administrator'" -Actual $adminRenamed -Severity "Medium" `
            -Remediation "Rename the built-in Administrator account."

        Add-Finding -Category "Account Policies" -CheckTitle "Guest account renamed" -CISRef "2.3.1.6" `
            -Status $(if($guestRenamed -ne "Guest"){"Pass"}else{"Fail"}) `
            -Expected "Not 'Guest'" -Actual $guestRenamed -Severity "Low" `
            -Remediation "Rename the built-in Guest account."
        } else {
            Add-Finding -Category "Account Policies" -CheckTitle "Security policy export" -Status "Warning" `
                -Actual "secedit export produced empty/small file" -Severity "High" `
                -POCResult "secedit returned: $(($secResult|Out-String).Trim())" `
                -Remediation "Run from elevated admin cmd. Windows Home may have limited secedit."
        }
    } catch {
        Add-Finding -Category "Account Policies" -CheckTitle "Secedit export" -Status "Warning" `
            -Actual "secedit failed: $($_.Exception.Message)" -Severity "High" `
            -Remediation "Run from elevated admin cmd."
    }

    # Users with blank passwords
    try {
        $users = Get-LocalUser | Where-Object { $_.Enabled -and $_.PasswordRequired -eq $false }
        $poc = "Users with PasswordRequired=False: $(if($users){($users|ForEach-Object{$_.Name}) -join ', '}else{'None'})"
        Add-Finding -Category "Account Policies" -CheckTitle "Blank password accounts" `
            -Status $(if($users.Count -eq 0){"Pass"}else{"Fail"}) -Expected "0" `
            -Actual $(if($users.Count -eq 0){"None"}else{"$($users.Count): $(($users|ForEach-Object{$_.Name}) -join ', ')"}) `
            -Severity "Critical" -POCResult $poc `
            -Remediation "Set-LocalUser -Name USER -PasswordNotRequired `$false" `
            -ExploitCmd $(if($users.Count -gt 0){"runas /user:USERNAME cmd (blank pw)"}else{""})
    } catch {}
}


# ============================================================================
# 2. SECURITY OPTIONS (CIS 2.3.x)
# ============================================================================
function Test-SecurityOptions {
    Write-Section "Security Options (CIS 2.3.x)"

    # UAC
    $uacEnable = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" 1
    $uacConsent = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" 5
    $uacSecure = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" 1
    $uacInstall = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableInstallerDetection" 1
    $uacVirt = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableVirtualization" 1
    $uacBinary = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "FilterAdministratorToken" 0
    $poc = "EnableLUA=$uacEnable`nConsentPromptBehaviorAdmin=$uacConsent`nPromptOnSecureDesktop=$uacSecure`nEnableInstallerDetection=$uacInstall`nEnableVirtualization=$uacVirt`nFilterAdministratorToken=$uacBinary"

    Add-Finding -Category "Security Options" -CheckTitle "UAC: Admin Approval Mode" -CISRef "2.3.17.1" `
        -Status $(if($uacEnable -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $uacEnable `
        -Severity "Critical" -POCResult $poc -Remediation "GPO: UAC: Run all admins in Admin Approval Mode = Enabled"

    Add-Finding -Category "Security Options" -CheckTitle "UAC: Admin consent prompt" -CISRef "2.3.17.2" `
        -Status $(if($uacConsent -le 2){"Pass"}elseif($uacConsent -le 5){"Warning"}else{"Fail"}) `
        -Expected "2 (consent on secure desktop)" -Actual $uacConsent -Severity "High" `
        -Remediation "GPO: Behavior of elevation prompt for admins = Prompt for consent on secure desktop"

    Add-Finding -Category "Security Options" -CheckTitle "UAC: Secure desktop" -CISRef "2.3.17.7" `
        -Status $(if($uacSecure -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $uacSecure `
        -Severity "High" -Remediation "GPO: Switch to secure desktop when prompting = Enabled"

    Add-Finding -Category "Security Options" -CheckTitle "UAC: Built-in admin token filter" -CISRef "2.3.17.3" `
        -Status $(if($uacBinary -eq 1){"Pass"}else{"Warning"}) -Expected "1" -Actual $uacBinary `
        -Severity "Medium" -Remediation "GPO: Admin Approval Mode for Built-in Admin = Enabled"

    # LAN Manager auth
    $lmLevel = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" 3
    Add-Finding -Category "Security Options" -CheckTitle "LAN Manager auth level" -CISRef "2.3.11.7" `
        -Status $(if($lmLevel -ge 5){"Pass"}elseif($lmLevel -ge 3){"Warning"}else{"Fail"}) `
        -Expected "5 (NTLMv2, refuse LM/NTLM)" -Actual "Level $lmLevel" `
        -Severity $(if($lmLevel -lt 3){"Critical"}else{"High"}) `
        -POCResult "LmCompatibilityLevel=$lmLevel (0=LM+NTLM...5=NTLMv2 only)" `
        -Remediation "GPO: Send NTLMv2 only. Refuse LM and NTLM." `
        -ExploitCmd $(if($lmLevel -lt 3){"LM/NTLM hashes crackable in seconds"}else{""})

    # Anonymous restrictions
    $restrictAnon = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous" 0
    $restrictAnonSAM = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM" 1
    $noEnum = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "everyoneincludesanonymous" 0

    Add-Finding -Category "Security Options" -CheckTitle "Restrict anonymous SAM enumeration" -CISRef "2.3.10.2" `
        -Status $(if($restrictAnonSAM -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $restrictAnonSAM `
        -Severity "High" -Remediation "GPO: Do not allow anonymous enumeration of SAM accounts = Enabled"

    Add-Finding -Category "Security Options" -CheckTitle "Restrict anonymous share/pipe access" -CISRef "2.3.10.3" `
        -Status $(if($restrictAnon -ge 1){"Pass"}else{"Fail"}) -Expected "1+" -Actual $restrictAnon `
        -Severity "Medium" -Remediation "GPO: Do not allow anonymous enumeration of SAM accounts and shares = Enabled"

    Add-Finding -Category "Security Options" -CheckTitle "Everyone includes Anonymous" -CISRef "2.3.10.5" `
        -Status $(if($noEnum -eq 0){"Pass"}else{"Fail"}) -Expected "0" -Actual $noEnum `
        -Severity "High" -Remediation "GPO: Let Everyone permissions apply to anonymous users = Disabled"

    # SMB signing
    $smbServerSign = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature" 0
    $smbClientSign = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" 0
    Add-Finding -Category "Security Options" -CheckTitle "SMB server signing" -CISRef "2.3.9.2" `
        -Status $(if($smbServerSign -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $smbServerSign `
        -Severity "High" -Remediation "GPO: Digitally sign communications (server always) = Enabled" `
        -ExploitCmd "ntlmrelayx.py (relay without signing)"
    Add-Finding -Category "Security Options" -CheckTitle "SMB client signing" -CISRef "2.3.9.1" `
        -Status $(if($smbClientSign -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $smbClientSign `
        -Severity "High" -Remediation "GPO: Digitally sign communications (client always) = Enabled"

    # LDAP signing
    $ldapSign = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" "LDAPClientIntegrity" 1
    Add-Finding -Category "Security Options" -CheckTitle "LDAP client signing" -CISRef "2.3.11.8" `
        -Status $(if($ldapSign -ge 1){"Pass"}else{"Fail"}) -Expected "1+" -Actual $ldapSign `
        -Severity "High" -Remediation "GPO: Network security: LDAP client signing requirements = Negotiate signing"

    # Remote SAM
    $remoteSAM = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictRemoteSAM"
    Add-Finding -Category "Security Options" -CheckTitle "Restrict Remote SAM" -CISRef "2.3.10.11" `
        -Status $(if($remoteSAM){"Pass"}else{"Warning"}) -Expected "Configured" `
        -Actual $(if($remoteSAM){$remoteSAM}else{"Not configured"}) -Severity "Medium" `
        -Remediation "GPO: Network access: Restrict clients allowed to make remote calls to SAM"

    # Null session pipes/shares
    $nullPipes = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "NullSessionPipes"
    $nullShares = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "NullSessionShares"
    Add-Finding -Category "Security Options" -CheckTitle "Null session pipes" -CISRef "2.3.10.8" `
        -Status $(if([string]::IsNullOrEmpty($nullPipes) -or $nullPipes.Count -eq 0){"Pass"}else{"Fail"}) `
        -Expected "Empty" -Actual $(if($nullPipes){"$($nullPipes.Count) pipes"}else{"Empty"}) `
        -Severity "Medium" -Remediation "GPO: Restrict null session access to named pipes = clear list"

    # Machine inactivity limit
    $inactivity = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs" 0
    Add-Finding -Category "Security Options" -CheckTitle "Machine inactivity limit" -CISRef "2.3.7.3" `
        -Status $(if($inactivity -gt 0 -and $inactivity -le 900){"Pass"}else{"Fail"}) `
        -Expected "900 sec (15 min)" -Actual $(if($inactivity -eq 0){"Not set"}else{"$inactivity sec"}) `
        -Severity "Medium" -Remediation "GPO: Interactive logon: Machine inactivity limit = 900"

    # AutoAdmin logon
    $autoLogon = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon" "0"
    $autoPass = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultPassword"
    Add-Finding -Category "Security Options" -CheckTitle "Auto admin logon" -CISRef "2.3.7.4" `
        -Status $(if($autoLogon -eq "0" -or $null -eq $autoLogon){"Pass"}else{"Fail"}) `
        -Expected "0 or not set" -Actual "AutoAdminLogon=$autoLogon$(if($autoPass){', PASSWORD SET!'})" `
        -Severity "Critical" -POCResult "AutoAdminLogon=$autoLogon`nDefaultPassword=$(if($autoPass){'SET (cleartext!)'}else{'Not set'})" `
        -Remediation "reg delete HKLM\...\Winlogon /v AutoAdminLogon /f" `
        -ExploitCmd $(if($autoPass){"reg query Winlogon for plaintext password"}else{""})
}


# ============================================================================
# 3. AUDIT POLICY (CIS 9.x)
# ============================================================================
function Test-AuditPolicy {
    Write-Section "Audit Policy (CIS 9.x)"

    $auditpol = auditpol /get /category:* 2>$null
    $poc = ($auditpol | Out-String).Trim()

    $checks = @(
        @{Cat="Account Logon";Sub="Credential Validation";CIS="17.1.1";Expect="Success and Failure"},
        @{Cat="Account Management";Sub="Security Group Management";CIS="17.2.5";Expect="Success"},
        @{Cat="Account Management";Sub="User Account Management";CIS="17.2.6";Expect="Success and Failure"},
        @{Cat="Detailed Tracking";Sub="Process Creation";CIS="17.3.1";Expect="Success"},
        @{Cat="Logon/Logoff";Sub="Logon";CIS="17.5.3";Expect="Success and Failure"},
        @{Cat="Logon/Logoff";Sub="Logoff";CIS="17.5.2";Expect="Success"},
        @{Cat="Logon/Logoff";Sub="Special Logon";CIS="17.5.6";Expect="Success"},
        @{Cat="Object Access";Sub="Removable Storage";CIS="17.6.4";Expect="Success and Failure"},
        @{Cat="Policy Change";Sub="Audit Policy Change";CIS="17.7.1";Expect="Success"},
        @{Cat="Policy Change";Sub="Authentication Policy Change";CIS="17.7.2";Expect="Success"},
        @{Cat="Privilege Use";Sub="Sensitive Privilege Use";CIS="17.8.1";Expect="Success and Failure"},
        @{Cat="System";Sub="Security State Change";CIS="17.9.3";Expect="Success"},
        @{Cat="System";Sub="Security System Extension";CIS="17.9.4";Expect="Success"},
        @{Cat="System";Sub="System Integrity";CIS="17.9.5";Expect="Success and Failure"}
    )

    foreach ($c in $checks) {
        $line = $auditpol | Select-String "^\s+$($c.Sub)\s" | Select-Object -First 1
        $actual = if ($line) { ($line -split "\s{2,}")[-1].Trim() } else { "Not found" }
        $pass = $actual -match "Success" -and ($c.Expect -notmatch "Failure" -or $actual -match "Failure")
        Add-Finding -Category "Audit Policy" -CheckTitle "$($c.Sub)" -CISRef $c.CIS `
            -Status $(if($pass){"Pass"}else{"Fail"}) -Expected $c.Expect -Actual $actual `
            -Severity $(if($c.Sub -match "Logon|Credential|Process"){"High"}else{"Medium"}) `
            -POCResult "auditpol: $($c.Sub) = $actual" `
            -Remediation "auditpol /set /subcategory:`"$($c.Sub)`" /success:enable $(if($c.Expect -match 'Failure'){'/failure:enable'})"
    }

    # Command line in process creation
    $cmdLine = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" 0
    Add-Finding -Category "Audit Policy" -CheckTitle "Command line in process events" -CISRef "18.9.3.1" `
        -Status $(if($cmdLine -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $cmdLine `
        -Severity "High" -POCResult "ProcessCreationIncludeCmdLine_Enabled=$cmdLine" `
        -Remediation "GPO: Include command line in process creation events = Enabled"
}


# ============================================================================
# 4. WINDOWS FIREWALL (CIS 9.x)
# ============================================================================
function Test-Firewall {
    Write-Section "Windows Firewall (CIS 9.x)"

    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($p in $profiles) {
            $poc = "$($p.Name): Enabled=$($p.Enabled) InDefault=$($p.DefaultInboundAction) OutDefault=$($p.DefaultOutboundAction) LogAllowed=$($p.LogAllowed) LogBlocked=$($p.LogBlocked) LogMax=$($p.LogMaxSizeKilobytes)"
            Add-Finding -Category "Windows Firewall" -CheckTitle "$($p.Name) profile enabled" -CISRef "9.$($p.Name).1" `
                -Status $(if($p.Enabled){"Pass"}else{"Fail"}) -Expected "True" -Actual $p.Enabled `
                -Severity "High" -POCResult $poc -Remediation "Set-NetFirewallProfile -Name $($p.Name) -Enabled True"

            Add-Finding -Category "Windows Firewall" -CheckTitle "$($p.Name) inbound default" -CISRef "9.$($p.Name).2" `
                -Status $(if($p.DefaultInboundAction -eq "Block"){"Pass"}else{"Fail"}) `
                -Expected "Block" -Actual $p.DefaultInboundAction -Severity "High" `
                -Remediation "Set-NetFirewallProfile -Name $($p.Name) -DefaultInboundAction Block"

            Add-Finding -Category "Windows Firewall" -CheckTitle "$($p.Name) firewall logging" `
                -Status $(if($p.LogBlocked -eq $true){"Pass"}else{"Fail"}) -Expected "Log blocked = True" `
                -Actual "LogBlocked=$($p.LogBlocked), Size=$($p.LogMaxSizeKilobytes)KB" `
                -Severity "Medium" -Remediation "Set-NetFirewallProfile -Name $($p.Name) -LogBlocked True -LogMaxSizeKilobytes 16384"
        }
    } catch { Add-Finding -Category "Windows Firewall" -CheckTitle "Firewall query" -Status "Error" -Actual "$_" -Severity "High" }
}


# ============================================================================
# 5. WINDOWS DEFENDER (CIS 18.x)
# ============================================================================
function Test-DefenderConfig {
    Write-Section "Windows Defender (CIS 18.x)"

    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $pref = Get-MpPreference -ErrorAction Stop
        $poc = "RealTime=$($mp.RealTimeProtectionEnabled)`nBehaviorMonitor=$($mp.BehaviorMonitorEnabled)`nIOAV=$($mp.IoavProtectionEnabled)`nTamper=$($mp.IsTamperProtected)`nNIS=$($mp.NISEnabled)`nSigAge=$($mp.AntivirusSignatureAge) days`nEngine=$($mp.AMEngineVersion)`nCloudBlock=$($pref.MAPSReporting)`nPUA=$($pref.PUAProtection)`nASR=$(if($pref.AttackSurfaceReductionRules_Actions){$pref.AttackSurfaceReductionRules_Actions -join ','}else{'None'})"

        Add-Finding -Category "Windows Defender" -CheckTitle "Real-time protection" -CISRef "18.10.43.10.1" `
            -Status $(if($mp.RealTimeProtectionEnabled){"Pass"}else{"Fail"}) -Expected "Enabled" `
            -Actual $(if($mp.RealTimeProtectionEnabled){"On"}else{"OFF"}) -Severity "Critical" `
            -POCResult $poc -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false"

        Add-Finding -Category "Windows Defender" -CheckTitle "Behavior monitoring" -CISRef "18.10.43.10.2" `
            -Status $(if($mp.BehaviorMonitorEnabled){"Pass"}else{"Fail"}) -Expected "Enabled" `
            -Actual $(if($mp.BehaviorMonitorEnabled){"On"}else{"OFF"}) -Severity "High" `
            -Remediation "Set-MpPreference -DisableBehaviorMonitoring `$false"

        Add-Finding -Category "Windows Defender" -CheckTitle "Tamper protection" `
            -Status $(if($mp.IsTamperProtected){"Pass"}else{"Fail"}) -Expected "Enabled" `
            -Actual $(if($mp.IsTamperProtected){"On"}else{"OFF"}) -Severity "High" `
            -Remediation "Enable via Windows Security UI."

        Add-Finding -Category "Windows Defender" -CheckTitle "Signature age" `
            -Status $(if($mp.AntivirusSignatureAge -le 3){"Pass"}elseif($mp.AntivirusSignatureAge -le 7){"Warning"}else{"Fail"}) `
            -Expected "3 days" -Actual "$($mp.AntivirusSignatureAge) days" `
            -Severity $(if($mp.AntivirusSignatureAge -gt 7){"High"}else{"Medium"}) `
            -Remediation "Update-MpSignature"

        Add-Finding -Category "Windows Defender" -CheckTitle "Cloud-delivered protection (MAPS)" -CISRef "18.10.43.5.1" `
            -Status $(if($pref.MAPSReporting -ge 2){"Pass"}else{"Warning"}) -Expected "2 (Advanced)" `
            -Actual $pref.MAPSReporting -Severity "Medium" `
            -Remediation "Set-MpPreference -MAPSReporting Advanced"

        Add-Finding -Category "Windows Defender" -CheckTitle "PUA protection" -CISRef "18.10.43.10" `
            -Status $(if($pref.PUAProtection -eq 1){"Pass"}else{"Warning"}) -Expected "1 (Enabled)" `
            -Actual $pref.PUAProtection -Severity "Medium" `
            -Remediation "Set-MpPreference -PUAProtection Enabled"

        # Exclusions
        $allExc = @()
        if ($pref.ExclusionPath) { $allExc += $pref.ExclusionPath | ForEach-Object { "Path: $_" } }
        if ($pref.ExclusionProcess) { $allExc += $pref.ExclusionProcess | ForEach-Object { "Proc: $_" } }
        if ($pref.ExclusionExtension) { $allExc += $pref.ExclusionExtension | ForEach-Object { "Ext: $_" } }
        Add-Finding -Category "Windows Defender" -CheckTitle "Exclusions" `
            -Status $(if($allExc.Count -eq 0){"Pass"}elseif($allExc.Count -le 3){"Warning"}else{"Fail"}) `
            -Expected "Minimal" -Actual "$($allExc.Count) exclusions" `
            -Severity $(if($allExc.Count -gt 5){"High"}else{"Medium"}) `
            -POCResult "Exclusions:`n$(if($allExc.Count -gt 0){$allExc -join "`n"}else{'None'})" `
            -Remediation "Remove unnecessary exclusions." `
            -ExploitCmd $(if($allExc.Count -gt 0){"Drop payload in excluded path/process"}else{""})

        # ASR rules
        $asrActions = $pref.AttackSurfaceReductionRules_Actions
        $asrCount = if ($asrActions) { ($asrActions | Where-Object { $_ -ge 1 }).Count } else { 0 }
        Add-Finding -Category "Windows Defender" -CheckTitle "Attack Surface Reduction rules" -CISRef "18.10.43.6" `
            -Status $(if($asrCount -ge 5){"Pass"}elseif($asrCount -ge 1){"Warning"}else{"Fail"}) `
            -Expected "5+ rules enforced" -Actual "$asrCount rules active" -Severity "High" `
            -Remediation "Deploy ASR rules via Intune/GPO." -Description "ASR blocks common exploit techniques."
    } catch {
        Add-Finding -Category "Windows Defender" -CheckTitle "Defender status" -Status "Warning" -Actual "Cannot query: $_" -Severity "Critical"
    }
}


# ============================================================================
# 6. CREDENTIAL PROTECTION
# ============================================================================
function Test-CredentialProtection {
    Write-Section "Credential Protection"

    # LSASS PPL
    $runAsPPL = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
    $pplMap = @{0="Disabled";1="Enabled";2="Enabled with UEFI lock (strongest)"}
    $pplOK = $runAsPPL -eq 1 -or $runAsPPL -eq 2
    Add-Finding -Category "Credential Protection" -CheckTitle "LSASS RunAsPPL" -CISRef "18.4.7" `
        -Status $(if($pplOK){"Pass"}else{"Fail"}) -Expected "1 or 2" `
        -Actual $(if($pplOK){"Protected ($($pplMap[[int]$runAsPPL]))"}else{"Unprotected"}) -Severity "Critical" `
        -POCResult "RunAsPPL=$(if($null -eq $runAsPPL){'Not set'}else{"$runAsPPL ($($pplMap[[int]$runAsPPL]))"}) `nValues: 0=Off, 1=On, 2=On+UEFI lock" `
        -Remediation "reg add HKLM\SYSTEM\...\Lsa /v RunAsPPL /t REG_DWORD /d 2" `
        -ExploitCmd $(if(-not $pplOK){"mimikatz # sekurlsa::logonpasswords"}else{""})

    # WDigest
    $wdigest = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"
    Add-Finding -Category "Credential Protection" -CheckTitle "WDigest plaintext" -CISRef "18.4.8" `
        -Status $(if($wdigest -eq 1){"Fail"}else{"Pass"}) -Expected "0 or not set" `
        -Actual $(if($wdigest -eq 1){"ENABLED"}elseif($null -eq $wdigest){"Default (disabled)"}else{$wdigest}) `
        -Severity "Critical" -Remediation "reg add ...\WDigest /v UseLogonCredential /d 0" `
        -ExploitCmd $(if($wdigest -eq 1){"mimikatz # sekurlsa::wdigest (plaintext!)"}else{""})

    # Credential Guard
    $credGuard = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\LSA" "LsaCfgFlags"
    $vbs = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity"
    Add-Finding -Category "Credential Protection" -CheckTitle "Credential Guard" -CISRef "18.4.1" `
        -Status $(if($credGuard -ge 1){"Pass"}else{"Fail"}) -Expected "1+" `
        -Actual $(if($credGuard -ge 1){"Enabled ($credGuard)"}else{"Not configured"}) -Severity "High" `
        -POCResult "LsaCfgFlags=$credGuard VBS=$vbs" -Remediation "GPO: Enable Credential Guard with UEFI lock."

    Add-Finding -Category "Credential Protection" -CheckTitle "VBS" `
        -Status $(if($vbs -eq 1){"Pass"}else{"Warning"}) -Expected "1" `
        -Actual $(if($null -eq $vbs){"Not set"}else{$vbs}) -Severity "Medium" `
        -Remediation "GPO: Enable Virtualization Based Security."

    # Cached logons
    $cached = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount" "10"
    Add-Finding -Category "Credential Protection" -CheckTitle "Cached logon count" -CISRef "2.3.7.5" `
        -Status $(if([int]$cached -le 4){"Pass"}else{"Warning"}) -Expected "4 or fewer (CIS=4)" `
        -Actual "$cached" -Severity "Medium" -POCResult "CachedLogonsCount=$cached" `
        -Remediation "GPO: Number of previous logons to cache = 4"

    # DPAPI backup key
    try {
        $dpapi = Get-ChildItem "C:\Windows\System32\Microsoft\Protect" -Recurse -ErrorAction SilentlyContinue
        Add-Finding -Category "Credential Protection" -CheckTitle "DPAPI system keys" -Status "Info" `
            -Actual "$($dpapi.Count) DPAPI files" -Severity "Informational" `
            -POCResult "System DPAPI location accessible. Count=$($dpapi.Count)" `
            -Remediation "Enable Credential Guard to protect DPAPI."
    } catch {}
}


# ============================================================================
# 7. NETWORK HARDENING
# ============================================================================
function Test-NetworkHardening {
    Write-Section "Network Hardening"

    # LLMNR
    $llmnr = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" 1
    Add-Finding -Category "Network Hardening" -CheckTitle "LLMNR" -CISRef "18.6.4.1" `
        -Status $(if($llmnr -eq 0){"Pass"}else{"Fail"}) -Expected "0" -Actual $llmnr `
        -Severity "High" -Remediation "GPO: Turn off multicast name resolution = Enabled" `
        -ExploitCmd "Responder -I eth0 (capture NTLMv2)"

    # NetBIOS
    try {
        $nics = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -ErrorAction SilentlyContinue
        $nbtEnabled = $false
        foreach ($n in $nics) { $v = Get-ItemProperty $n.PSPath -Name "NetbiosOptions" -ErrorAction SilentlyContinue
            if ($null -eq $v -or $v.NetbiosOptions -ne 2) { $nbtEnabled = $true; break } }
        Add-Finding -Category "Network Hardening" -CheckTitle "NetBIOS over TCP/IP" `
            -Status $(if(-not $nbtEnabled){"Pass"}else{"Warning"}) -Expected "Disabled (2)" `
            -Actual $(if($nbtEnabled){"Enabled"}else{"Disabled"}) -Severity "Medium" `
            -Remediation "Disable NetBIOS on all NICs." -ExploitCmd "Responder NBT-NS poisoning"
    } catch {}

    # WPAD
    $wpad = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" "Start" 4
    Add-Finding -Category "Network Hardening" -CheckTitle "WPAD service" `
        -Status $(if($wpad -eq 4){"Pass"}else{"Warning"}) -Expected "4 (Disabled)" `
        -Actual $wpad -Severity "Medium" -Remediation "Disable WinHTTP Auto-Proxy service." `
        -ExploitCmd "Responder WPAD poisoning for credential capture"

    # WinRM
    try { $winrm = Get-Service WinRM -ErrorAction SilentlyContinue
        Add-Finding -Category "Network Hardening" -CheckTitle "WinRM" `
            -Status $(if($winrm.Status -ne "Running"){"Pass"}else{"Warning"}) `
            -Expected "Stopped (workstations)" -Actual $winrm.Status -Severity "Medium" `
            -Remediation "Stop-Service WinRM; Set-Service WinRM -StartupType Disabled"
    } catch {}

    # RDP settings
    $rdpDeny = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" 1
    $rdpNLA = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication" 1
    $rdpEncrypt = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "MinEncryptionLevel" 3
    Add-Finding -Category "Network Hardening" -CheckTitle "RDP NLA" -CISRef "18.10.57.3.9.1" `
        -Status $(if($rdpDeny -eq 1 -or $rdpNLA -eq 1){"Pass"}else{"Fail"}) -Expected "NLA required" `
        -Actual "RDP=$(if($rdpDeny -eq 0){'On'}else{'Off'}), NLA=$(if($rdpNLA){'Yes'}else{'No'})" -Severity "High" `
        -POCResult "fDenyTSConnections=$rdpDeny UserAuthentication=$rdpNLA MinEncryption=$rdpEncrypt" `
        -Remediation "GPO: Require NLA for Remote Desktop connections"

    Add-Finding -Category "Network Hardening" -CheckTitle "RDP encryption level" -CISRef "18.10.57.3.9.2" `
        -Status $(if($rdpEncrypt -ge 3){"Pass"}else{"Warning"}) -Expected "3 (High)" `
        -Actual $(if($null -eq $rdpEncrypt){"Not set"}else{$rdpEncrypt}) -Severity "Medium" `
        -Remediation "GPO: Set RDP Encryption Level to High"

    # Listening services
    try {
        $l = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalAddress -ne "127.0.0.1" -and $_.LocalAddress -ne "::1" } | Sort-Object LocalPort -Unique
        $poc = ($l|Select-Object -First 20|ForEach-Object{ $p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; "$($_.LocalPort)/$($p.ProcessName)" }) -join ", "
        Add-Finding -Category "Network Hardening" -CheckTitle "Exposed services" -Status "Info" `
            -Actual "$($l.Count) ports: $poc" -Severity "Informational" `
            -POCResult ($l|Select-Object -First 20|ForEach-Object{$p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue;"  $($_.LocalAddress):$($_.LocalPort) $($p.ProcessName)"}) -join "`n" `
            -Remediation "Disable unnecessary services."
    } catch {}
}


# ============================================================================
# 8. SYSTEM HARDENING (CIS 18.x)
# ============================================================================
function Test-SystemHardening {
    Write-Section "System Hardening (CIS 18.x)"

    # Secure Boot
    try { $sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        Add-Finding -Category "System Hardening" -CheckTitle "Secure Boot" `
            -Status $(if($sb){"Pass"}else{"Fail"}) -Expected "Enabled" `
            -Actual $(if($sb){"On"}else{"Off"}) -Severity "High" -Remediation "Enable in UEFI/BIOS."
    } catch { Add-Finding -Category "System Hardening" -CheckTitle "Secure Boot" -Status "Info" -Actual "Cannot query" -Severity "High" }

    # BitLocker
    try { $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
        $poc = "C: Status=$($bl.ProtectionStatus) Method=$($bl.EncryptionMethod) KeyProtectors=$(($bl.KeyProtector|ForEach-Object{$_.KeyProtectorType}) -join ',')"
        Add-Finding -Category "System Hardening" -CheckTitle "BitLocker C:" -CISRef "18.10.9.1" `
            -Status $(if($bl.ProtectionStatus -eq "On"){"Pass"}else{"Fail"}) -Expected "On" `
            -Actual "$($bl.ProtectionStatus) ($($bl.EncryptionMethod))" -Severity "High" -POCResult $poc `
            -Remediation "Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256"
    } catch { Add-Finding -Category "System Hardening" -CheckTitle "BitLocker" -Status "Warning" -Actual "Cannot query" -Severity "High" }

    # DEP
    try { $dep = (Get-CimInstance Win32_OperatingSystem).DataExecutionPrevention_SupportPolicy
        $m = @{0="Off";1="Essential";2="OptOut";3="AlwaysOn"}
        Add-Finding -Category "System Hardening" -CheckTitle "DEP/NX" `
            -Status $(if($dep -ge 2){"Pass"}else{"Warning"}) -Expected "2+" -Actual "$dep ($($m[[int]$dep]))" `
            -Severity "Medium" -Remediation "bcdedit /set nx AlwaysOn"
    } catch {}

    # ASLR
    $aslr = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "MoveImages" 1
    Add-Finding -Category "System Hardening" -CheckTitle "ASLR" `
        -Status $(if($aslr -ne 0){"Pass"}else{"Fail"}) -Expected "Enabled (not 0)" `
        -Actual $(if($null -eq $aslr){"Default (enabled)"}else{$aslr}) -Severity "Medium"

    # Spectre/Meltdown
    $specCtrl = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverride"
    Add-Finding -Category "System Hardening" -CheckTitle "Spectre mitigations" `
        -Status $(if($null -ne $specCtrl){"Pass"}else{"Warning"}) -Expected "Configured" `
        -Actual $(if($null -eq $specCtrl){"Not set"}else{$specCtrl}) -Severity "Medium" `
        -Remediation "Apply all patches. Configure per Microsoft guidance."

    # PowerShell v2
    try { $psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop
        $psv2State = if ($psv2.State) { $psv2.State.ToString() } else { "Unknown" }
        $psv2Disabled = $psv2State -eq "Disabled" -or $psv2State -eq "DisabledWithPayloadRemoved"
        Add-Finding -Category "System Hardening" -CheckTitle "PowerShell v2" -CISRef "18.10.40.1" `
            -Status $(if($psv2Disabled){"Pass"}else{"Fail"}) -Expected "Disabled" `
            -Actual $(if($psv2Disabled){$psv2State}else{if($psv2State -eq "Unknown"){"Enabled (feature present)"}else{$psv2State}}) -Severity "High" `
            -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root" `
            -ExploitCmd "powershell -version 2 (bypasses ScriptBlock logging and AMSI)" `
            -Description "PSv2 bypasses all modern PowerShell security."
    } catch {}

    # PowerShell logging
    $sbLog = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" 0
    $trans = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting" 0
    $modLog = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging" 0
    $score = ([int]($sbLog -eq 1)) + ([int]($trans -eq 1)) + ([int]($modLog -eq 1))
    Add-Finding -Category "System Hardening" -CheckTitle "PowerShell logging" -CISRef "18.10.40.2" `
        -Status $(if($score -ge 2){"Pass"}elseif($score -eq 1){"Warning"}else{"Fail"}) `
        -Expected "All 3" -Actual "Score=$score/3 (SB=$sbLog Trans=$trans Mod=$modLog)" -Severity "High" `
        -POCResult "ScriptBlock=$sbLog Transcription=$trans Module=$modLog" `
        -Remediation "GPO: Enable all 3 PS logging types."

    # Sysmon
    try { $sys = Get-Service Sysmon* -ErrorAction SilentlyContinue | Where-Object Status -eq "Running"
        Add-Finding -Category "System Hardening" -CheckTitle "Sysmon" `
            -Status $(if($sys){"Pass"}else{"Warning"}) -Expected "Running" `
            -Actual $(if($sys){"Running: $($sys.Name)"}else{"Not installed"}) -Severity "Medium" `
            -Remediation "Install Sysmon with SwiftOnSecurity config."
    } catch {}

    # Event log sizes
    foreach ($log in @(
        @{N="Security";Min=1024000;CIS="18.9.27.2.1"},
        @{N="Application";Min=32768;CIS="18.9.27.1.1"},
        @{N="System";Min=32768;CIS="18.9.27.3.1"}
    )) {
        try { $el = Get-WinEvent -ListLog $log.N -ErrorAction Stop
            Add-Finding -Category "System Hardening" -CheckTitle "$($log.N) log max size" -CISRef $log.CIS `
                -Status $(if($el.MaximumSizeInBytes -ge $log.Min){"Pass"}else{"Fail"}) `
                -Expected "$([math]::Round($log.Min/1024))KB" `
                -Actual "$([math]::Round($el.MaximumSizeInBytes/1024))KB" -Severity "Medium" `
                -Remediation "wevtutil sl $($log.N) /ms:$($log.Min)"
        } catch {}
    }

    # Hotfix status
    try { $hf = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending
        $latest = $hf | Select-Object -First 1
        $days = if ($latest.InstalledOn) { ((Get-Date) - $latest.InstalledOn).Days } else { 999 }
        $poc = "Total: $($hf.Count) | Latest: $($latest.HotFixID) ($days days ago)`n$(($hf|Select-Object -First 5|ForEach-Object{"  $($_.HotFixID) $($_.InstalledOn)"}) -join "`n")"
        Add-Finding -Category "System Hardening" -CheckTitle "Windows Update status" `
            -Status $(if($days -le 30){"Pass"}elseif($days -le 90){"Warning"}else{"Fail"}) `
            -Expected "30 days" -Actual "$days days since last update" `
            -Severity $(if($days -gt 90){"Critical"}else{"Medium"}) -POCResult $poc `
            -Remediation "Install all pending updates."
    } catch {}
}


# ============================================================================
# 9. APPLICATION CONTROL
# ============================================================================
function Test-ApplicationControl {
    Write-Section "Application Control"

    # AppLocker
    try { $ap = Get-AppLockerPolicy -Effective -ErrorAction Stop
        $rc = ($ap.RuleCollections | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
        $poc = "Rule collections:`n$(($ap.RuleCollections | ForEach-Object { "  $($_.RuleCollectionType): $($_.Count) rules" }) -join "`n")"
        Add-Finding -Category "Application Control" -CheckTitle "AppLocker" `
            -Status $(if($rc -gt 0){"Pass"}else{"Fail"}) -Expected "Rules configured" `
            -Actual $(if($rc -gt 0){"$rc rules"}else{"None"}) -Severity "High" -POCResult $poc `
            -Remediation "Deploy AppLocker via GPO."
    } catch {
        Add-Finding -Category "Application Control" -CheckTitle "AppLocker" -Status "Fail" `
            -Expected "Rules in effect" -Actual "Not configured" -Severity "High" `
            -Remediation "Deploy AppLocker default rules." -ExploitCmd "Any EXE from any writable path."
    }

    # WDAC
    try { $wdac = Get-CimInstance -Namespace root/Microsoft/Windows/CI -ClassName MSFT_SIPolicy -ErrorAction SilentlyContinue
        Add-Finding -Category "Application Control" -CheckTitle "WDAC" `
            -Status $(if($wdac){"Pass"}else{"Warning"}) -Expected "Active" `
            -Actual $(if($wdac){"Active"}else{"Not deployed"}) -Severity "Medium" `
            -Remediation "Deploy WDAC base policy."
    } catch {}

    # Execution policy
    $ep = Get-ExecutionPolicy -Scope LocalMachine -ErrorAction SilentlyContinue
    Add-Finding -Category "Application Control" -CheckTitle "PS Execution Policy" `
        -Status $(if($ep -in @("Restricted","AllSigned")){"Pass"}else{"Warning"}) `
        -Expected "AllSigned" -Actual $ep -Severity "Medium" `
        -POCResult "Machine: $ep`n$((Get-ExecutionPolicy -List|Out-String).Trim())" `
        -Remediation "Set-ExecutionPolicy AllSigned"

    # WSL
    $wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
    Add-Finding -Category "Application Control" -CheckTitle "WSL" `
        -Status $(if($wsl){"Warning"}else{"Pass"}) -Expected "Not installed" `
        -Actual $(if($wsl){"Installed"}else{"No"}) -Severity "Medium" `
        -Remediation "dism /online /disable-feature /featurename:Microsoft-Windows-Subsystem-Linux" `
        -ExploitCmd "WSL bypasses AppLocker/AMSI/AV"
}

# ============================================================================
# 10. SERVICE SECURITY
# ============================================================================
function Test-ServiceSecurity {
    Write-Section "Service Security"
    $dq = [string][char]34

    # Writable binaries
    try {
        $vuln = @(); $svcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -and $_.State -eq "Running" }
        foreach ($s in $svcs | Select-Object -First 80) {
            $p = $s.PathName -replace $dq,''
            if ($p -match '^([a-zA-Z]:\\.+?\.(exe|dll))') { $ep = $Matches[1]
                if (Test-Path $ep) { $a = Get-Acl $ep -ErrorAction SilentlyContinue
                    if ($a) { $w = $a.Access | Where-Object { $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                        $_.FileSystemRights -match "(Write|Modify|FullControl)" }; if ($w) { $vuln += "$($s.Name): $ep" } } } } }
        $poc = "Scanned $($svcs.Count) services (80 sampled).`n$(if($vuln.Count -gt 0){($vuln -join "`n")}else{'None writable.'})"
        Add-Finding -Category "Service Security" -CheckTitle "Writable service binaries" `
            -Status $(if($vuln.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($vuln.Count -eq 0){"None"}else{"$($vuln.Count): $(($vuln|Select-Object -First 5) -join '; ')"}) `
            -Severity "Critical" -POCResult $poc -Remediation "icacls BINARY /reset" `
            -ExploitCmd "copy payload.exe BINARY; sc stop/start SVC"
    } catch {}

    # Unquoted paths
    try { $uq = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
            $_.PathName -and $_.PathName -notmatch ('^\s*' + $dq) -and $_.PathName -match '\s' -and $_.PathName -notmatch '^[a-zA-Z]:\\Windows\\' }
        Add-Finding -Category "Service Security" -CheckTitle "Unquoted service paths" `
            -Status $(if($uq.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($uq.Count -eq 0){"None"}else{"$($uq.Count)"}) -Severity "High" `
            -POCResult $(if($uq.Count -gt 0){($uq|Select-Object -First 5|ForEach-Object{"$($_.Name): $($_.PathName)"}) -join "`n"}else{""}) `
            -Remediation "Quote service paths." -ExploitCmd "copy payload.exe C:\Program.exe"
    } catch {}

    # AlwaysInstallElevated
    $aieHKCU = Get-RegValue "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
    $aieHKLM = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
    $aieVuln = $aieHKCU -eq 1 -and $aieHKLM -eq 1
    Add-Finding -Category "Service Security" -CheckTitle "AlwaysInstallElevated" `
        -Status $(if($aieVuln){"Fail"}else{"Pass"}) -Expected "Not 1 in both" `
        -Actual "HKLM=$(if($null -eq $aieHKLM){'N/A'}else{$aieHKLM}), HKCU=$(if($null -eq $aieHKCU){'N/A'}else{$aieHKCU})" `
        -Severity "Critical" -Remediation "Set both to 0." `
        -ExploitCmd $(if($aieVuln){"msfvenom -f msi > evil.msi; msiexec /quiet /i evil.msi"}else{""})

    # Print Spooler
    try { $sp = Get-Service Spooler -ErrorAction SilentlyContinue
        Add-Finding -Category "Service Security" -CheckTitle "Print Spooler" -CISRef "5.36" `
            -Status $(if($sp.Status -ne "Running"){"Pass"}else{"Fail"}) -Expected "Stopped" `
            -Actual $sp.Status -Severity "High" `
            -Remediation "Stop-Service Spooler; Set-Service Spooler -StartupType Disabled" `
            -ExploitCmd "PrintNightmare / PrintSpoofer.exe"
    } catch {}

    # Remote Registry
    try { $rr = Get-Service RemoteRegistry -ErrorAction SilentlyContinue
        Add-Finding -Category "Service Security" -CheckTitle "Remote Registry" -CISRef "5.27" `
            -Status $(if($rr.Status -ne "Running" -and $rr.StartType -eq "Disabled"){"Pass"}else{"Fail"}) `
            -Expected "Disabled" -Actual "Status=$($rr.Status), Start=$($rr.StartType)" -Severity "Medium" `
            -Remediation "Set-Service RemoteRegistry -StartupType Disabled"
    } catch {}

    # SMBv1
    $smbv1Client = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start" 4
    $smbv1Server = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1" 1
    $smbv1Enabled = $smbv1Client -ne 4 -or $smbv1Server -eq 1
    Add-Finding -Category "Service Security" -CheckTitle "SMBv1 protocol" -CISRef "18.4.9" `
        -Status $(if(-not $smbv1Enabled){"Pass"}else{"Fail"}) -Expected "Disabled" `
        -Actual "Client=$(if($smbv1Client -eq 4){'Disabled'}else{'Enabled'}), Server=$(if($smbv1Server -eq 0){'Disabled'}else{'Enabled/Default'})" `
        -Severity "Critical" -POCResult "mrxsmb10 Start=$smbv1Client (4=disabled), SMB1=$smbv1Server (0=disabled)" `
        -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol" `
        -ExploitCmd $(if($smbv1Enabled){"EternalBlue/WannaCry (MS17-010)"}else{""})

    # Remote access tools
    $rmmTools = @()
    $rmmProcs = @("AnyDesk","TeamViewer","TeamViewer_Service","vncserver","rustdesk","ScreenConnect","ConnectWise","LogMeIn")
    foreach ($rp in $rmmProcs) { $p = Get-Process -Name $rp -ErrorAction SilentlyContinue; if ($p) { $rmmTools += "$rp (PID: $(($p|ForEach-Object{$_.Id}) -join ','))" } }
    $rmmSvcs = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match "(AnyDesk|TeamViewer|VNC|RustDesk|ScreenConnect)" -and $_.Status -eq "Running" }
    foreach ($rs in $rmmSvcs) { $rmmTools += "$($rs.DisplayName) (svc)" }
    Add-Finding -Category "Service Security" -CheckTitle "Remote access tools (RMM)" `
        -Status $(if($rmmTools.Count -eq 0){"Pass"}else{"Warning"}) -Expected "None or approved" `
        -Actual $(if($rmmTools.Count -eq 0){"None"}else{"$($rmmTools.Count): $($rmmTools -join ', ')"}) `
        -Severity $(if($rmmTools.Count -gt 0){"High"}else{"Medium"}) `
        -POCResult "RMM: $(if($rmmTools.Count -gt 0){$rmmTools -join "`n"}else{'None'})" `
        -Remediation "Remove unapproved RMM tools." `
        -Description "RMM tools provide persistent remote access."

    # Accessibility hijack
    $accessHijack = @()
    foreach ($tool in @("sethc.exe","utilman.exe","narrator.exe","magnify.exe","osk.exe")) {
        $ifeo = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$tool" "Debugger"
        if ($ifeo) { $accessHijack += "$tool IFEO=$ifeo" }
        $fp = "C:\Windows\System32\$tool"
        if (Test-Path $fp) { $fi = Get-Item $fp -ErrorAction SilentlyContinue
            if ($fi -and $fi.VersionInfo.CompanyName -notmatch "Microsoft") { $accessHijack += "$tool NOT Microsoft!" } }
    }
    Add-Finding -Category "Service Security" -CheckTitle "Accessibility tool hijacking" `
        -Status $(if($accessHijack.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
        -Actual $(if($accessHijack.Count -eq 0){"Clean"}else{$accessHijack -join '; '}) `
        -Severity "Critical" -Remediation "Restore originals. Remove IFEO debuggers." `
        -ExploitCmd $(if($accessHijack.Count -gt 0){"Shift 5x at login = SYSTEM shell"}else{""})
}


# ============================================================================
# 11. PERSISTENCE VECTORS
# ============================================================================
function Test-PersistenceVectors {
    Write-Section "Persistence Vectors"

    # HKLM Run
    $writableHKLM = @()
    foreach ($k in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")) {
        if (Test-Path $k) { try { $a = Get-Acl $k -ErrorAction Stop
            $w = $a.Access | Where-Object { $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                $_.RegistryRights -match "(WriteKey|SetValue|FullControl)" -and $_.AccessControlType -eq "Allow" }
            if ($w) { $writableHKLM += $k }
        } catch {} } }
    Add-Finding -Category "Persistence Vectors" -CheckTitle "HKLM Run writable by Users" `
        -Status $(if($writableHKLM.Count -eq 0){"Pass"}else{"Fail"}) -Expected "Restricted" `
        -Actual $(if($writableHKLM.Count -eq 0){"Properly restricted"}else{"$($writableHKLM.Count) writable"}) `
        -Severity "Critical" -Remediation "Remove Users write from HKLM Run."

    # Scheduled tasks
    try {
        $st = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.Principal.UserId -match "SYSTEM|LocalSystem" -and $_.State -ne "Disabled" }
        $vuln = @(); $dq = [string][char]34
        foreach ($t in $st|Select-Object -First 50) { foreach ($a in $t.Actions) {
            if ($a.Execute) { $te = $a.Execute -replace $dq,''
                if ($te -and (Test-Path $te -ErrorAction SilentlyContinue)) {
                    $ta = Get-Acl $te -ErrorAction SilentlyContinue
                    if ($ta) { $w = $ta.Access | Where-Object { $_.IdentityReference -match "(Everyone|BUILTIN\\Users)" -and
                        $_.FileSystemRights -match "(Write|Modify|FullControl)" }; if ($w) { $vuln += "$($t.TaskName): $te" } } } } } }
        Add-Finding -Category "Persistence Vectors" -CheckTitle "SYSTEM tasks writable" `
            -Status $(if($vuln.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($vuln.Count -eq 0){"None (sampled 50)"}else{($vuln|Select-Object -First 5) -join '; '}) `
            -Severity "Critical" -POCResult "SYSTEM tasks: $($st.Count)`n$(if($vuln.Count -gt 0){$vuln -join "`n"}else{'None writable'})" `
            -Remediation "icacls BINARY /remove:g Users"
    } catch {}

    # DLL hijacking
    try {
        $sp = [Environment]::GetEnvironmentVariable("PATH","Machine") -split ";"
        $writable = @()
        foreach ($d in $sp) { if ($d -and (Test-Path $d -ErrorAction SilentlyContinue)) {
            $a = Get-Acl $d -ErrorAction SilentlyContinue
            if ($a) { $w = $a.Access | Where-Object { $_.IdentityReference -match "(Everyone|BUILTIN\\Users|Authenticated Users)" -and
                $_.FileSystemRights -match "(Write|Modify|FullControl|CreateFiles)" -and $_.AccessControlType -eq "Allow" }
                if ($w) { $writable += $d } } } }
        $poc = "PATH dirs: $($sp.Count)`n$(if($writable.Count -gt 0){foreach($w in $writable){"  WRITABLE: $w`n  $(Get-IcaclsOutput $w)"}}else{'All restricted.'})"
        Add-Finding -Category "Persistence Vectors" -CheckTitle "Writable system PATH dirs" `
            -Status $(if($writable.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
            -Actual $(if($writable.Count -eq 0){"None"}else{"$($writable.Count): $($writable -join '; ')"}) `
            -Severity "Critical" -POCResult $poc -Remediation "Remove writable dirs or fix ACLs." `
            -ExploitCmd "copy version.dll WRITABLE_PATH\"
    } catch {}

    # IFEO
    $ifeoHijacks = @()
    $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    if (Test-Path $ifeoPath) { Get-ChildItem $ifeoPath -ErrorAction SilentlyContinue | ForEach-Object {
        $dbg = Get-ItemProperty $_.PSPath -Name "Debugger" -ErrorAction SilentlyContinue
        if ($dbg.Debugger) { $ifeoHijacks += "$($_.PSChildName): $($dbg.Debugger)" } } }
    Add-Finding -Category "Persistence Vectors" -CheckTitle "IFEO debugger hijacks" `
        -Status $(if($ifeoHijacks.Count -eq 0){"Pass"}else{"Fail"}) -Expected "None" `
        -Actual $(if($ifeoHijacks.Count -eq 0){"None"}else{$ifeoHijacks -join '; '}) `
        -Severity "High" -Remediation "reg delete HKLM\...\IFEO\target.exe /v Debugger"

    # WMI subscriptions
    try {
        $wmi = @(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue)
        $wmiCount = $wmi.Count
        Add-Finding -Category "Persistence Vectors" -CheckTitle "WMI event consumers" `
            -Status $(if($wmiCount -eq 0){"Pass"}else{"Warning"}) -Expected "None" `
            -Actual "$wmiCount consumers" -Severity "High" `
            -POCResult "WMI consumers: $(if($wmiCount -gt 0){($wmi|ForEach-Object{"$($_.Name) ($($_.__CLASS))"}) -join ', '}else{'None'})" `
            -Remediation "Remove unknown: Get-CimInstance ... | Remove-CimInstance"
    } catch {}
}

# ============================================================================
# 12. ATTACK PATH SUMMARY
# ============================================================================
function Test-AttackSummary {
    Write-Section "Attack Path Summary"
    $fails = $Script:Results | Where-Object Status -eq "Fail"
    $crits = ($fails | Where-Object Severity -eq "Critical").Count
    $highs = ($fails | Where-Object Severity -eq "High").Count
    $paths = $fails | ForEach-Object { "[$($_.Severity)] $($_.CheckTitle)" }
    if ($paths.Count -gt 0) {
        Add-Finding -Category "Attack Path Summary" -CheckTitle "FINDINGS: Critical=$crits High=$highs Total=$($paths.Count)" `
            -Status "Fail" -Expected "0" -Actual ($paths -join " | ") -Severity "Critical" `
            -Remediation "Address Critical first, then High."
    } else {
        Add-Finding -Category "Attack Path Summary" -CheckTitle "SUMMARY" -Status "Pass" `
            -Expected "Minimal" -Actual "No critical findings" -Severity "Informational"
    }
}


# ============================================================================
# HTML REPORT
# ============================================================================
function Generate-Report {
    Write-Section "Generating Report"
    $end = Get-Date; $dur = $end - $Script:StartTime
    $total = $Script:Results.Count
    $pass = ($Script:Results|Where-Object Status -eq "Pass").Count
    $fail = ($Script:Results|Where-Object Status -eq "Fail").Count
    $warn = ($Script:Results|Where-Object Status -eq "Warning").Count
    $pocN = ($Script:Results|Where-Object{$_.POCResult -ne ""}).Count
    $comp = if(($pass+$fail) -gt 0){[math]::Round(($pass/($pass+$fail))*100,1)}else{0}
    $cats = $Script:Results | Group-Object Category | Sort-Object Name
    $ts = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $rp = Join-Path $OutputPath "CIS_Admin_Review_${Script:ComputerName}_$ts.html"
    $compCol = if($comp -ge 80){"#4ade80"}elseif($comp -ge 60){"#fbbf24"}else{"#f87171"}
    $a = [string][char]38

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>CIS Admin Build Review - $Script:ComputerName</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}
.ctr{max-width:1400px;margin:0 auto;padding:20px}
.hdr{background:linear-gradient(135deg,#0c1929,#162544);border-radius:12px;padding:28px;margin-bottom:22px;border:1px solid #1e40af}
.hdr h1{font-size:22px;color:#93c5fd}.hdr .sub{color:#94a3b8;font-size:13px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-top:16px}
.mi{background:#1e293b;padding:9px 13px;border-radius:7px;border:1px solid #334155}
.mi .lb{font-size:10px;text-transform:uppercase;color:#64748b}.mi .vl{font-size:14px;color:#f1f5f9;font-weight:600}
.dash{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin-bottom:22px}
.sc{background:#1e293b;border-radius:9px;padding:16px;text-align:center;border:1px solid #334155}
.sc .n{font-size:28px;font-weight:700}.sc .l{font-size:10px;color:#94a3b8;text-transform:uppercase}
.sc.p .n{color:#4ade80}.sc.f .n{color:#f87171}.sc.w .n{color:#fbbf24}.sc.c .n{color:$compCol}.sc.poc .n{color:#60a5fa}
.cat{background:#1e293b;border-radius:9px;margin-bottom:12px;border:1px solid #334155;overflow:hidden}
.ch{padding:13px 17px;cursor:pointer;display:flex;justify-content:space-between;align-items:center}
.ch:hover{background:#253347}.ch h3{font-size:14px;color:#f1f5f9}
.cs span{font-size:10px;padding:2px 7px;border-radius:9px;font-weight:600;margin-left:3px}
.cp{background:#14532d;color:#4ade80}.cf{background:#7f1d1d;color:#f87171}.cw{background:#78350f;color:#fbbf24}
.cb{display:none}.cb.open{display:block}
table{width:100%;border-collapse:collapse;font-size:11px}
th{background:#0f172a;padding:7px 9px;text-align:left;color:#94a3b8;font-size:9px;text-transform:uppercase}
td{padding:7px 9px;border-bottom:1px solid #1e293b;vertical-align:top}
tr:hover td{background:#162032}
.b{padding:2px 7px;border-radius:7px;font-size:9px;font-weight:700;display:inline-block;min-width:42px;text-align:center}
.sP{background:#14532d;color:#4ade80}.sF{background:#7f1d1d;color:#f87171}
.sW{background:#78350f;color:#fbbf24}.sI{background:#1e3a5f;color:#60a5fa}.sE{background:#581845;color:#e879f9}
.svC{color:#f87171;font-weight:700}.svH{color:#fb923c;font-weight:600}.svM{color:#fbbf24}.svL{color:#94a3b8}.svN{color:#64748b}
.desc{color:#64748b;font-size:10px;margin-top:2px}
.rem{color:#34d399;font-size:10px;margin-top:3px;padding:3px 7px;background:#052e16;border-radius:3px}
.rem::before{content:"FIX: ";font-weight:700}
.exp{color:#fb923c;font-size:10px;margin-top:3px;font-family:'Cascadia Code',Consolas,monospace;padding:3px 7px;background:#1c1306;border-radius:3px;white-space:pre-wrap;word-break:break-all}
.exp::before{content:"EXPLOIT: ";font-weight:700}
.poc{color:#93c5fd;font-size:10px;margin-top:4px;padding:5px 8px;background:#0c1929;border:1px solid #1e40af;border-radius:3px;white-space:pre-wrap;font-family:'Cascadia Code',Consolas,monospace;max-height:250px;overflow-y:auto}
.poc::before{content:"EVIDENCE ";font-weight:700;color:#60a5fa}
.crit-box{background:#1c1117;border:1px solid #7f1d1d;border-radius:9px;padding:16px;margin-bottom:18px}
.crit-box h3{color:#f87171;margin-bottom:8px;font-size:14px}
.crit-box ul{list-style:none}.crit-box li{padding:4px 0;color:#fca5a5;font-size:11px;border-bottom:1px solid #2d1318}
.crit-box li:last-child{border-bottom:none}.crit-box li::before{content:"! ";font-weight:bold}
.tb{background:#334155;border:none;color:#94a3b8;padding:6px 12px;border-radius:5px;cursor:pointer;font-size:10px;margin-bottom:8px;margin-right:5px}
.tb:hover{background:#475569;color:#f1f5f9}
.ftr{text-align:center;padding:16px;color:#475569;font-size:10px}
</style></head>
<body><div class="ctr">
<div class="hdr"><h1>CIS Windows 11 Admin Build Review</h1>
<div class="sub">CIS L1/L2 benchmarks + attack surface + defense posture with evidence</div>
<div class="meta">
<div class="mi"><div class="lb">Hostname</div><div class="vl">$Script:ComputerName</div></div>
<div class="mi"><div class="lb">OS</div><div class="vl">$Script:OSVersion</div></div>
<div class="mi"><div class="lb">Build</div><div class="vl">$Script:OSBuild</div></div>
<div class="mi"><div class="lb">User</div><div class="vl">$Script:CurrentUser</div></div>
<div class="mi"><div class="lb">Domain</div><div class="vl">$(if($Script:IsDomainJoined){'Joined'}else{'Standalone'})</div></div>
<div class="mi"><div class="lb">Date</div><div class="vl">$(Get-Date -Format 'dd MMM yyyy HH:mm')</div></div>
<div class="mi"><div class="lb">Duration</div><div class="vl">$([math]::Round($dur.TotalSeconds,1))s</div></div>
<div class="mi"><div class="lb">Evidence Items</div><div class="vl" style="color:#60a5fa">$pocN</div></div>
</div></div>
<div class="dash">
<div class="sc"><div class="n">$total</div><div class="l">Checks</div></div>
<div class="sc p"><div class="n">$pass</div><div class="l">Pass</div></div>
<div class="sc f"><div class="n">$fail</div><div class="l">Fail</div></div>
<div class="sc w"><div class="n">$warn</div><div class="l">Warn</div></div>
<div class="sc c"><div class="n">${comp}%</div><div class="l">CIS Score</div></div>
<div class="sc poc"><div class="n">$pocN</div><div class="l">Evidence</div></div>
</div>
"@

    $cf = $Script:Results | Where-Object { $_.Status -eq "Fail" -and $_.Severity -in @("Critical","High") } | Sort-Object Severity
    if ($cf.Count -gt 0) {
        $html += "<div class=`"crit-box`"><h3>Critical/High Findings ($($cf.Count))</h3><ul>`n"
        foreach ($f in $cf) { $html += "        <li><strong>[$($f.Severity)]</strong> $($f.Category) - $(ConvertTo-HtmlSafe $f.CheckTitle)</li>`n" }
        $html += "    </ul></div>`n"
    }

    $html += "<button class=`"tb`" onclick=`"document.querySelectorAll('.cb').forEach(e=>e.classList.toggle('open'))`">Toggle All</button>`n"

    foreach ($cat in $cats) {
        $cP=($cat.Group|Where-Object Status -eq "Pass").Count;$cF=($cat.Group|Where-Object Status -eq "Fail").Count;$cW=($cat.Group|Where-Object Status -eq "Warning").Count
        $html += "<div class=`"cat`"><div class=`"ch`" onclick=`"this.nextElementSibling.classList.toggle('open')`">"
        $html += "<h3>$($cat.Name) ($($cat.Count))</h3><div class=`"cs`">"
        if($cP){$html+="<span class='cp'>$cP Pass</span>"};if($cF){$html+="<span class='cf'>$cF Fail</span>"};if($cW){$html+="<span class='cw'>$cW Warn</span>"}
        $html += "</div></div><div class=`"cb$(if($cF -gt 0){' open'})`"><table><thead><tr><th>Status</th><th>Sev</th><th>Check</th><th>Expected</th><th>Actual</th></tr></thead><tbody>`n"
        $sorted = $cat.Group | Sort-Object @{Expression={switch($_.Status){"Fail"{0}"Warning"{1}"Error"{2}"Info"{3}"Pass"{4}}};Ascending=$true}
        foreach ($f in $sorted) {
            $sc = switch($f.Severity){"Critical"{"svC"}"High"{"svH"}"Medium"{"svM"}"Low"{"svL"}default{"svN"}}
            $stc = switch($f.Status){"Pass"{"sP"}"Fail"{"sF"}"Warning"{"sW"}"Info"{"sI"}"Error"{"sE"}default{"sI"}}
            $cell = ConvertTo-HtmlSafe $f.CheckTitle
            if($f.Description){$cell+="<div class='desc'>$(ConvertTo-HtmlSafe $f.Description)</div>"}
            if($f.Remediation){$cell+="<div class='rem'>$(ConvertTo-HtmlSafe $f.Remediation)</div>"}
            if($f.ExploitCmd){$cell+="<div class='exp'>$(ConvertTo-HtmlSafe $f.ExploitCmd)</div>"}
            if($f.POCResult){$cell+="<div class='poc'>$(ConvertTo-HtmlSafe $f.POCResult)</div>"}
            $html += "<tr><td><span class=`"b $stc`">$($f.Status)</span></td><td><span class=`"$sc`">$($f.Severity)</span></td>"
            $html += "<td>$cell</td><td>$(ConvertTo-HtmlSafe $f.Expected)</td><td>$(ConvertTo-HtmlSafe $f.Actual)</td></tr>`n"
        }
        $html += "</tbody></table></div></div>`n"
    }

    $html += "<div class=`"ftr`"><p>CIS Win11 Admin Build Review v4 | $(Get-Date -Format 'dd MMM yyyy HH:mm:ss') | $([math]::Round($dur.TotalSeconds,1))s | $pocN evidence items | Authorised use only.</p></div>"
    $html += "</div></body></html>"
    $html | Out-File -FilePath $rp -Encoding UTF8 -Force
    return $rp
}

# ============================================================================
# MAIN
# ============================================================================
function Invoke-CISReview {
    Write-Host "============================================================" -ForegroundColor White
    Write-Host "  CIS Windows 11 Admin Build Review v4" -ForegroundColor Cyan
    Write-Host "  $Script:ComputerName | $Script:CurrentUser | $(Get-Date)" -ForegroundColor Gray
    Write-Host "============================================================" -ForegroundColor White

    @({ Test-AccountPolicies },{ Test-SecurityOptions },{ Test-AuditPolicy },
      { Test-Firewall },{ Test-DefenderConfig },{ Test-CredentialProtection },
      { Test-NetworkHardening },{ Test-SystemHardening },{ Test-ApplicationControl },
      { Test-ServiceSecurity },{ Test-PersistenceVectors },{ Test-AttackSummary }
    ) | ForEach-Object { try { & $_ } catch { Write-Host "  [!] $_" -ForegroundColor Red } }

    $rp = Generate-Report
    $fc = ($Script:Results|Where-Object Status -eq 'Fail').Count
    $pc = ($Script:Results|Where-Object{$_.POCResult -ne ""}).Count
    Write-Host "`n============================================================" -ForegroundColor White
    Write-Host "  DONE | Checks:$($Script:Results.Count) Fail:$fc Evidence:$pc" -ForegroundColor Green
    Write-Host "  Report: $rp" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor White
    $cp = $rp -replace '\.html$','.csv'
    $Script:Results | Export-Csv -Path $cp -NoTypeInformation -Encoding UTF8
    Write-Host "  CSV: $cp" -ForegroundColor Cyan
}

Invoke-CISReview
