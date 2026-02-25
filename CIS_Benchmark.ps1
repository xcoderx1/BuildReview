<#
.SYNOPSIS
    CIS Windows 11 Enterprise Benchmark v4.0 - L1 + L2 Automated Audit
.DESCRIPTION
    Pure CIS benchmark assessment. Every check maps to a specific CIS control ID.
    Covers: Account Policies, Local Policies, Audit Policy, Security Options,
    Windows Firewall, Windows Defender, Administrative Templates, System Services.
    REQUIRES ADMINISTRATOR. Produces HTML + CSV report.
.EXAMPLE
    .\CIS_Benchmark.ps1
    .\CIS_Benchmark.ps1 -OutputPath C:\Reports
    .\CIS_Benchmark.ps1 -Level 1    # L1 only
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop",
    [ValidateSet(1,2)][int]$Level = 2
)

# Output directory validation
if (-not (Test-Path $OutputPath)) {
    foreach ($fb in @([Environment]::GetFolderPath('Desktop'),"$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\OneDrive\Desktop","$env:USERPROFILE\Documents",$env:USERPROFILE,$env:TEMP)) {
        if ($fb -and (Test-Path $fb)) { $OutputPath = $fb; break } }
}
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
if (-not $isAdmin) { Write-Host "`n  [!] REQUIRES Administrator.`n" -ForegroundColor Red; exit }

$Script:Results = [System.Collections.ArrayList]::new()
$Script:StartTime = Get-Date
$Script:ComputerName = $env:COMPUTERNAME
$Script:OSVersion = try { (Get-CimInstance Win32_OperatingSystem).Caption } catch { "Unknown" }
$Script:OSBuild = try { (Get-CimInstance Win32_OperatingSystem).BuildNumber } catch { "Unknown" }
$Script:CurrentUser = "$env:USERDOMAIN\$env:USERNAME"
$Script:CISLevel = $Level

function Add-CIS {
    param(
        [Parameter(Mandatory)][string]$ID,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][ValidateSet("Pass","Fail","Warning","Info","Error","N/A")][string]$Status,
        [string]$Expected = "", [string]$Actual = "",
        [ValidateSet(1,2)][int]$CISLevel = 1,
        [string]$Remediation = "", [string]$Evidence = ""
    )
    if ($CISLevel -gt $Script:CISLevel) { return }
    $null = $Script:Results.Add([PSCustomObject]@{
        ID=$ID; Title=$Title; Section=$Section; Status=$Status; Expected=$Expected
        Actual=$Actual; Level="L$CISLevel"; Remediation=$Remediation; Evidence=$Evidence
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

function Write-Section { param([string]$Name) Write-Host "`n[+] $Name" -ForegroundColor Cyan }


# ============================================================================
# CIS 1.x - ACCOUNT POLICIES
# ============================================================================
function Test-AccountPolicies {
    Write-Section "CIS 1.x - Account Policies"

    # Export security policy
    $tmpInf = Join-Path $env:TEMP "cis_secpol_$(Get-Date -Format 'yyyyMMddHHmmss').inf"
    secedit /export /cfg $tmpInf /areas SECURITYPOLICY 2>&1 | Out-Null
    $secpol = if ((Test-Path $tmpInf) -and (Get-Item $tmpInf).Length -gt 100) { Get-Content $tmpInf } else { @() }
    Remove-Item $tmpInf -Force -ErrorAction SilentlyContinue

    function Get-SecPol { param([string]$Key)
        $m = $secpol | Select-String "$Key\s*=\s*(.+)" | Select-Object -First 1
        if ($m) { return $m.Matches[0].Groups[1].Value.Trim() } return $null
    }

    # 1.1.1 Password History
    $v = Get-SecPol "PasswordHistorySize"
    Add-CIS -ID "1.1.1" -Title "Enforce password history" -Section "Account Policies" `
        -Status $(if([int]$v -ge 24){"Pass"}else{"Fail"}) -Expected "24 or more" -Actual "$v passwords" `
        -Remediation "GPO: Computer > Windows Settings > Security > Account Policies > Password Policy" `
        -Evidence "PasswordHistorySize=$v"

    # 1.1.2 Maximum password age
    $v = Get-SecPol "MaximumPasswordAge"
    Add-CIS -ID "1.1.2" -Title "Maximum password age" -Section "Account Policies" `
        -Status $(if($v -and [int]$v -ge 1 -and [int]$v -le 365){"Pass"}else{"Fail"}) `
        -Expected "1-365 days" -Actual $(if($v -eq 0 -or $v -eq -1){"Never expires"}else{"$v days"}) `
        -Evidence "MaximumPasswordAge=$v"

    # 1.1.3 Minimum password age
    $v = Get-SecPol "MinimumPasswordAge"
    Add-CIS -ID "1.1.3" -Title "Minimum password age" -Section "Account Policies" `
        -Status $(if([int]$v -ge 1){"Pass"}else{"Fail"}) -Expected "1 or more days" -Actual "$v days" `
        -Evidence "MinimumPasswordAge=$v"

    # 1.1.4 Minimum password length
    $v = Get-SecPol "MinimumPasswordLength"
    Add-CIS -ID "1.1.4" -Title "Minimum password length" -Section "Account Policies" `
        -Status $(if([int]$v -ge 14){"Pass"}else{"Fail"}) -Expected "14 or more" -Actual "$v characters" `
        -Evidence "MinimumPasswordLength=$v"

    # 1.1.5 Password complexity
    $v = Get-SecPol "PasswordComplexity"
    Add-CIS -ID "1.1.5" -Title "Password must meet complexity" -Section "Account Policies" `
        -Status $(if([int]$v -eq 1){"Pass"}else{"Fail"}) -Expected "Enabled (1)" -Actual $v `
        -Evidence "PasswordComplexity=$v"

    # 1.1.6 Reversible encryption
    $v = Get-SecPol "ClearTextPassword"
    Add-CIS -ID "1.1.6" -Title "Store passwords using reversible encryption" -Section "Account Policies" `
        -Status $(if([int]$v -eq 0){"Pass"}else{"Fail"}) -Expected "Disabled (0)" -Actual $v `
        -Evidence "ClearTextPassword=$v"

    # 1.2.1 Account lockout duration
    $v = Get-SecPol "LockoutDuration"
    Add-CIS -ID "1.2.1" -Title "Account lockout duration" -Section "Account Policies" `
        -Status $(if([int]$v -ge 15){"Pass"}else{"Fail"}) -Expected "15 or more minutes" -Actual "$v minutes" `
        -Evidence "LockoutDuration=$v"

    # 1.2.2 Account lockout threshold
    $v = Get-SecPol "LockoutBadCount"
    Add-CIS -ID "1.2.2" -Title "Account lockout threshold" -Section "Account Policies" `
        -Status $(if([int]$v -ge 1 -and [int]$v -le 5){"Pass"}else{"Fail"}) `
        -Expected "1-5 attempts" -Actual $(if($v -eq 0){"Never (0)"}else{"$v attempts"}) `
        -Evidence "LockoutBadCount=$v"

    # 1.2.3 Reset account lockout counter
    $v = Get-SecPol "ResetLockoutCount"
    Add-CIS -ID "1.2.3" -Title "Reset account lockout counter after" -Section "Account Policies" `
        -Status $(if([int]$v -ge 15){"Pass"}else{"Fail"}) -Expected "15 or more minutes" -Actual "$v minutes" `
        -Evidence "ResetLockoutCount=$v"

    if (-not $secpol -or $secpol.Count -eq 0) {
        Add-CIS -ID "1.x" -Title "Security policy export" -Section "Account Policies" -Status "Error" `
            -Actual "secedit export failed. Account policy checks may be inaccurate." -Expected "Successful export"
    }
}


# ============================================================================
# CIS 2.x - LOCAL POLICIES / SECURITY OPTIONS
# ============================================================================
function Test-SecurityOptions {
    Write-Section "CIS 2.x - Security Options"

    # 2.3.1.1 Accounts: Block Microsoft accounts
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "NoConnectedUser"
    Add-CIS -ID "2.3.1.1" -Title "Block Microsoft accounts" -Section "Security Options" `
        -Status $(if($v -eq 3){"Pass"}elseif($v -ge 1){"Warning"}else{"Fail"}) `
        -Expected "3" -Actual $(if($null -eq $v){"Not configured"}else{$v}) `
        -Evidence "NoConnectedUser=$v" -CISLevel 1

    # 2.3.1.2 Accounts: Guest account status
    try { $guest = Get-LocalUser -Name "Guest" -ErrorAction Stop
        Add-CIS -ID "2.3.1.2" -Title "Guest account status" -Section "Security Options" `
            -Status $(if(-not $guest.Enabled){"Pass"}else{"Fail"}) -Expected "Disabled" `
            -Actual $(if($guest.Enabled){"Enabled"}else{"Disabled"}) -Evidence "Guest.Enabled=$($guest.Enabled)"
    } catch {}

    # 2.3.1.5 Accounts: Limit local account use of blank passwords
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse" 1
    Add-CIS -ID "2.3.1.5" -Title "Limit blank password use to console only" -Section "Security Options" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v `
        -Evidence "LimitBlankPasswordUse=$v"

    # 2.3.2.1 Audit: Force audit policy subcategory settings
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy"
    Add-CIS -ID "2.3.2.1" -Title "Force audit policy subcategory settings" -Section "Security Options" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $(if($null -eq $v){"Not configured"}else{$v}) `
        -Evidence "SCENoApplyLegacyAuditPolicy=$v" -CISLevel 1

    # 2.3.7.1 Interactive logon: Do not display last user name
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName"
    Add-CIS -ID "2.3.7.1" -Title "Do not display last signed-in" -Section "Security Options" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $(if($null -eq $v){"Not configured (0)"}else{$v}) `
        -Evidence "DontDisplayLastUserName=$v" -CISLevel 1

    # 2.3.7.2 Interactive logon: Do not require CTRL+ALT+DEL
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD"
    Add-CIS -ID "2.3.7.2" -Title "Do not require CTRL+ALT+DEL" -Section "Security Options" `
        -Status $(if($v -eq 0 -or $null -eq $v){"Pass"}else{"Fail"}) -Expected "0 (Disabled)" `
        -Actual $(if($null -eq $v){"Not configured (default)"}else{$v}) `
        -Evidence "DisableCAD=$v" -CISLevel 1

    # 2.3.7.3 Machine inactivity limit
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs" 0
    Add-CIS -ID "2.3.7.3" -Title "Machine inactivity limit" -Section "Security Options" `
        -Status $(if($v -gt 0 -and $v -le 900){"Pass"}else{"Fail"}) `
        -Expected "900 or fewer seconds" -Actual $(if($v -eq 0){"Not set"}else{"$v seconds"}) `
        -Evidence "InactivityTimeoutSecs=$v"

    # 2.3.7.4 Interactive logon: Message text/title
    $msgText = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeText"
    $msgTitle = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeCaption"
    Add-CIS -ID "2.3.7.4" -Title "Message text for logon" -Section "Security Options" `
        -Status $(if($msgText){"Pass"}else{"Fail"}) -Expected "Configured" `
        -Actual $(if($msgText){"Set ($($msgText.Length) chars)"}else{"Not configured"}) `
        -Evidence "LegalNoticeCaption=$(if($msgTitle){$msgTitle}else{'empty'})" -CISLevel 1

    # 2.3.8.1 Microsoft network client: Digitally sign communications (always)
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" 0
    Add-CIS -ID "2.3.8.1" -Title "Microsoft network client: Digitally sign (always)" -Section "Security Options" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v `
        -Evidence "LanmanWorkstation\RequireSecuritySignature=$v"

    # 2.3.8.2 Microsoft network client: Digitally sign (if server agrees)
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnableSecuritySignature" 1
    Add-CIS -ID "2.3.8.2" -Title "Microsoft network client: Digitally sign (if server agrees)" -Section "Security Options" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v `
        -Evidence "LanmanWorkstation\EnableSecuritySignature=$v"

    # 2.3.8.3 Microsoft network client: Send unencrypted password to third-party SMB
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnablePlainTextPassword" 0
    Add-CIS -ID "2.3.8.3" -Title "Send unencrypted password to SMB servers" -Section "Security Options" `
        -Status $(if($v -eq 0){"Pass"}else{"Fail"}) -Expected "0" -Actual $v `
        -Evidence "EnablePlainTextPassword=$v"

    # 2.3.9.1 Microsoft network server: Digitally sign (always)
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature" 0
    Add-CIS -ID "2.3.9.1" -Title "Microsoft network server: Digitally sign (always)" -Section "Security Options" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v `
        -Evidence "LanmanServer\RequireSecuritySignature=$v"

    # 2.3.9.2 Microsoft network server: Digitally sign (if client agrees)
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "EnableSecuritySignature" 1
    Add-CIS -ID "2.3.9.2" -Title "Microsoft network server: Digitally sign (if client agrees)" -Section "Security Options" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v `
        -Evidence "LanmanServer\EnableSecuritySignature=$v"

    # 2.3.10.2 Network access: Do not allow anonymous enumeration of SAM accounts
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM" 1
    Add-CIS -ID "2.3.10.2" -Title "Do not allow anonymous enum of SAM accounts" -Section "Security Options" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v `
        -Evidence "RestrictAnonymousSAM=$v"

    # 2.3.10.3 Network access: Do not allow anonymous enum of SAM accounts and shares
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous" 0
    Add-CIS -ID "2.3.10.3" -Title "Do not allow anonymous enum of SAM and shares" -Section "Security Options" `
        -Status $(if($v -ge 1){"Pass"}else{"Fail"}) -Expected "1 or higher" -Actual $v `
        -Evidence "RestrictAnonymous=$v"

    # 2.3.10.5 Network access: Let Everyone permissions apply to anonymous
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "EveryoneIncludesAnonymous" 0
    Add-CIS -ID "2.3.10.5" -Title "Let Everyone apply to anonymous users" -Section "Security Options" `
        -Status $(if($v -eq 0){"Pass"}else{"Fail"}) -Expected "0" -Actual $v `
        -Evidence "EveryoneIncludesAnonymous=$v"

    # 2.3.10.7 Named Pipes accessible anonymously
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "NullSessionPipes"
    Add-CIS -ID "2.3.10.7" -Title "Named Pipes accessible anonymously" -Section "Security Options" `
        -Status $(if(-not $v -or $v.Count -eq 0){"Pass"}else{"Fail"}) -Expected "Empty" `
        -Actual $(if($v -and $v.Count -gt 0){$v -join ', '}else{"Empty"}) `
        -Evidence "NullSessionPipes=$(if($v){$v -join ','}else{'empty'})"

    # 2.3.10.11 Restrict clients allowed to make remote calls to SAM
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictRemoteSAM"
    Add-CIS -ID "2.3.10.11" -Title "Restrict remote calls to SAM" -Section "Security Options" `
        -Status $(if($v){"Pass"}else{"Fail"}) -Expected "Configured" `
        -Actual $(if($v){"Set"}else{"Not configured"}) -Evidence "RestrictRemoteSAM=$(if($v){'configured'}else{'null'})"

    # 2.3.11.7 Network security: LAN Manager authentication level
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" 3
    $lvlMap = @{0="LM & NTLM";1="LM & NTLM - NTLMv2 if negotiated";2="NTLM only";3="NTLMv2 only";4="NTLMv2 only, refuse LM";5="NTLMv2 only, refuse LM & NTLM"}
    Add-CIS -ID "2.3.11.7" -Title "LAN Manager authentication level" -Section "Security Options" `
        -Status $(if($v -ge 5){"Pass"}elseif($v -ge 3){"Warning"}else{"Fail"}) `
        -Expected "5 (Send NTLMv2 only. Refuse LM & NTLM)" -Actual "$v ($($lvlMap[[int]$v]))" `
        -Evidence "LmCompatibilityLevel=$v"

    # 2.3.11.8 Network security: LDAP client signing requirements
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" "LDAPClientIntegrity" 1
    Add-CIS -ID "2.3.11.8" -Title "LDAP client signing requirements" -Section "Security Options" `
        -Status $(if($v -ge 1){"Pass"}else{"Fail"}) -Expected "1 (Negotiate signing)" -Actual $v `
        -Evidence "LDAPClientIntegrity=$v"

    # 2.3.11.10 Network security: Minimum session security for NTLM SSP clients
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinClientSec"
    Add-CIS -ID "2.3.11.10" -Title "Min session security for NTLM SSP clients" -Section "Security Options" `
        -Status $(if($v -eq 537395200){"Pass"}else{"Fail"}) -Expected "537395200 (Require NTLMv2 + 128-bit)" `
        -Actual $(if($null -eq $v){"Not configured"}else{$v}) -Evidence "NTLMMinClientSec=$v" -CISLevel 1

    # 2.3.11.11 Network security: Minimum session security for NTLM SSP servers
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinServerSec"
    Add-CIS -ID "2.3.11.11" -Title "Min session security for NTLM SSP servers" -Section "Security Options" `
        -Status $(if($v -eq 537395200){"Pass"}else{"Fail"}) -Expected "537395200 (Require NTLMv2 + 128-bit)" `
        -Actual $(if($null -eq $v){"Not configured"}else{$v}) -Evidence "NTLMMinServerSec=$v" -CISLevel 1

    # 2.3.17.1 UAC: Admin Approval Mode
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" 1
    Add-CIS -ID "2.3.17.1" -Title "UAC: Run all admins in Admin Approval Mode" -Section "Security Options" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v -Evidence "EnableLUA=$v"

    # 2.3.17.2 UAC: Behavior of elevation prompt for admins
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" 5
    Add-CIS -ID "2.3.17.2" -Title "UAC: Elevation prompt for admins" -Section "Security Options" `
        -Status $(if($v -eq 2){"Pass"}elseif($v -eq 1 -or $v -eq 5){"Warning"}else{"Fail"}) `
        -Expected "2 (Prompt for consent on secure desktop)" -Actual $v -Evidence "ConsentPromptBehaviorAdmin=$v"

    # 2.3.17.3 UAC: Behavior of elevation prompt for standard users
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorUser" 3
    Add-CIS -ID "2.3.17.3" -Title "UAC: Elevation prompt for standard users" -Section "Security Options" `
        -Status $(if($v -eq 0){"Pass"}elseif($v -eq 3){"Warning"}else{"Fail"}) `
        -Expected "0 (Automatically deny)" -Actual $v -Evidence "ConsentPromptBehaviorUser=$v" -CISLevel 1

    # 2.3.17.4 UAC: Detect application installations
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableInstallerDetection" 1
    Add-CIS -ID "2.3.17.4" -Title "UAC: Detect application installations" -Section "Security Options" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v -Evidence "EnableInstallerDetection=$v"

    # 2.3.17.5 UAC: Only elevate UIAccess apps in secure locations
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableSecureUIAPaths" 1
    Add-CIS -ID "2.3.17.5" -Title "UAC: Only elevate UIAccess in secure locations" -Section "Security Options" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v -Evidence "EnableSecureUIAPaths=$v"

    # 2.3.17.6 UAC: Only elevate executables that are signed
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ValidateAdminCodeSignatures" 0
    Add-CIS -ID "2.3.17.6" -Title "UAC: Only elevate signed and validated executables" -Section "Security Options" `
        -Status $(if($v -eq 1){"Pass"}else{"Warning"}) -Expected "1" -Actual $(if($null -eq $v){"Not configured (0)"}else{$v}) `
        -Evidence "ValidateAdminCodeSignatures=$v" -CISLevel 2

    # 2.3.17.7 UAC: Switch to secure desktop
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" 1
    Add-CIS -ID "2.3.17.7" -Title "UAC: Switch to secure desktop when prompting" -Section "Security Options" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v -Evidence "PromptOnSecureDesktop=$v"

    # 2.3.17.8 UAC: Virtualize file and registry write failures
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableVirtualization" 1
    Add-CIS -ID "2.3.17.8" -Title "UAC: Virtualize file/registry write failures" -Section "Security Options" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v -Evidence "EnableVirtualization=$v"

    # 2.3.7.8 Interactive logon: Smart card removal behavior (L2)
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "ScRemoveOption"
    Add-CIS -ID "2.3.7.8" -Title "Smart card removal behavior" -Section "Security Options" `
        -Status $(if($v -eq "1" -or $v -eq "2" -or $v -eq "3"){"Pass"}else{"Fail"}) `
        -Expected "1-3 (Lock/Force Logoff/Disconnect)" -Actual $(if($null -eq $v){"Not configured"}else{$v}) `
        -Evidence "ScRemoveOption=$v" -CISLevel 2
}


# ============================================================================
# CIS 5.x - SYSTEM SERVICES
# ============================================================================
function Test-SystemServices {
    Write-Section "CIS 5.x - System Services"

    $svcChecks = @(
        @{ID="5.2";Name="BTAGService";Title="Bluetooth Audio Gateway";Start=4;Lv=1},
        @{ID="5.3";Name="bthserv";Title="Bluetooth Support Service";Start=4;Lv=2},
        @{ID="5.6";Name="Browser";Title="Computer Browser";Start=4;Lv=1},
        @{ID="5.9";Name="MapsBroker";Title="Downloaded Maps Manager";Start=4;Lv=2},
        @{ID="5.11";Name="lfsvc";Title="Geolocation Service";Start=4;Lv=2},
        @{ID="5.14";Name="SharedAccess";Title="Internet Connection Sharing (ICS)";Start=4;Lv=1},
        @{ID="5.16";Name="lltdsvc";Title="Link-Layer Topology Discovery Mapper";Start=4;Lv=2},
        @{ID="5.19";Name="LxssManager";Title="LxssManager (WSL)";Start=4;Lv=1},
        @{ID="5.22";Name="SSDPSRV";Title="SSDP Discovery";Start=4;Lv=2},
        @{ID="5.27";Name="RemoteRegistry";Title="Remote Registry";Start=4;Lv=1},
        @{ID="5.29";Name="RpcLocator";Title="Remote Procedure Call (RPC) Locator";Start=4;Lv=2},
        @{ID="5.33";Name="SessionEnv";Title="Remote Desktop Configuration";Start=4;Lv=2},
        @{ID="5.36";Name="Spooler";Title="Print Spooler";Start=4;Lv=2},
        @{ID="5.40";Name="WinRM";Title="Windows Remote Management (WS-Management)";Start=4;Lv=2},
        @{ID="5.41";Name="WMPNetworkSvc";Title="Windows Media Player Network Sharing";Start=4;Lv=2},
        @{ID="5.42";Name="PushToInstall";Title="Windows PushToInstall Service";Start=4;Lv=2},
        @{ID="5.44";Name="WSearch";Title="Windows Search";Start=4;Lv=2},
        @{ID="5.45";Name="XblAuthManager";Title="Xbox Accessory Management Service";Start=4;Lv=2},
        @{ID="5.46";Name="XblGameSave";Title="Xbox Game Save";Start=4;Lv=2}
    )

    foreach ($sc in $svcChecks) {
        $svc = Get-Service $sc.Name -ErrorAction SilentlyContinue
        $startType = if ($svc) { switch($svc.StartType) {"Disabled"{4}"Manual"{3}"Automatic"{2}default{$svc.StartType}} } else { "N/A" }
        Add-CIS -ID $sc.ID -Title "Ensure '$($sc.Title)' is Disabled" -Section "System Services" `
            -Status $(if(-not $svc -or $svc.StartType -eq "Disabled"){"Pass"}else{"Fail"}) `
            -Expected "Disabled (4)" -Actual $(if(-not $svc){"Not installed"}else{"$($svc.Status)/$($svc.StartType)"}) `
            -CISLevel $sc.Lv -Evidence "Service=$($sc.Name) Start=$startType" `
            -Remediation "Set-Service $($sc.Name) -StartupType Disabled"
    }
}


# ============================================================================
# CIS 9.x - WINDOWS FIREWALL WITH ADVANCED SECURITY
# ============================================================================
function Test-WindowsFirewall {
    Write-Section "CIS 9.x - Windows Firewall"

    try { $profiles = Get-NetFirewallProfile -ErrorAction Stop } catch { Add-CIS -ID "9.x" -Title "Firewall query" -Section "Windows Firewall" -Status "Error" -Actual "Cannot query"; return }

    $fwChecks = @(
        @{Profile="Domain";PfxID="9.1"},
        @{Profile="Private";PfxID="9.2"},
        @{Profile="Public";PfxID="9.3"}
    )

    foreach ($fc in $fwChecks) {
        $p = $profiles | Where-Object Name -eq $fc.Profile

        # .1 Firewall State = On
        Add-CIS -ID "$($fc.PfxID).1" -Title "$($fc.Profile) profile: Firewall state" -Section "Windows Firewall" `
            -Status $(if($p.Enabled){"Pass"}else{"Fail"}) -Expected "True" -Actual "$($p.Enabled)" `
            -Evidence "$($fc.Profile): Enabled=$($p.Enabled)" `
            -Remediation "Set-NetFirewallProfile -Name $($fc.Profile) -Enabled True"

        # .2 Inbound connections = Block
        Add-CIS -ID "$($fc.PfxID).2" -Title "$($fc.Profile) profile: Inbound connections" -Section "Windows Firewall" `
            -Status $(if($p.DefaultInboundAction -eq "Block"){"Pass"}else{"Fail"}) `
            -Expected "Block" -Actual "$($p.DefaultInboundAction)" `
            -Evidence "DefaultInboundAction=$($p.DefaultInboundAction)" `
            -Remediation "Set-NetFirewallProfile -Name $($fc.Profile) -DefaultInboundAction Block"

        # .3 Outbound connections = Allow
        Add-CIS -ID "$($fc.PfxID).3" -Title "$($fc.Profile) profile: Outbound connections" -Section "Windows Firewall" `
            -Status $(if($p.DefaultOutboundAction -eq "Allow" -or $p.DefaultOutboundAction -eq "NotConfigured"){"Pass"}else{"Warning"}) `
            -Expected "Allow" -Actual "$($p.DefaultOutboundAction)" -Evidence "DefaultOutboundAction=$($p.DefaultOutboundAction)"

        # .7 Logging: Log dropped packets
        Add-CIS -ID "$($fc.PfxID).7" -Title "$($fc.Profile) profile: Log dropped packets" -Section "Windows Firewall" `
            -Status $(if($p.LogBlocked -eq $true){"Pass"}else{"Fail"}) `
            -Expected "True" -Actual "$($p.LogBlocked)" -Evidence "LogBlocked=$($p.LogBlocked)" `
            -Remediation "Set-NetFirewallProfile -Name $($fc.Profile) -LogBlocked True"

        # .9 Logging: Size limit
        Add-CIS -ID "$($fc.PfxID).9" -Title "$($fc.Profile) profile: Log file size" -Section "Windows Firewall" `
            -Status $(if($p.LogMaxSizeKilobytes -ge 16384){"Pass"}else{"Fail"}) `
            -Expected "16384 KB or more" -Actual "$($p.LogMaxSizeKilobytes) KB" -Evidence "LogMaxSizeKilobytes=$($p.LogMaxSizeKilobytes)" `
            -Remediation "Set-NetFirewallProfile -Name $($fc.Profile) -LogMaxSizeKilobytes 16384" -CISLevel 1
    }
}


# ============================================================================
# CIS 17.x - ADVANCED AUDIT POLICY CONFIGURATION
# ============================================================================
function Test-AuditPolicy {
    Write-Section "CIS 17.x - Audit Policy"

    $auditpol = auditpol /get /category:* 2>$null

    $checks = @(
        @{ID="17.1.1";Sub="Credential Validation";Expect="Success and Failure";Lv=1},
        @{ID="17.2.1";Sub="Application Group Management";Expect="Success and Failure";Lv=1},
        @{ID="17.2.5";Sub="Security Group Management";Expect="Success";Lv=1},
        @{ID="17.2.6";Sub="User Account Management";Expect="Success and Failure";Lv=1},
        @{ID="17.3.1";Sub="Process Creation";Expect="Success";Lv=1},
        @{ID="17.5.1";Sub="Account Lockout";Expect="Failure";Lv=1},
        @{ID="17.5.2";Sub="Logoff";Expect="Success";Lv=1},
        @{ID="17.5.3";Sub="Logon";Expect="Success and Failure";Lv=1},
        @{ID="17.5.4";Sub="Other Logon/Logoff Events";Expect="Success and Failure";Lv=1},
        @{ID="17.5.6";Sub="Special Logon";Expect="Success";Lv=1},
        @{ID="17.6.1";Sub="Detailed File Share";Expect="Failure";Lv=1},
        @{ID="17.6.2";Sub="File Share";Expect="Success and Failure";Lv=1},
        @{ID="17.6.3";Sub="Other Object Access Events";Expect="Success and Failure";Lv=1},
        @{ID="17.6.4";Sub="Removable Storage";Expect="Success and Failure";Lv=1},
        @{ID="17.7.1";Sub="Audit Policy Change";Expect="Success";Lv=1},
        @{ID="17.7.2";Sub="Authentication Policy Change";Expect="Success";Lv=1},
        @{ID="17.7.3";Sub="Authorization Policy Change";Expect="Success";Lv=1},
        @{ID="17.7.4";Sub="MPSSVC Rule-Level Policy Change";Expect="Success and Failure";Lv=1},
        @{ID="17.8.1";Sub="Sensitive Privilege Use";Expect="Success and Failure";Lv=1},
        @{ID="17.9.1";Sub="IPsec Driver";Expect="Success and Failure";Lv=1},
        @{ID="17.9.2";Sub="Other System Events";Expect="Success and Failure";Lv=1},
        @{ID="17.9.3";Sub="Security State Change";Expect="Success";Lv=1},
        @{ID="17.9.4";Sub="Security System Extension";Expect="Success";Lv=1},
        @{ID="17.9.5";Sub="System Integrity";Expect="Success and Failure";Lv=1}
    )

    foreach ($c in $checks) {
        $line = $auditpol | Select-String "^\s+$($c.Sub)\s" | Select-Object -First 1
        $actual = if ($line) { ($line -split "\s{2,}")[-1].Trim() } else { "Not found" }
        $pass = $actual -match "Success" -and ($c.Expect -notmatch "Failure" -or $actual -match "Failure")
        # For Failure-only checks
        if ($c.Expect -eq "Failure") { $pass = $actual -match "Failure" }
        Add-CIS -ID $c.ID -Title $c.Sub -Section "Audit Policy" `
            -Status $(if($pass){"Pass"}else{"Fail"}) -Expected $c.Expect -Actual $actual `
            -CISLevel $c.Lv -Evidence "auditpol: $($c.Sub) = $actual" `
            -Remediation "auditpol /set /subcategory:`"$($c.Sub)`" /success:$(if($c.Expect -match 'Success'){'enable'}else{'disable'}) /failure:$(if($c.Expect -match 'Failure'){'enable'}else{'disable'})"
    }
}


# ============================================================================
# CIS 18.x - ADMINISTRATIVE TEMPLATES (COMPUTER)
# ============================================================================
function Test-AdminTemplates {
    Write-Section "CIS 18.x - Administrative Templates"

    # --- 18.1 Control Panel ---
    # 18.1.1.1 Personalization: Prevent enabling lock screen camera
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera"
    Add-CIS -ID "18.1.1.1" -Title "Prevent enabling lock screen camera" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $(if($null -eq $v){"Not configured"}else{$v}) `
        -Evidence "NoLockScreenCamera=$v" -CISLevel 1

    # 18.1.1.2 Personalization: Prevent enabling lock screen slide show
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow"
    Add-CIS -ID "18.1.1.2" -Title "Prevent enabling lock screen slide show" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $(if($null -eq $v){"Not configured"}else{$v}) `
        -Evidence "NoLockScreenSlideshow=$v" -CISLevel 1

    # --- 18.4 MS Security Guide ---
    # 18.4.1 Credential Guard
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\LSA" "LsaCfgFlags"
    Add-CIS -ID "18.4.1" -Title "Configure LSASS to run as a protected process (Credential Guard)" -Section "Admin Templates" `
        -Status $(if($v -ge 1){"Pass"}else{"Fail"}) -Expected "1 or 2" -Actual $(if($null -eq $v){"Not configured"}else{$v}) `
        -Evidence "LsaCfgFlags=$v" -CISLevel 1

    # 18.4.4 SMB v1 client driver
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start" 3
    Add-CIS -ID "18.4.4" -Title "Configure SMBv1 client driver" -Section "Admin Templates" `
        -Status $(if($v -eq 4){"Pass"}else{"Fail"}) -Expected "4 (Disabled)" -Actual $v `
        -Evidence "mrxsmb10\Start=$v"

    # 18.4.5 SMB v1 server
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1" 1
    Add-CIS -ID "18.4.5" -Title "Configure SMBv1 server" -Section "Admin Templates" `
        -Status $(if($v -eq 0){"Pass"}else{"Fail"}) -Expected "0 (Disabled)" -Actual $(if($null -eq $v -or $v -eq 1){"Enabled (default)"}else{$v}) `
        -Evidence "LanmanServer\SMB1=$v"

    # 18.4.7 LSASS PPL
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
    $pplOK = $v -eq 1 -or $v -eq 2
    Add-CIS -ID "18.4.7" -Title "Configuring LSASS to run as protected process" -Section "Admin Templates" `
        -Status $(if($pplOK){"Pass"}else{"Fail"}) -Expected "1 or 2" `
        -Actual $(if($pplOK){"$v ($(if($v -eq 2){'UEFI lock'}else{'Enabled'}))"}else{"Not configured"}) `
        -Evidence "RunAsPPL=$v"

    # 18.4.8 WDigest Authentication
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"
    Add-CIS -ID "18.4.8" -Title "WDigest Authentication" -Section "Admin Templates" `
        -Status $(if($v -ne 1){"Pass"}else{"Fail"}) -Expected "0 or not set" `
        -Actual $(if($v -eq 1){"ENABLED (cleartext passwords!)"}else{"Disabled (default)"}) -Evidence "UseLogonCredential=$v"

    # --- 18.5 MSS (Legacy) ---
    # 18.5.1 AutoAdminLogon
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon" "0"
    $pw = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultPassword"
    Add-CIS -ID "18.5.1" -Title "MSS: AutoAdminLogon" -Section "Admin Templates" `
        -Status $(if($v -eq "0" -and -not $pw){"Pass"}else{"Fail"}) -Expected "0 with no password" `
        -Actual "AutoAdminLogon=$v, DefaultPassword=$(if($pw){'SET!'}else{'Not set'})" `
        -Evidence "AutoAdminLogon=$v DefaultPassword=$(if($pw){'present'}else{'absent'})"

    # --- 18.6 Network ---
    # 18.6.4.1 LLMNR
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" 1
    Add-CIS -ID "18.6.4.1" -Title "Turn off multicast name resolution (LLMNR)" -Section "Admin Templates" `
        -Status $(if($v -eq 0){"Pass"}else{"Fail"}) -Expected "0" -Actual $v -Evidence "EnableMulticast=$v"

    # 18.6.14.1 Hardened UNC Paths
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\netlogon"
    Add-CIS -ID "18.6.14.1" -Title "Hardened UNC Paths" -Section "Admin Templates" `
        -Status $(if($v){"Pass"}else{"Warning"}) -Expected "Configured" `
        -Actual $(if($v){"Set"}else{"Not configured"}) -Evidence "HardenedPaths=$v" -CISLevel 1

    # --- 18.8 System ---
    # 18.8.3.1 Remote host allows delegation of non-exportable credentials
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "AllowProtectedCreds"
    Add-CIS -ID "18.8.3.1" -Title "Remote host: delegation of non-exportable credentials" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $(if($null -eq $v){"Not configured"}else{$v}) `
        -Evidence "AllowProtectedCreds=$v" -CISLevel 1

    # --- 18.9 Windows Components ---
    # 18.9.3.1 Include command line in process creation events
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" 0
    Add-CIS -ID "18.9.3.1" -Title "Include command line in process creation events" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v -Evidence "ProcessCreationIncludeCmdLine_Enabled=$v"

    # 18.9.4.1 Encryption Oracle Remediation (CredSSP)
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" "AllowEncryptionOracle"
    Add-CIS -ID "18.9.4.1" -Title "Encryption Oracle Remediation" -Section "Admin Templates" `
        -Status $(if($v -eq 0){"Pass"}else{"Fail"}) -Expected "0 (Force Updated Clients)" `
        -Actual $(if($null -eq $v){"Not configured"}else{$v}) -Evidence "AllowEncryptionOracle=$v" -CISLevel 1

    # 18.9.7.2 Prevent device metadata retrieval from Internet
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" "PreventDeviceMetadataFromNetwork"
    Add-CIS -ID "18.9.7.2" -Title "Prevent device metadata retrieval from Internet" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $(if($null -eq $v){"Not configured"}else{$v}) `
        -Evidence "PreventDeviceMetadataFromNetwork=$v" -CISLevel 1

    # 18.9.27.1.1 Application event log size
    try { $el = Get-WinEvent -ListLog Application -ErrorAction Stop
        Add-CIS -ID "18.9.27.1.1" -Title "Application: Maximum Log Size" -Section "Admin Templates" `
            -Status $(if($el.MaximumSizeInBytes -ge 32768){"Pass"}else{"Fail"}) -Expected "32768 bytes (32KB) or more" `
            -Actual "$($el.MaximumSizeInBytes) bytes ($([math]::Round($el.MaximumSizeInBytes/1024))KB)" `
            -Evidence "Application MaxSize=$($el.MaximumSizeInBytes)"
    } catch {}

    # 18.9.27.2.1 Security event log size
    try { $el = Get-WinEvent -ListLog Security -ErrorAction Stop
        Add-CIS -ID "18.9.27.2.1" -Title "Security: Maximum Log Size" -Section "Admin Templates" `
            -Status $(if($el.MaximumSizeInBytes -ge 196608){"Pass"}else{"Fail"}) -Expected "196608 bytes (192KB) or more" `
            -Actual "$($el.MaximumSizeInBytes) bytes ($([math]::Round($el.MaximumSizeInBytes/1024))KB)" `
            -Evidence "Security MaxSize=$($el.MaximumSizeInBytes)"
    } catch {}

    # 18.9.27.3.1 System event log size
    try { $el = Get-WinEvent -ListLog System -ErrorAction Stop
        Add-CIS -ID "18.9.27.3.1" -Title "System: Maximum Log Size" -Section "Admin Templates" `
            -Status $(if($el.MaximumSizeInBytes -ge 32768){"Pass"}else{"Fail"}) -Expected "32768 bytes (32KB) or more" `
            -Actual "$($el.MaximumSizeInBytes) bytes ($([math]::Round($el.MaximumSizeInBytes/1024))KB)" `
            -Evidence "System MaxSize=$($el.MaximumSizeInBytes)"
    } catch {}

    # --- 18.10 Windows Components ---
    # 18.10.9.1 BitLocker
    try { $bl = Get-BitLockerVolume -MountPoint C: -ErrorAction Stop
        Add-CIS -ID "18.10.9.1" -Title "BitLocker Drive Encryption: OS Drive" -Section "Admin Templates" `
            -Status $(if($bl.ProtectionStatus -eq "On"){"Pass"}else{"Fail"}) -Expected "On" `
            -Actual "$($bl.ProtectionStatus) ($($bl.EncryptionMethod))" -Evidence "C: Status=$($bl.ProtectionStatus) Method=$($bl.EncryptionMethod)"
    } catch { Add-CIS -ID "18.10.9.1" -Title "BitLocker Drive Encryption: OS Drive" -Section "Admin Templates" -Status "Fail" -Expected "On" -Actual "Cannot query or not enabled" }

    # 18.10.12.1 Do not display the password reveal button
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" "DisablePasswordReveal"
    Add-CIS -ID "18.10.12.1" -Title "Do not display password reveal button" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $(if($null -eq $v){"Not configured"}else{$v}) `
        -Evidence "DisablePasswordReveal=$v" -CISLevel 1

    # 18.10.14.1 Turn off Microsoft consumer experiences
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures"
    Add-CIS -ID "18.10.14.1" -Title "Turn off Microsoft consumer experiences" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $(if($null -eq $v){"Not configured"}else{$v}) `
        -Evidence "DisableWindowsConsumerFeatures=$v" -CISLevel 1

    # 18.10.25.1 Turn off Autoplay
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" 0
    Add-CIS -ID "18.10.25.1" -Title "Turn off Autoplay" -Section "Admin Templates" `
        -Status $(if($v -eq 255){"Pass"}else{"Fail"}) -Expected "255 (All drives)" -Actual $v `
        -Evidence "NoDriveTypeAutoRun=$v"

    # 18.10.25.2 Default behavior for AutoRun
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun" 0
    Add-CIS -ID "18.10.25.2" -Title "Set default behavior for AutoRun" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1 (Do not execute)" -Actual $v `
        -Evidence "NoAutorun=$v"

    # 18.10.40.1 PowerShell v2 (feature check)
    try { $psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop
        $state = if ($psv2.State) { $psv2.State.ToString() } else { "Unknown" }
        Add-CIS -ID "18.10.40.1" -Title "Turn on PowerShell Script Block Logging / Disable PSv2" -Section "Admin Templates" `
            -Status $(if($state -match "Disabled"){"Pass"}else{"Fail"}) -Expected "Disabled" -Actual $state `
            -Evidence "MicrosoftWindowsPowerShellV2Root=$state"
    } catch {}

    # 18.10.40.2 PowerShell Script Block Logging
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" 0
    Add-CIS -ID "18.10.40.2" -Title "Turn on PowerShell Script Block Logging" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v -Evidence "EnableScriptBlockLogging=$v"

    # 18.10.40.3 PowerShell Transcription
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting" 0
    Add-CIS -ID "18.10.40.3" -Title "Turn on PowerShell Transcription" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v -Evidence "EnableTranscripting=$v"

    # 18.10.43.5.1 Cloud-delivered protection (MAPS)
    $v = try { (Get-MpPreference).MAPSReporting } catch { $null }
    Add-CIS -ID "18.10.43.5.1" -Title "Join Microsoft MAPS" -Section "Admin Templates" `
        -Status $(if($v -ge 1){"Pass"}else{"Fail"}) -Expected "1 or 2" -Actual $(if($null -eq $v){"Not configured"}else{$v}) `
        -Evidence "MAPSReporting=$v"

    # 18.10.43.6.1 ASR rules
    try { $asr = (Get-MpPreference).AttackSurfaceReductionRules_Actions
        $active = ($asr | Where-Object { $_ -ge 1 }).Count
        Add-CIS -ID "18.10.43.6.1" -Title "Configure Attack Surface Reduction rules" -Section "Admin Templates" `
            -Status $(if($active -ge 5){"Pass"}else{"Fail"}) -Expected "5+ rules enforced" -Actual "$active active" `
            -Evidence "ASR rules active=$active"
    } catch { Add-CIS -ID "18.10.43.6.1" -Title "Configure ASR rules" -Section "Admin Templates" -Status "Fail" -Expected "5+" -Actual "Cannot query" }

    # 18.10.43.10.1 Real-time protection
    try { $mp = Get-MpComputerStatus -ErrorAction Stop
        Add-CIS -ID "18.10.43.10.1" -Title "Turn on real-time protection" -Section "Admin Templates" `
            -Status $(if($mp.RealTimeProtectionEnabled){"Pass"}else{"Fail"}) -Expected "Enabled" `
            -Actual $(if($mp.RealTimeProtectionEnabled){"On"}else{"OFF"}) -Evidence "RealTimeProtection=$($mp.RealTimeProtectionEnabled)"

        # 18.10.43.10.2 Turn on behavior monitoring
        Add-CIS -ID "18.10.43.10.2" -Title "Turn on behavior monitoring" -Section "Admin Templates" `
            -Status $(if($mp.BehaviorMonitorEnabled){"Pass"}else{"Fail"}) -Expected "Enabled" `
            -Actual $(if($mp.BehaviorMonitorEnabled){"On"}else{"OFF"}) -Evidence "BehaviorMonitor=$($mp.BehaviorMonitorEnabled)"

        # Scan type (18.10.43.13.1)
        $scanType = try { (Get-MpPreference).ScanParameters } catch { $null }
        Add-CIS -ID "18.10.43.13.1" -Title "Specify scan type" -Section "Admin Templates" `
            -Status $(if($scanType -eq 2){"Pass"}else{"Warning"}) -Expected "2 (Full scan)" `
            -Actual $(if($null -eq $scanType){"Not configured"}else{$scanType}) -Evidence "ScanParameters=$scanType" -CISLevel 2

        # PUA (18.10.43.16)
        $pua = try { (Get-MpPreference).PUAProtection } catch { $null }
        Add-CIS -ID "18.10.43.16" -Title "Configure detection for PUA" -Section "Admin Templates" `
            -Status $(if($pua -eq 1){"Pass"}else{"Fail"}) -Expected "1 (Enabled)" `
            -Actual $(if($null -eq $pua){"Not configured"}else{$pua}) -Evidence "PUAProtection=$pua"
    } catch {}

    # 18.10.57.3.9.1 Require NLA for RDP
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication" 1
    Add-CIS -ID "18.10.57.3.9.1" -Title "Require user authentication for remote connections (NLA)" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v -Evidence "UserAuthentication=$v"

    # 18.10.57.3.9.2 Set client connection encryption level
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "MinEncryptionLevel"
    Add-CIS -ID "18.10.57.3.9.2" -Title "Set client connection encryption level" -Section "Admin Templates" `
        -Status $(if($v -eq 3){"Pass"}else{"Fail"}) -Expected "3 (High Level)" `
        -Actual $(if($null -eq $v){"Not configured"}else{$v}) -Evidence "MinEncryptionLevel=$v"

    # 18.10.75.1 Configure Windows Defender SmartScreen
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen"
    Add-CIS -ID "18.10.75.1" -Title "Configure Windows Defender SmartScreen" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1 (Enabled)" `
        -Actual $(if($null -eq $v){"Not configured"}else{$v}) -Evidence "EnableSmartScreen=$v" -CISLevel 1

    # 18.10.80.1 Configure Windows spotlight on lock screen (L1)
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "ConfigureWindowsSpotlight"
    Add-CIS -ID "18.10.80.1" -Title "Configure Windows Spotlight on lock screen" -Section "Admin Templates" `
        -Status $(if($v -eq 2){"Pass"}else{"Warning"}) -Expected "2 (Disabled)" `
        -Actual $(if($null -eq $v){"Not configured"}else{$v}) -Evidence "ConfigureWindowsSpotlight=$v" -CISLevel 2
}


# ============================================================================
# COMPLIANCE SUMMARY + HTML REPORT + MAIN
# ============================================================================
function Generate-CISReport {
    Write-Section "Generating CIS Report"
    $end = Get-Date; $dur = $end - $Script:StartTime
    $total = $Script:Results.Count
    $pass = ($Script:Results|Where-Object Status -eq "Pass").Count
    $fail = ($Script:Results|Where-Object Status -eq "Fail").Count
    $warn = ($Script:Results|Where-Object Status -eq "Warning").Count
    $na = ($Script:Results|Where-Object Status -in @("N/A","Info","Error")).Count
    $comp = if(($pass+$fail) -gt 0){[math]::Round(($pass/($pass+$fail))*100,1)}else{0}
    $secs = $Script:Results | Group-Object Section | Sort-Object Name
    $ts = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $rp = Join-Path $OutputPath "CIS_Benchmark_${Script:ComputerName}_$ts.html"
    $compCol = if($comp -ge 80){"#4ade80"}elseif($comp -ge 60){"#fbbf24"}else{"#f87171"}

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>CIS Benchmark - $Script:ComputerName</title>
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
.sc.p .n{color:#4ade80}.sc.f .n{color:#f87171}.sc.w .n{color:#fbbf24}.sc.c .n{color:$compCol}
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
.sP{background:#14532d;color:#4ade80}.sF{background:#7f1d1d;color:#f87171}.sW{background:#78350f;color:#fbbf24}.sI{background:#1e3a5f;color:#60a5fa}
.ev{color:#93c5fd;font-size:10px;margin-top:3px;padding:3px 7px;background:#0c1929;border:1px solid #1e3a5f;border-radius:3px;font-family:'Cascadia Code',Consolas,monospace;white-space:pre-wrap}
.rem{color:#34d399;font-size:10px;margin-top:3px;padding:3px 7px;background:#052e16;border-radius:3px}
.rem::before{content:"FIX: ";font-weight:700}
.crit-box{background:#1c1117;border:1px solid #7f1d1d;border-radius:9px;padding:16px;margin-bottom:18px}
.crit-box h3{color:#f87171;margin-bottom:8px;font-size:14px}
.crit-box ul{list-style:none}.crit-box li{padding:3px 0;color:#fca5a5;font-size:11px;border-bottom:1px solid #2d1318}
.crit-box li:last-child{border-bottom:none}.crit-box li::before{content:"! ";font-weight:bold}
.tb{background:#334155;border:none;color:#94a3b8;padding:6px 12px;border-radius:5px;cursor:pointer;font-size:10px;margin-bottom:8px}
.tb:hover{background:#475569;color:#f1f5f9}
.ftr{text-align:center;padding:16px;color:#475569;font-size:10px}
</style></head>
<body><div class="ctr">
<div class="hdr"><h1>CIS Windows 11 Enterprise Benchmark</h1>
<div class="sub">Level $Script:CISLevel Assessment | CIS v4.0 Controls</div>
<div class="meta">
<div class="mi"><div class="lb">Hostname</div><div class="vl">$Script:ComputerName</div></div>
<div class="mi"><div class="lb">OS</div><div class="vl">$Script:OSVersion</div></div>
<div class="mi"><div class="lb">Build</div><div class="vl">$Script:OSBuild</div></div>
<div class="mi"><div class="lb">User</div><div class="vl">$Script:CurrentUser</div></div>
<div class="mi"><div class="lb">CIS Level</div><div class="vl" style="color:#93c5fd">L$Script:CISLevel</div></div>
<div class="mi"><div class="lb">Date</div><div class="vl">$(Get-Date -Format 'dd MMM yyyy HH:mm')</div></div>
<div class="mi"><div class="lb">Duration</div><div class="vl">$([math]::Round($dur.TotalSeconds,1))s</div></div>
<div class="mi"><div class="lb">Controls</div><div class="vl">$total</div></div>
</div></div>
<div class="dash">
<div class="sc"><div class="n">$total</div><div class="l">Controls</div></div>
<div class="sc p"><div class="n">$pass</div><div class="l">Pass</div></div>
<div class="sc f"><div class="n">$fail</div><div class="l">Fail</div></div>
<div class="sc w"><div class="n">$warn</div><div class="l">Warn</div></div>
<div class="sc c"><div class="n">${comp}%</div><div class="l">Compliance</div></div>
</div>
"@

    $cf = $Script:Results | Where-Object Status -eq "Fail" | Sort-Object ID
    if ($cf.Count -gt 0) {
        $html += "<div class=`"crit-box`"><h3>Failed Controls ($($cf.Count))</h3><ul>`n"
        foreach ($f in $cf) { $html += "        <li><strong>$($f.ID)</strong> $($f.Section) - $(ConvertTo-HtmlSafe $f.Title)</li>`n" }
        $html += "    </ul></div>`n"
    }
    $html += "<button class=`"tb`" onclick=`"document.querySelectorAll('.cb').forEach(e=>e.classList.toggle('open'))`">Toggle All</button>`n"

    foreach ($sec in $secs) {
        $cP=($sec.Group|Where-Object Status -eq "Pass").Count;$cF=($sec.Group|Where-Object Status -eq "Fail").Count;$cW=($sec.Group|Where-Object Status -eq "Warning").Count
        $html += "<div class=`"cat`"><div class=`"ch`" onclick=`"this.nextElementSibling.classList.toggle('open')`">"
        $html += "<h3>$($sec.Name) ($($sec.Count))</h3><div class=`"cs`">"
        if($cP){$html+="<span class='cp'>$cP Pass</span>"};if($cF){$html+="<span class='cf'>$cF Fail</span>"};if($cW){$html+="<span class='cw'>$cW Warn</span>"}
        $html += "</div></div><div class=`"cb$(if($cF -gt 0){' open'})`"><table><thead><tr><th>Status</th><th>CIS ID</th><th>Lvl</th><th>Control</th><th>Expected</th><th>Actual</th></tr></thead><tbody>`n"
        $sorted = $sec.Group | Sort-Object @{Expression={switch($_.Status){"Fail"{0}"Warning"{1}"Error"{2}"Info"{3}"Pass"{4}}};Ascending=$true}
        foreach ($f in $sorted) {
            $stc = switch($f.Status){"Pass"{"sP"}"Fail"{"sF"}"Warning"{"sW"}default{"sI"}}
            $cell = ConvertTo-HtmlSafe $f.Title
            if($f.Remediation){$cell+="<div class='rem'>$(ConvertTo-HtmlSafe $f.Remediation)</div>"}
            if($f.Evidence){$cell+="<div class='ev'>$(ConvertTo-HtmlSafe $f.Evidence)</div>"}
            $html += "<tr><td><span class=`"b $stc`">$($f.Status)</span></td><td><strong>$($f.ID)</strong></td><td>$($f.Level)</td>"
            $html += "<td>$cell</td><td>$(ConvertTo-HtmlSafe $f.Expected)</td><td>$(ConvertTo-HtmlSafe $f.Actual)</td></tr>`n"
        }
        $html += "</tbody></table></div></div>`n"
    }

    $html += "<div class=`"ftr`"><p>CIS Windows 11 Benchmark L$Script:CISLevel | $(Get-Date -Format 'dd MMM yyyy HH:mm:ss') | $([math]::Round($dur.TotalSeconds,1))s | $total controls | Authorised use only.</p></div>"
    $html += "</div></body></html>"
    $html | Out-File -FilePath $rp -Encoding UTF8 -Force
    return $rp
}

function Invoke-CISBenchmark {
    Write-Host "============================================================" -ForegroundColor White
    Write-Host "  CIS Windows 11 Enterprise Benchmark - Level $Script:CISLevel" -ForegroundColor Cyan
    Write-Host "  $Script:ComputerName | $Script:CurrentUser | $(Get-Date)" -ForegroundColor Gray
    Write-Host "============================================================" -ForegroundColor White

    @({ Test-AccountPolicies },{ Test-SecurityOptions },{ Test-SystemServices },
      { Test-WindowsFirewall },{ Test-AuditPolicy },{ Test-AdminTemplates }
    ) | ForEach-Object { try { & $_ } catch { Write-Host "  [!] $_" -ForegroundColor Red } }

    $rp = Generate-CISReport
    Write-Host "`n============================================================" -ForegroundColor White
    Write-Host "  DONE | Controls:$($Script:Results.Count) Pass:$(($Script:Results|Where-Object Status -eq 'Pass').Count) Fail:$(($Script:Results|Where-Object Status -eq 'Fail').Count)" -ForegroundColor Green
    Write-Host "  Report: $rp" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor White
    $cp = $rp -replace '\.html$','.csv'
    $Script:Results | Export-Csv -Path $cp -NoTypeInformation -Encoding UTF8
    Write-Host "  CSV: $cp" -ForegroundColor Cyan
}

Invoke-CISBenchmark
