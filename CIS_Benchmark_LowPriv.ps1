<#
.SYNOPSIS
    CIS Windows 11 Benchmark - LOW PRIVILEGE (Standard User)
.DESCRIPTION
    Pure CIS benchmark audit from standard user context. Every check maps to a
    CIS control ID. Registry reads, service queries, and WMI calls that work
    without elevation. Graceful fallback where admin is needed.
    Produces HTML + CSV report.
.EXAMPLE
    .\CIS_Benchmark_LowPriv.ps1
    .\CIS_Benchmark_LowPriv.ps1 -Level 1
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop",
    [ValidateSet(1,2)][int]$Level = 2
)

if (-not (Test-Path $OutputPath)) {
    foreach ($fb in @([Environment]::GetFolderPath('Desktop'),"$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\OneDrive\Desktop","$env:USERPROFILE\Documents",$env:USERPROFILE,$env:TEMP)) {
        if ($fb -and (Test-Path $fb)) { $OutputPath = $fb; break } }
}
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$Script:Results = [System.Collections.ArrayList]::new()
$Script:StartTime = Get-Date
$Script:ComputerName = $env:COMPUTERNAME
$Script:OSVersion = try { (Get-CimInstance Win32_OperatingSystem).Caption } catch { "Unknown" }
$Script:OSBuild = try { (Get-CimInstance Win32_OperatingSystem).BuildNumber } catch { "Unknown" }
$Script:CurrentUser = "$env:USERDOMAIN\$env:USERNAME"
$Script:CISLevel = $Level
$Script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")

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

    # Try net accounts first (works on some standard user configs)
    $naWorked = $false
    try {
        $na = net accounts 2>$null
        if ($na -and ($na -join "") -match "password") {
            $naWorked = $true
            $minLen = if ($na -match "Minimum password length:\s+(\d+)") { [int]$Matches[1] } else { 0 }
            $maxAge = if ($na -match "Maximum password age.*?:\s+(\S+)") { $Matches[1] } else { "Unknown" }
            $minAge = if ($na -match "Minimum password age.*?:\s+(\S+)") { $Matches[1] } else { "Unknown" }
            $history = if ($na -match "Length of password history.*?:\s+(\S+)") { $Matches[1] } else { "Unknown" }
            $lockout = if ($na -match "Lockout threshold:\s+(\S+)") { $Matches[1] } else { "Unknown" }
            $lockDur = if ($na -match "Lockout duration.*?:\s+(\S+)") { $Matches[1] } else { "Unknown" }
            $lockWin = if ($na -match "Lockout observation.*?:\s+(\S+)") { $Matches[1] } else { "Unknown" }
            $poc = ($na | Out-String).Trim()

            Add-CIS -ID "1.1.1" -Title "Enforce password history" -Section "Account Policies" `
                -Status $(if($history -match "^\d+$" -and [int]$history -ge 24){"Pass"}else{"Fail"}) `
                -Expected "24 or more" -Actual "$history passwords" -Evidence $poc

            Add-CIS -ID "1.1.2" -Title "Maximum password age" -Section "Account Policies" `
                -Status $(if($maxAge -match "Never" -or $maxAge -eq "0"){"Fail"}elseif($maxAge -match "^\d+$" -and [int]$maxAge -le 365){"Pass"}else{"Warning"}) `
                -Expected "1-365 days" -Actual "$maxAge days"

            Add-CIS -ID "1.1.3" -Title "Minimum password age" -Section "Account Policies" `
                -Status $(if($minAge -match "^\d+$" -and [int]$minAge -ge 1){"Pass"}else{"Fail"}) `
                -Expected "1 or more days" -Actual "$minAge days"

            Add-CIS -ID "1.1.4" -Title "Minimum password length" -Section "Account Policies" `
                -Status $(if($minLen -ge 14){"Pass"}elseif($minLen -ge 8){"Warning"}else{"Fail"}) `
                -Expected "14 or more" -Actual "$minLen characters"

            Add-CIS -ID "1.2.1" -Title "Account lockout duration" -Section "Account Policies" `
                -Status $(if($lockDur -match "^\d+$" -and [int]$lockDur -ge 15){"Pass"}else{"Fail"}) `
                -Expected "15 or more minutes" -Actual "$lockDur minutes"

            Add-CIS -ID "1.2.2" -Title "Account lockout threshold" -Section "Account Policies" `
                -Status $(if($lockout -match "^\d+$" -and [int]$lockout -ge 1 -and [int]$lockout -le 5){"Pass"}else{"Fail"}) `
                -Expected "1-5 attempts" -Actual $(if($lockout -eq "Never"){"Never (0)"}else{"$lockout attempts"})

            Add-CIS -ID "1.2.3" -Title "Reset account lockout counter after" -Section "Account Policies" `
                -Status $(if($lockWin -match "^\d+$" -and [int]$lockWin -ge 15){"Pass"}else{"Fail"}) `
                -Expected "15 or more minutes" -Actual "$lockWin minutes"
        }
    } catch {}

    if (-not $naWorked) {
        Add-CIS -ID "1.x" -Title "Account Policies" -Section "Account Policies" -Status "Info" `
            -Actual "net accounts unavailable (standard user). Run admin version for full audit." -Expected "secedit export"
    }

    # 1.1.5 Password complexity (registry readable)
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\SAM" "PasswordComplexity"
    if ($null -ne $v) {
        Add-CIS -ID "1.1.5" -Title "Password must meet complexity" -Section "Account Policies" `
            -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v -Evidence "SAM\PasswordComplexity=$v"
    }

    # 1.1.6 Reversible encryption (best effort)
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\SAM" "ClearTextPassword"
    if ($null -ne $v) {
        Add-CIS -ID "1.1.6" -Title "Store passwords using reversible encryption" -Section "Account Policies" `
            -Status $(if($v -eq 0){"Pass"}else{"Fail"}) -Expected "0" -Actual $v
    }
}


# ============================================================================
# CIS 2.x - LOCAL POLICIES / SECURITY OPTIONS
# ============================================================================
function Test-SecurityOptions {
    Write-Section "CIS 2.x - Security Options"

    # 2.3.1.1 Block Microsoft accounts
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "NoConnectedUser"
    Add-CIS -ID "2.3.1.1" -Title "Block Microsoft accounts" -Section "Security Options" `
        -Status $(if($v -eq 3){"Pass"}elseif($v -ge 1){"Warning"}else{"Fail"}) `
        -Expected "3" -Actual $(if($null -eq $v){"Not configured"}else{$v}) -CISLevel 1

    # 2.3.1.2 Guest account
    try { $guest = Get-LocalUser -Name "Guest" -ErrorAction Stop
        Add-CIS -ID "2.3.1.2" -Title "Guest account status" -Section "Security Options" `
            -Status $(if(-not $guest.Enabled){"Pass"}else{"Fail"}) -Expected "Disabled" `
            -Actual $(if($guest.Enabled){"Enabled"}else{"Disabled"})
    } catch {}

    # 2.3.1.5 Limit blank password use
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse" 1
    Add-CIS -ID "2.3.1.5" -Title "Limit blank password use to console only" -Section "Security Options" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v

    # 2.3.2.1 Force audit policy subcategory
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy"
    Add-CIS -ID "2.3.2.1" -Title "Force audit policy subcategory settings" -Section "Security Options" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $(if($null -eq $v){"Not configured"}else{$v}) -CISLevel 1

    # 2.3.7.1 Do not display last user name
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName"
    Add-CIS -ID "2.3.7.1" -Title "Do not display last signed-in" -Section "Security Options" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $(if($null -eq $v){"Not configured (0)"}else{$v}) -CISLevel 1

    # 2.3.7.2 Do not require CTRL+ALT+DEL
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD"
    Add-CIS -ID "2.3.7.2" -Title "Do not require CTRL+ALT+DEL" -Section "Security Options" `
        -Status $(if($v -eq 0 -or $null -eq $v){"Pass"}else{"Fail"}) -Expected "0" `
        -Actual $(if($null -eq $v){"Default"}else{$v}) -CISLevel 1

    # 2.3.7.3 Machine inactivity limit
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs" 0
    Add-CIS -ID "2.3.7.3" -Title "Machine inactivity limit" -Section "Security Options" `
        -Status $(if($v -gt 0 -and $v -le 900){"Pass"}else{"Fail"}) `
        -Expected "900 or fewer" -Actual $(if($v -eq 0){"Not set"}else{"$v seconds"})

    # 2.3.7.4 Message text
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeText"
    Add-CIS -ID "2.3.7.4" -Title "Message text for logon" -Section "Security Options" `
        -Status $(if($v){"Pass"}else{"Fail"}) -Expected "Configured" `
        -Actual $(if($v){"Set ($($v.Length) chars)"}else{"Not configured"}) -CISLevel 1

    # 2.3.7.8 Smart card removal
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "ScRemoveOption"
    Add-CIS -ID "2.3.7.8" -Title "Smart card removal behavior" -Section "Security Options" `
        -Status $(if($v -in @("1","2","3")){"Pass"}else{"Fail"}) `
        -Expected "1-3 (Lock/Logoff/Disconnect)" -Actual $(if($null -eq $v){"Not configured"}else{$v}) -CISLevel 2

    # 2.3.8.1 SMB client sign always
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" 0
    Add-CIS -ID "2.3.8.1" -Title "SMB client: Digitally sign (always)" -Section "Security Options" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v

    # 2.3.8.2 SMB client sign if server agrees
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnableSecuritySignature" 1
    Add-CIS -ID "2.3.8.2" -Title "SMB client: Digitally sign (if server agrees)" -Section "Security Options" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v

    # 2.3.8.3 Send unencrypted password
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnablePlainTextPassword" 0
    Add-CIS -ID "2.3.8.3" -Title "Send unencrypted password to SMB servers" -Section "Security Options" `
        -Status $(if($v -eq 0){"Pass"}else{"Fail"}) -Expected "0" -Actual $v

    # 2.3.9.1 SMB server sign always
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature" 0
    Add-CIS -ID "2.3.9.1" -Title "SMB server: Digitally sign (always)" -Section "Security Options" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v

    # 2.3.9.2 SMB server sign if client agrees
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "EnableSecuritySignature" 1
    Add-CIS -ID "2.3.9.2" -Title "SMB server: Digitally sign (if client agrees)" -Section "Security Options" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v

    # 2.3.10.2 Restrict anonymous SAM
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM" 1
    Add-CIS -ID "2.3.10.2" -Title "Do not allow anonymous enum of SAM accounts" -Section "Security Options" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v

    # 2.3.10.3 Restrict anonymous SAM+shares
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous" 0
    Add-CIS -ID "2.3.10.3" -Title "Do not allow anonymous enum of SAM and shares" -Section "Security Options" `
        -Status $(if($v -ge 1){"Pass"}else{"Fail"}) -Expected "1+" -Actual $v

    # 2.3.10.5 Everyone includes Anonymous
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "EveryoneIncludesAnonymous" 0
    Add-CIS -ID "2.3.10.5" -Title "Let Everyone apply to anonymous users" -Section "Security Options" `
        -Status $(if($v -eq 0){"Pass"}else{"Fail"}) -Expected "0" -Actual $v

    # 2.3.10.7 Null session pipes
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "NullSessionPipes"
    Add-CIS -ID "2.3.10.7" -Title "Named Pipes accessible anonymously" -Section "Security Options" `
        -Status $(if(-not $v -or $v.Count -eq 0){"Pass"}else{"Fail"}) -Expected "Empty" `
        -Actual $(if($v -and $v.Count -gt 0){$v -join ', '}else{"Empty"})

    # 2.3.10.11 Restrict remote SAM
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictRemoteSAM"
    Add-CIS -ID "2.3.10.11" -Title "Restrict remote calls to SAM" -Section "Security Options" `
        -Status $(if($v){"Pass"}else{"Fail"}) -Expected "Configured" `
        -Actual $(if($v){"Set"}else{"Not configured"})

    # 2.3.11.7 LAN Manager auth level
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" 3
    $map = @{0="LM+NTLM";1="LM+NTLM,NTLMv2 negotiated";2="NTLM only";3="NTLMv2 only";4="NTLMv2,refuse LM";5="NTLMv2,refuse LM+NTLM"}
    Add-CIS -ID "2.3.11.7" -Title "LAN Manager authentication level" -Section "Security Options" `
        -Status $(if($v -ge 5){"Pass"}elseif($v -ge 3){"Warning"}else{"Fail"}) `
        -Expected "5 (NTLMv2 only, refuse all)" -Actual "$v ($($map[[int]$v]))" -Evidence "LmCompatibilityLevel=$v"

    # 2.3.11.8 LDAP client signing
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" "LDAPClientIntegrity" 1
    Add-CIS -ID "2.3.11.8" -Title "LDAP client signing requirements" -Section "Security Options" `
        -Status $(if($v -ge 1){"Pass"}else{"Fail"}) -Expected "1 (Negotiate signing)" -Actual $v

    # 2.3.11.10 Min session security NTLM SSP clients
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinClientSec"
    Add-CIS -ID "2.3.11.10" -Title "Min session security NTLM SSP clients" -Section "Security Options" `
        -Status $(if($v -eq 537395200){"Pass"}else{"Fail"}) -Expected "537395200" `
        -Actual $(if($null -eq $v){"Not configured"}else{$v}) -CISLevel 1

    # 2.3.11.11 Min session security NTLM SSP servers
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinServerSec"
    Add-CIS -ID "2.3.11.11" -Title "Min session security NTLM SSP servers" -Section "Security Options" `
        -Status $(if($v -eq 537395200){"Pass"}else{"Fail"}) -Expected "537395200" `
        -Actual $(if($null -eq $v){"Not configured"}else{$v}) -CISLevel 1

    # 2.3.17.x UAC
    $lua = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" 1
    Add-CIS -ID "2.3.17.1" -Title "UAC: Admin Approval Mode" -Section "Security Options" `
        -Status $(if($lua -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $lua

    $consent = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" 5
    Add-CIS -ID "2.3.17.2" -Title "UAC: Elevation prompt for admins" -Section "Security Options" `
        -Status $(if($consent -eq 2){"Pass"}elseif($consent -le 5){"Warning"}else{"Fail"}) `
        -Expected "2 (Consent on secure desktop)" -Actual $consent

    $consentUser = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorUser" 3
    Add-CIS -ID "2.3.17.3" -Title "UAC: Elevation prompt for standard users" -Section "Security Options" `
        -Status $(if($consentUser -eq 0){"Pass"}elseif($consentUser -eq 3){"Warning"}else{"Fail"}) `
        -Expected "0 (Auto deny)" -Actual $consentUser -CISLevel 1

    $detect = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableInstallerDetection" 1
    Add-CIS -ID "2.3.17.4" -Title "UAC: Detect app installations" -Section "Security Options" `
        -Status $(if($detect -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $detect

    $uiAccess = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableSecureUIAPaths" 1
    Add-CIS -ID "2.3.17.5" -Title "UAC: Only elevate UIAccess in secure locations" -Section "Security Options" `
        -Status $(if($uiAccess -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $uiAccess

    $codeSig = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ValidateAdminCodeSignatures" 0
    Add-CIS -ID "2.3.17.6" -Title "UAC: Only elevate signed executables" -Section "Security Options" `
        -Status $(if($codeSig -eq 1){"Pass"}else{"Warning"}) -Expected "1" `
        -Actual $(if($null -eq $codeSig){"Not configured (0)"}else{$codeSig}) -CISLevel 2

    $secDesk = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" 1
    Add-CIS -ID "2.3.17.7" -Title "UAC: Secure desktop when prompting" -Section "Security Options" `
        -Status $(if($secDesk -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $secDesk

    $virt = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableVirtualization" 1
    Add-CIS -ID "2.3.17.8" -Title "UAC: Virtualize write failures" -Section "Security Options" `
        -Status $(if($virt -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $virt
}


# ============================================================================
# CIS 5.x - SYSTEM SERVICES
# ============================================================================
function Test-SystemServices {
    Write-Section "CIS 5.x - System Services"

    $svcChecks = @(
        @{ID="5.2";Name="BTAGService";Title="Bluetooth Audio Gateway";Lv=1},
        @{ID="5.3";Name="bthserv";Title="Bluetooth Support Service";Lv=2},
        @{ID="5.6";Name="Browser";Title="Computer Browser";Lv=1},
        @{ID="5.9";Name="MapsBroker";Title="Downloaded Maps Manager";Lv=2},
        @{ID="5.11";Name="lfsvc";Title="Geolocation Service";Lv=2},
        @{ID="5.14";Name="SharedAccess";Title="Internet Connection Sharing";Lv=1},
        @{ID="5.16";Name="lltdsvc";Title="Link-Layer Topology Discovery";Lv=2},
        @{ID="5.19";Name="LxssManager";Title="LxssManager (WSL)";Lv=1},
        @{ID="5.22";Name="SSDPSRV";Title="SSDP Discovery";Lv=2},
        @{ID="5.27";Name="RemoteRegistry";Title="Remote Registry";Lv=1},
        @{ID="5.29";Name="RpcLocator";Title="RPC Locator";Lv=2},
        @{ID="5.33";Name="SessionEnv";Title="Remote Desktop Configuration";Lv=2},
        @{ID="5.36";Name="Spooler";Title="Print Spooler";Lv=2},
        @{ID="5.40";Name="WinRM";Title="Windows Remote Management";Lv=2},
        @{ID="5.41";Name="WMPNetworkSvc";Title="WMP Network Sharing";Lv=2},
        @{ID="5.42";Name="PushToInstall";Title="Windows PushToInstall";Lv=2},
        @{ID="5.44";Name="WSearch";Title="Windows Search";Lv=2},
        @{ID="5.45";Name="XblAuthManager";Title="Xbox Accessory Management";Lv=2},
        @{ID="5.46";Name="XblGameSave";Title="Xbox Game Save";Lv=2}
    )

    foreach ($sc in $svcChecks) {
        $svc = Get-Service $sc.Name -ErrorAction SilentlyContinue
        Add-CIS -ID $sc.ID -Title "Ensure '$($sc.Title)' is Disabled" -Section "System Services" `
            -Status $(if(-not $svc -or $svc.StartType -eq "Disabled"){"Pass"}else{"Fail"}) `
            -Expected "Disabled" -Actual $(if(-not $svc){"Not installed"}else{"$($svc.Status)/$($svc.StartType)"}) `
            -CISLevel $sc.Lv -Evidence "Service=$($sc.Name)" `
            -Remediation "Set-Service $($sc.Name) -StartupType Disabled"
    }
}


# ============================================================================
# CIS 9.x - WINDOWS FIREWALL
# ============================================================================
function Test-WindowsFirewall {
    Write-Section "CIS 9.x - Windows Firewall"

    # Try cmdlet first, fall back to registry
    $profiles = $null
    try { $profiles = Get-NetFirewallProfile -ErrorAction Stop } catch {}

    $fwChecks = @(
        @{Profile="Domain";PfxID="9.1";RegKey="DomainProfile"},
        @{Profile="Private";PfxID="9.2";RegKey="StandardProfile"},
        @{Profile="Public";PfxID="9.3";RegKey="PublicProfile"}
    )

    foreach ($fc in $fwChecks) {
        if ($profiles) {
            $p = $profiles | Where-Object Name -eq $fc.Profile

            Add-CIS -ID "$($fc.PfxID).1" -Title "$($fc.Profile): Firewall state" -Section "Windows Firewall" `
                -Status $(if($p.Enabled){"Pass"}else{"Fail"}) -Expected "True" -Actual "$($p.Enabled)" `
                -Evidence "$($fc.Profile): Enabled=$($p.Enabled)"

            Add-CIS -ID "$($fc.PfxID).2" -Title "$($fc.Profile): Inbound connections" -Section "Windows Firewall" `
                -Status $(if($p.DefaultInboundAction -eq "Block"){"Pass"}else{"Fail"}) `
                -Expected "Block" -Actual "$($p.DefaultInboundAction)"

            Add-CIS -ID "$($fc.PfxID).3" -Title "$($fc.Profile): Outbound connections" -Section "Windows Firewall" `
                -Status $(if($p.DefaultOutboundAction -eq "Allow" -or $p.DefaultOutboundAction -eq "NotConfigured"){"Pass"}else{"Warning"}) `
                -Expected "Allow" -Actual "$($p.DefaultOutboundAction)"

            Add-CIS -ID "$($fc.PfxID).7" -Title "$($fc.Profile): Log dropped packets" -Section "Windows Firewall" `
                -Status $(if($p.LogBlocked -eq $true){"Pass"}else{"Fail"}) -Expected "True" -Actual "$($p.LogBlocked)"

            Add-CIS -ID "$($fc.PfxID).9" -Title "$($fc.Profile): Log file size" -Section "Windows Firewall" `
                -Status $(if($p.LogMaxSizeKilobytes -ge 16384){"Pass"}else{"Fail"}) `
                -Expected "16384 KB+" -Actual "$($p.LogMaxSizeKilobytes) KB" -CISLevel 1
        } else {
            # Registry fallback
            $base = "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$($fc.RegKey)"
            $enabled = Get-RegValue $base "EnableFirewall" 0
            $inDefault = Get-RegValue $base "DefaultInboundAction" 0
            $logSize = Get-RegValue "$base\Logging" "LogFileMaxSize" 4096

            Add-CIS -ID "$($fc.PfxID).1" -Title "$($fc.Profile): Firewall state" -Section "Windows Firewall" `
                -Status $(if($enabled -eq 1){"Pass"}else{"Fail"}) -Expected "1 (Enabled)" -Actual $enabled `
                -Evidence "Registry: EnableFirewall=$enabled"

            Add-CIS -ID "$($fc.PfxID).2" -Title "$($fc.Profile): Inbound connections" -Section "Windows Firewall" `
                -Status $(if($inDefault -eq 1){"Pass"}else{"Fail"}) -Expected "1 (Block)" -Actual $inDefault

            Add-CIS -ID "$($fc.PfxID).9" -Title "$($fc.Profile): Log file size" -Section "Windows Firewall" `
                -Status $(if($logSize -ge 16384){"Pass"}else{"Fail"}) -Expected "16384+" -Actual "$logSize KB" -CISLevel 1
        }
    }
}


# ============================================================================
# CIS 17.x - ADVANCED AUDIT POLICY
# ============================================================================
function Test-AuditPolicy {
    Write-Section "CIS 17.x - Audit Policy"

    $auditpol = $null
    try { $auditpol = auditpol /get /category:* 2>$null
        if (-not $auditpol -or ($auditpol -join "") -notmatch "Logon") { $auditpol = $null }
    } catch {}

    if (-not $auditpol) {
        Add-CIS -ID "17.x" -Title "Audit policy query" -Section "Audit Policy" -Status "Info" `
            -Actual "Cannot query auditpol (standard user). Run admin version." -Expected "Access granted"
        return
    }

    $checks = @(
        @{ID="17.1.1";Sub="Credential Validation";Expect="Success and Failure"},
        @{ID="17.2.1";Sub="Application Group Management";Expect="Success and Failure"},
        @{ID="17.2.5";Sub="Security Group Management";Expect="Success"},
        @{ID="17.2.6";Sub="User Account Management";Expect="Success and Failure"},
        @{ID="17.3.1";Sub="Process Creation";Expect="Success"},
        @{ID="17.5.1";Sub="Account Lockout";Expect="Failure"},
        @{ID="17.5.2";Sub="Logoff";Expect="Success"},
        @{ID="17.5.3";Sub="Logon";Expect="Success and Failure"},
        @{ID="17.5.4";Sub="Other Logon/Logoff Events";Expect="Success and Failure"},
        @{ID="17.5.6";Sub="Special Logon";Expect="Success"},
        @{ID="17.6.1";Sub="Detailed File Share";Expect="Failure"},
        @{ID="17.6.2";Sub="File Share";Expect="Success and Failure"},
        @{ID="17.6.3";Sub="Other Object Access Events";Expect="Success and Failure"},
        @{ID="17.6.4";Sub="Removable Storage";Expect="Success and Failure"},
        @{ID="17.7.1";Sub="Audit Policy Change";Expect="Success"},
        @{ID="17.7.2";Sub="Authentication Policy Change";Expect="Success"},
        @{ID="17.7.3";Sub="Authorization Policy Change";Expect="Success"},
        @{ID="17.7.4";Sub="MPSSVC Rule-Level Policy Change";Expect="Success and Failure"},
        @{ID="17.8.1";Sub="Sensitive Privilege Use";Expect="Success and Failure"},
        @{ID="17.9.1";Sub="IPsec Driver";Expect="Success and Failure"},
        @{ID="17.9.2";Sub="Other System Events";Expect="Success and Failure"},
        @{ID="17.9.3";Sub="Security State Change";Expect="Success"},
        @{ID="17.9.4";Sub="Security System Extension";Expect="Success"},
        @{ID="17.9.5";Sub="System Integrity";Expect="Success and Failure"}
    )

    foreach ($c in $checks) {
        $line = $auditpol | Select-String "^\s+$($c.Sub)\s" | Select-Object -First 1
        $actual = if ($line) { ($line -split "\s{2,}")[-1].Trim() } else { "Not found" }
        $pass = $actual -match "Success" -and ($c.Expect -notmatch "Failure" -or $actual -match "Failure")
        if ($c.Expect -eq "Failure") { $pass = $actual -match "Failure" }
        Add-CIS -ID $c.ID -Title $c.Sub -Section "Audit Policy" `
            -Status $(if($pass){"Pass"}else{"Fail"}) -Expected $c.Expect -Actual $actual `
            -Evidence "auditpol: $($c.Sub) = $actual"
    }
}


# ============================================================================
# CIS 18.x - ADMINISTRATIVE TEMPLATES
# ============================================================================
function Test-AdminTemplates {
    Write-Section "CIS 18.x - Administrative Templates"

    # 18.1.1.1 Lock screen camera
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera"
    Add-CIS -ID "18.1.1.1" -Title "Prevent lock screen camera" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $(if($null -eq $v){"Not configured"}else{$v}) -CISLevel 1

    # 18.1.1.2 Lock screen slide show
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow"
    Add-CIS -ID "18.1.1.2" -Title "Prevent lock screen slide show" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $(if($null -eq $v){"Not configured"}else{$v}) -CISLevel 1

    # 18.4.1 Credential Guard
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\LSA" "LsaCfgFlags"
    Add-CIS -ID "18.4.1" -Title "Configure Credential Guard" -Section "Admin Templates" `
        -Status $(if($v -ge 1){"Pass"}else{"Fail"}) -Expected "1 or 2" -Actual $(if($null -eq $v){"Not configured"}else{$v}) -CISLevel 1

    # 18.4.4 SMBv1 client
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start" 3
    Add-CIS -ID "18.4.4" -Title "Configure SMBv1 client driver" -Section "Admin Templates" `
        -Status $(if($v -eq 4){"Pass"}else{"Fail"}) -Expected "4 (Disabled)" -Actual $v

    # 18.4.5 SMBv1 server
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1" 1
    Add-CIS -ID "18.4.5" -Title "Configure SMBv1 server" -Section "Admin Templates" `
        -Status $(if($v -eq 0){"Pass"}else{"Fail"}) -Expected "0 (Disabled)" `
        -Actual $(if($null -eq $v -or $v -eq 1){"Enabled/Default"}else{$v})

    # 18.4.7 LSASS PPL
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
    $pplOK = $v -eq 1 -or $v -eq 2
    Add-CIS -ID "18.4.7" -Title "LSASS protected process" -Section "Admin Templates" `
        -Status $(if($pplOK){"Pass"}else{"Fail"}) -Expected "1 or 2" `
        -Actual $(if($pplOK){"$v ($(if($v -eq 2){'UEFI lock'}else{'Enabled'}))"}else{"Not configured"}) `
        -Evidence "RunAsPPL=$v"

    # 18.4.8 WDigest
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"
    Add-CIS -ID "18.4.8" -Title "WDigest Authentication" -Section "Admin Templates" `
        -Status $(if($v -ne 1){"Pass"}else{"Fail"}) -Expected "0 or not set" `
        -Actual $(if($v -eq 1){"ENABLED!"}else{"Disabled"})

    # 18.5.1 AutoAdminLogon
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon" "0"
    $pw = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultPassword"
    Add-CIS -ID "18.5.1" -Title "MSS: AutoAdminLogon" -Section "Admin Templates" `
        -Status $(if($v -eq "0" -and -not $pw){"Pass"}else{"Fail"}) -Expected "0, no password" `
        -Actual "AutoLogon=$v, Password=$(if($pw){'SET!'}else{'No'})"

    # 18.6.4.1 LLMNR
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" 1
    Add-CIS -ID "18.6.4.1" -Title "Turn off multicast name resolution (LLMNR)" -Section "Admin Templates" `
        -Status $(if($v -eq 0){"Pass"}else{"Fail"}) -Expected "0" -Actual $v

    # 18.6.14.1 Hardened UNC
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\netlogon"
    Add-CIS -ID "18.6.14.1" -Title "Hardened UNC Paths" -Section "Admin Templates" `
        -Status $(if($v){"Pass"}else{"Warning"}) -Expected "Configured" `
        -Actual $(if($v){"Set"}else{"Not configured"}) -CISLevel 1

    # 18.8.3.1 Delegation of non-exportable creds
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "AllowProtectedCreds"
    Add-CIS -ID "18.8.3.1" -Title "Remote host: non-exportable credentials" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $(if($null -eq $v){"Not configured"}else{$v}) -CISLevel 1

    # 18.9.3.1 Command line in process events
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" 0
    Add-CIS -ID "18.9.3.1" -Title "Include command line in process events" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v

    # 18.9.4.1 CredSSP Encryption Oracle
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" "AllowEncryptionOracle"
    Add-CIS -ID "18.9.4.1" -Title "Encryption Oracle Remediation" -Section "Admin Templates" `
        -Status $(if($v -eq 0){"Pass"}else{"Fail"}) -Expected "0 (Force Updated)" `
        -Actual $(if($null -eq $v){"Not configured"}else{$v}) -CISLevel 1

    # 18.9.7.2 Device metadata
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" "PreventDeviceMetadataFromNetwork"
    Add-CIS -ID "18.9.7.2" -Title "Prevent device metadata from Internet" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $(if($null -eq $v){"Not configured"}else{$v}) -CISLevel 1

    # Event log sizes
    foreach ($log in @(
        @{N="Application";CIS="18.9.27.1.1";Min=32768},
        @{N="Security";CIS="18.9.27.2.1";Min=196608},
        @{N="System";CIS="18.9.27.3.1";Min=32768}
    )) { try { $el = Get-WinEvent -ListLog $log.N -ErrorAction Stop
        Add-CIS -ID $log.CIS -Title "$($log.N): Maximum Log Size" -Section "Admin Templates" `
            -Status $(if($el.MaximumSizeInBytes -ge $log.Min){"Pass"}else{"Fail"}) `
            -Expected "$([math]::Round($log.Min/1024))KB+" -Actual "$([math]::Round($el.MaximumSizeInBytes/1024))KB"
    } catch {} }

    # 18.10.9.1 BitLocker (try multiple methods)
    $blStatus = "Unknown"
    try { $bl = Get-BitLockerVolume -MountPoint C: -ErrorAction Stop; $blStatus = "$($bl.ProtectionStatus)" } catch {
        try { $bde = manage-bde -status C: 2>$null; if ($bde -match "Protection Status:\s+(.+)") { $blStatus = $Matches[1].Trim() } } catch {
            try { $ev = Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -ErrorAction Stop |
                Where-Object DriveLetter -eq "C:"; $blStatus = if($ev.ProtectionStatus -eq 1){"On"}else{"Off"} } catch { $blStatus = "Cannot query" } } }
    Add-CIS -ID "18.10.9.1" -Title "BitLocker: OS Drive" -Section "Admin Templates" `
        -Status $(if($blStatus -match "On"){"Pass"}else{"Fail"}) -Expected "On" -Actual $blStatus

    # 18.10.12.1 Password reveal button
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" "DisablePasswordReveal"
    Add-CIS -ID "18.10.12.1" -Title "Do not display password reveal button" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $(if($null -eq $v){"Not configured"}else{$v}) -CISLevel 1

    # 18.10.14.1 Consumer experiences
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures"
    Add-CIS -ID "18.10.14.1" -Title "Turn off Microsoft consumer experiences" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $(if($null -eq $v){"Not configured"}else{$v}) -CISLevel 1

    # 18.10.25.1 Autoplay
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" 0
    Add-CIS -ID "18.10.25.1" -Title "Turn off Autoplay" -Section "Admin Templates" `
        -Status $(if($v -eq 255){"Pass"}else{"Fail"}) -Expected "255 (All drives)" -Actual $v

    # 18.10.25.2 AutoRun default
    $v = Get-RegValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun" 0
    Add-CIS -ID "18.10.25.2" -Title "Default behavior for AutoRun" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1 (Do not execute)" -Actual $v

    # 18.10.40.1 PSv2
    try { $psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop
        $state = if ($psv2.State) { $psv2.State.ToString() } else { "Unknown" }
        Add-CIS -ID "18.10.40.1" -Title "Disable PowerShell v2" -Section "Admin Templates" `
            -Status $(if($state -match "Disabled"){"Pass"}else{"Fail"}) -Expected "Disabled" -Actual $state
    } catch { Add-CIS -ID "18.10.40.1" -Title "Disable PowerShell v2" -Section "Admin Templates" -Status "Info" -Actual "Cannot query (may need admin)" }

    # 18.10.40.2 Script Block Logging
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" 0
    Add-CIS -ID "18.10.40.2" -Title "PowerShell Script Block Logging" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v

    # 18.10.40.3 Transcription
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting" 0
    Add-CIS -ID "18.10.40.3" -Title "PowerShell Transcription" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v

    # Defender checks (Get-MpPreference works as standard user)
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $mp = Get-MpComputerStatus -ErrorAction Stop

        Add-CIS -ID "18.10.43.5.1" -Title "Join Microsoft MAPS" -Section "Admin Templates" `
            -Status $(if($pref.MAPSReporting -ge 1){"Pass"}else{"Fail"}) -Expected "1 or 2" -Actual $pref.MAPSReporting

        $asrActive = ($pref.AttackSurfaceReductionRules_Actions | Where-Object { $_ -ge 1 }).Count
        Add-CIS -ID "18.10.43.6.1" -Title "Configure ASR rules" -Section "Admin Templates" `
            -Status $(if($asrActive -ge 5){"Pass"}else{"Fail"}) -Expected "5+ rules" -Actual "$asrActive active"

        Add-CIS -ID "18.10.43.10.1" -Title "Real-time protection" -Section "Admin Templates" `
            -Status $(if($mp.RealTimeProtectionEnabled){"Pass"}else{"Fail"}) -Expected "Enabled" `
            -Actual $(if($mp.RealTimeProtectionEnabled){"On"}else{"OFF"})

        Add-CIS -ID "18.10.43.10.2" -Title "Behavior monitoring" -Section "Admin Templates" `
            -Status $(if($mp.BehaviorMonitorEnabled){"Pass"}else{"Fail"}) -Expected "Enabled" `
            -Actual $(if($mp.BehaviorMonitorEnabled){"On"}else{"OFF"})

        Add-CIS -ID "18.10.43.13.1" -Title "Specify scan type" -Section "Admin Templates" `
            -Status $(if($pref.ScanParameters -eq 2){"Pass"}else{"Warning"}) -Expected "2 (Full)" `
            -Actual $pref.ScanParameters -CISLevel 2

        Add-CIS -ID "18.10.43.16" -Title "PUA detection" -Section "Admin Templates" `
            -Status $(if($pref.PUAProtection -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $pref.PUAProtection
    } catch { Add-CIS -ID "18.10.43.x" -Title "Defender checks" -Section "Admin Templates" -Status "Info" -Actual "Cannot query Defender: $_" }

    # 18.10.57.3.9.1 NLA
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication" 1
    Add-CIS -ID "18.10.57.3.9.1" -Title "Require NLA for RDP" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" -Actual $v

    # 18.10.57.3.9.2 RDP encryption
    $v = Get-RegValue "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "MinEncryptionLevel"
    Add-CIS -ID "18.10.57.3.9.2" -Title "RDP encryption level" -Section "Admin Templates" `
        -Status $(if($v -eq 3){"Pass"}else{"Fail"}) -Expected "3 (High)" `
        -Actual $(if($null -eq $v){"Not configured"}else{$v})

    # 18.10.75.1 SmartScreen
    $v = Get-RegValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen"
    Add-CIS -ID "18.10.75.1" -Title "Windows Defender SmartScreen" -Section "Admin Templates" `
        -Status $(if($v -eq 1){"Pass"}else{"Fail"}) -Expected "1" `
        -Actual $(if($null -eq $v){"Not configured"}else{$v}) -CISLevel 1
}


# ============================================================================
# HTML REPORT + MAIN
# ============================================================================
function Generate-CISReport {
    Write-Section "Generating CIS Report"
    $end = Get-Date; $dur = $end - $Script:StartTime
    $total = $Script:Results.Count
    $pass = ($Script:Results|Where-Object Status -eq "Pass").Count
    $fail = ($Script:Results|Where-Object Status -eq "Fail").Count
    $warn = ($Script:Results|Where-Object Status -eq "Warning").Count
    $comp = if(($pass+$fail) -gt 0){[math]::Round(($pass/($pass+$fail))*100,1)}else{0}
    $secs = $Script:Results | Group-Object Section | Sort-Object Name
    $ts = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $rp = Join-Path $OutputPath "CIS_Benchmark_LowPriv_${Script:ComputerName}_$ts.html"
    $compCol = if($comp -ge 80){"#4ade80"}elseif($comp -ge 60){"#fbbf24"}else{"#f87171"}

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>CIS Benchmark (Low-Priv) - $Script:ComputerName</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}
.ctr{max-width:1400px;margin:0 auto;padding:20px}
.hdr{background:linear-gradient(135deg,#0c1929,#0c2918);border-radius:12px;padding:28px;margin-bottom:22px;border:1px solid #166534}
.hdr h1{font-size:22px;color:#86efac}.hdr .sub{color:#94a3b8;font-size:13px}
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
.ev{color:#86efac;font-size:10px;margin-top:3px;padding:3px 7px;background:#071a0e;border:1px solid #166534;border-radius:3px;font-family:'Cascadia Code',Consolas,monospace;white-space:pre-wrap}
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
<div class="hdr"><h1>CIS Windows 11 Benchmark (Low-Privilege)</h1>
<div class="sub">Level $Script:CISLevel | Standard user context | Registry + service checks</div>
<div class="meta">
<div class="mi"><div class="lb">Hostname</div><div class="vl">$Script:ComputerName</div></div>
<div class="mi"><div class="lb">OS</div><div class="vl">$Script:OSVersion</div></div>
<div class="mi"><div class="lb">Build</div><div class="vl">$Script:OSBuild</div></div>
<div class="mi"><div class="lb">User</div><div class="vl">$Script:CurrentUser</div></div>
<div class="mi"><div class="lb">Privilege</div><div class="vl" style="color:#fbbf24">$(if($Script:IsAdmin){'ADMIN'}else{'Standard'})</div></div>
<div class="mi"><div class="lb">CIS Level</div><div class="vl" style="color:#86efac">L$Script:CISLevel</div></div>
<div class="mi"><div class="lb">Date</div><div class="vl">$(Get-Date -Format 'dd MMM yyyy HH:mm')</div></div>
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

    $html += "<div class=`"ftr`"><p>CIS Windows 11 Benchmark L$Script:CISLevel (Low-Priv) | $(Get-Date -Format 'dd MMM yyyy HH:mm:ss') | $([math]::Round($dur.TotalSeconds,1))s | $total controls | Authorised use only.</p></div>"
    $html += "</div></body></html>"
    $html | Out-File -FilePath $rp -Encoding UTF8 -Force
    return $rp
}

function Invoke-CISBenchmark {
    Write-Host "============================================================" -ForegroundColor White
    Write-Host "  CIS Windows 11 Benchmark - Level $Script:CISLevel (Low-Priv)" -ForegroundColor Green
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
